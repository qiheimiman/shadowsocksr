#!/usr/bin/python
# -*- coding: utf-8 -*-

import logging
import time
import sys
from server_pool import ServerPool
import traceback
from shadowsocks import common, shell, lru_cache, obfs
from configloader import load_config, get_config
import importloader
import copy
from database import *
import pymysql
from utils.net_util import *
import requests
import json, hashlib

switchrule = None
db_instance = None

class TransferBase(object):
    def __init__(self):
        import threading
        self.event = threading.Event()
        self.key_list = ['port', 'u', 'd', 'transfer_enable', 'passwd', 'enable','id']
        self.last_get_transfer = {} #上一次的实际流量
        self.last_update_transfer = {} #上一次更新到的流量（小于等于实际流量）
        self.force_update_transfer = set() #强制推入数据库的ID
        self.port_uid_table = {} #端口到uid的映射（仅v3以上有用）
        self.onlineuser_cache = lru_cache.LRUCache(timeout=60*30) #用户在线状态记录
        self.pull_ok = False #记录是否已经拉出过数据
        self.mu_ports = {}
        
        self.detect_text_list = {}
        self.detect_text_ischanged = False

        self.node_info = {} #节点信息
        self.node_info_unique = None #节点信息md5比较,信息改变就重启

    def load_cfg(self):
        pass

    def push_db_all_user(self):
        if self.pull_ok is False:
            return
        #更新用户流量到数据库
        last_transfer = self.last_update_transfer
        curr_transfer = ServerPool.get_instance().get_servers_transfer()
        #上次和本次的增量
        dt_transfer = {}
        for id in self.force_update_transfer: #此表中的用户统计上次未计入的流量
            if id in self.last_get_transfer and id in last_transfer:
                dt_transfer[id] = [self.last_get_transfer[id][0] - last_transfer[id][0], self.last_get_transfer[id][1] - last_transfer[id][1]]

        for id in curr_transfer.keys():
            if id in self.force_update_transfer or id in self.mu_ports:
                continue
            #算出与上次记录的流量差值，保存于dt_transfer表
            if id in last_transfer:
                if curr_transfer[id][0] + curr_transfer[id][1] - last_transfer[id][0] - last_transfer[id][1] <= 0:
                    continue
                dt_transfer[id] = [curr_transfer[id][0] - last_transfer[id][0],
                                curr_transfer[id][1] - last_transfer[id][1]]
            else:
                if curr_transfer[id][0] + curr_transfer[id][1] <= 0:
                    continue
                dt_transfer[id] = [curr_transfer[id][0], curr_transfer[id][1]]

            #有流量的，先记录在线状态
            if id in self.last_get_transfer:
                if curr_transfer[id][0] + curr_transfer[id][1] > self.last_get_transfer[id][0] + self.last_get_transfer[id][1]:
                    self.onlineuser_cache[id] = curr_transfer[id][0] + curr_transfer[id][1]
            else:
                self.onlineuser_cache[id] = curr_transfer[id][0] + curr_transfer[id][1]

        self.onlineuser_cache.sweep()

        update_transfer = self.update_all_user(dt_transfer) #返回有更新的表
        for id in update_transfer.keys(): #其增量加在此表
            if id not in self.force_update_transfer: #但排除在force_update_transfer内的
                last = self.last_update_transfer.get(id, [0,0])
                self.last_update_transfer[id] = [last[0] + update_transfer[id][0], last[1] + update_transfer[id][1]]
        self.last_get_transfer = curr_transfer
        for id in self.force_update_transfer:
            if id in self.last_update_transfer:
                del self.last_update_transfer[id]
            if id in self.last_get_transfer:
                del self.last_get_transfer[id]
        self.force_update_transfer = set()

    def del_server_out_of_bound_safe(self, last_rows, rows):
        #停止超流量的服务
        #启动没超流量的服务
        keymap = {}
        try:
            switchrule = importloader.load('switchrule')
            keymap = switchrule.getRowMap()
        except Exception as e:
            logging.error('load switchrule.py fail')
        cur_servers = {} #记录每次读取配置的所有有效端口服务,port=>passwd
        new_servers = {} #记录每次读取配置后需要新启动的端口,port=>(passwd,cfg)
        allow_users = {}
        mu_servers  = {}
        config = {
            'additional_ports_only' : False
        }

        if self.node_info['single_force'] == 1: #严格模式
            config['additional_ports_only'] = True
        
        for row in rows:
            try:
                allow = switchrule.isTurnOn(row) and row['enable'] == 1 and row['u'] + row['d'] < row['transfer_enable']
            except Exception as e:
                allow = False

            port = row['port']

            #转换密码编码为utf-8编码
            passwd = common.to_bytes(row['passwd'])
            if hasattr(passwd, 'encode'):
                passwd = passwd.encode('utf-8')
            cfg = {'password': passwd}
            
            if 'id' in row:
                self.port_uid_table[row['port']] = row['id']

            read_config_keys = ['method', 'obfs', 'obfs_param', 'protocol', 'protocol_param', 'forbidden_ip', 'forbidden_port',
             'speed_limit_per_con', 'speed_limit_per_user','is_udp']
            for name in read_config_keys:
                if name in row and row[name]:
                    if name in keymap:
                        cfg[keymap[name]] = row[name]
                    else:
                        cfg[name] = row[name]

            merge_config_keys = ['password'] + read_config_keys
            for name in cfg.keys():
                if hasattr(cfg[name], 'encode'):
                    try:
                        cfg[name] = cfg[name].encode('utf-8')
                    except Exception as e:
                        logging.warning('encode cfg key "%s" fail, val "%s"' % (name, cfg[name]))

            #有多个用户使用相同的端口
            if port not in cur_servers:
                cur_servers[port] = passwd
            else:
                logging.error('more than one user use the same port [%s]' % (port,))
                continue

            if 'protocol' in cfg and 'protocol_param' in cfg and common.to_str(cfg['protocol']) in obfs.mu_protocol():
                if '#' in common.to_str(cfg['protocol_param']):
                    mu_servers[port] = passwd
                    allow = True
            
            cfg['detect_text_list'] = self.detect_text_list.copy()


            #单端口时节点信息被修改后，立即重启端口刷新
            if str(port) == str(self.node_info['single_port']):
                if row['unique'] != self.node_info_unique :
                    self.node_info_unique = None
                    logging.info('db stop server at port [%s] reason: config changed1: %s' % (port, cfg))
                    ServerPool.get_instance().cb_del_server(port)
                    self.force_update_transfer.add(port)
                    new_servers[port] = (passwd, cfg) 

            #如果当前端口允许运行
            if allow:
                if port not in mu_servers:
                    allow_users[port] = cfg

                cfgchange = False
                #检查端口参数变更
                if port in ServerPool.get_instance().tcp_servers_pool:
                    relay = ServerPool.get_instance().tcp_servers_pool[port]
                    for name in merge_config_keys:
                        if name in cfg and not self.cmp(cfg[name], relay._config[name]):
                            cfgchange = True
                            break
                if not cfgchange and port in ServerPool.get_instance().tcp_ipv6_servers_pool:
                    relay = ServerPool.get_instance().tcp_ipv6_servers_pool[port]
                    for name in merge_config_keys:
                        if (name in cfg) and ((name not in relay._config) or not self.cmp(cfg[name], relay._config[name])):
                            cfgchange = True
                            break
            

            if port in mu_servers:
                if ServerPool.get_instance().server_is_run(port) > 0:
                
                    if self.detect_text_ischanged:
                        cfgchange = True
                    
                    if port in ServerPool.get_instance().tcp_servers_pool:
                        ServerPool.get_instance().tcp_servers_pool[
                            port].modify_detect_text_list(self.detect_text_list)
                    if port in ServerPool.get_instance().tcp_ipv6_servers_pool:
                        ServerPool.get_instance().tcp_ipv6_servers_pool[
                            port].modify_detect_text_list(self.detect_text_list)

                    
                    if port in ServerPool.get_instance().udp_servers_pool:
                        ServerPool.get_instance().udp_servers_pool[
                            port].modify_detect_text_list(self.detect_text_list)
                    if port in ServerPool.get_instance().udp_ipv6_servers_pool:
                        ServerPool.get_instance().udp_ipv6_servers_pool[
                            port].modify_detect_text_list(self.detect_text_list)
                
                    if cfgchange:
                        logging.info('db stop server at port [%s] reason: config changed: %s' % (port, cfg))
                        ServerPool.get_instance().cb_del_server(port)
                        self.force_update_transfer.add(port)
                        new_servers[port] = (passwd, cfg)
                else:
                    self.new_server(port, passwd, cfg)
            else:
                #停止需要重启的端口服务,并把端口参数放入new_servers
                if ServerPool.get_instance().server_is_run(port) > 0:
                    
                    if self.detect_text_ischanged:
                        cfgchange = True
                        
                    
                    if port in ServerPool.get_instance().tcp_servers_pool:
                        ServerPool.get_instance().tcp_servers_pool[
                            port].modify_detect_text_list(self.detect_text_list)
                    if port in ServerPool.get_instance().tcp_ipv6_servers_pool:
                        ServerPool.get_instance().tcp_ipv6_servers_pool[
                            port].modify_detect_text_list(self.detect_text_list)
                    if port in ServerPool.get_instance().udp_servers_pool:
                        ServerPool.get_instance().udp_servers_pool[
                            port].modify_detect_text_list(self.detect_text_list)
                    if port in ServerPool.get_instance().udp_ipv6_servers_pool:
                        ServerPool.get_instance().udp_ipv6_servers_pool[
                            port].modify_detect_text_list(self.detect_text_list)
                
                
                    if config['additional_ports_only'] or not allow:
                        logging.info('db stop server at port [%s]' % (port))
                        ServerPool.get_instance().cb_del_server(port)
                        self.force_update_transfer.add(port)
                    else:
                        if cfgchange:
                            logging.info('db stop server at port [%s] reason: config changed: %s' % (port, cfg))
                            ServerPool.get_instance().cb_del_server(port)
                            self.force_update_transfer.add(port)
                            new_servers[port] = (passwd, cfg)
                #新增的端口服务放入new_server
                elif not config['additional_ports_only'] and allow and port > 0 and port < 65536 and ServerPool.get_instance().server_run_status(port) is False:
                    self.new_server(port, passwd, cfg)
        #关闭需要停止服务的端口
        for row in last_rows:
            if row['port'] in cur_servers:
                pass
            else:
                logging.info('db stop server at port [%s] reason: port not exist' % (row['port']))
                ServerPool.get_instance().cb_del_server(row['port'])
                self.clear_cache(row['port'])
                if row['port'] in self.port_uid_table:
                    del self.port_uid_table[row['port']]
        #启动新增的端口服务和需要重启的端口服务
        if len(new_servers) > 0:
            from shadowsocks import eventloop
            self.event.wait(eventloop.TIMEOUT_PRECISION + eventloop.TIMEOUT_PRECISION / 2)
            for port in new_servers.keys():
                passwd, cfg = new_servers[port]
                self.new_server(port, passwd, cfg)

        logging.debug('db allow users %s \nmu_servers %s' % (allow_users, mu_servers))
        for port in mu_servers:
            ServerPool.get_instance().update_mu_users(port, allow_users)

        self.mu_ports = mu_servers

    def clear_cache(self, port):
        if port in self.force_update_transfer: del self.force_update_transfer[port]
        if port in self.last_get_transfer: del self.last_get_transfer[port]
        if port in self.last_update_transfer: del self.last_update_transfer[port]

    def new_server(self, port, passwd, cfg):
        protocol = cfg.get('protocol', ServerPool.get_instance().config.get('protocol', 'origin'))
        method = cfg.get('method', ServerPool.get_instance().config.get('method', 'None'))
        obfs = cfg.get('obfs', ServerPool.get_instance().config.get('obfs', 'plain'))
        logging.info('db start server at port [%s] pass [%s] protocol [%s] method [%s] obfs [%s]' % (port, passwd, protocol, method, obfs))
        ServerPool.get_instance().new_server(port, cfg)

    def cmp(self, val1, val2):
        if type(val1) is bytes:
            val1 = common.to_str(val1)
        if type(val2) is bytes:
            val2 = common.to_str(val2)
        return val1 == val2

    def push_all_port_and_connect(self):
        pass

    @staticmethod
    def del_servers():
        for port in [v for v in ServerPool.get_instance().tcp_servers_pool.keys()]:
            if ServerPool.get_instance().server_is_run(port) > 0:
                ServerPool.get_instance().cb_del_server(port)
        for port in [v for v in ServerPool.get_instance().tcp_ipv6_servers_pool.keys()]:
            if ServerPool.get_instance().server_is_run(port) > 0:
                ServerPool.get_instance().cb_del_server(port)

    @staticmethod
    def thread_db(obj):
        import socket
        global db_instance
        timeout = 60
        socket.setdefaulttimeout(timeout)
        last_rows = [] #上次读取的参数
        db_instance = obj()
        ServerPool.get_instance()
        shell.log_shadowsocks_version()

        try:
            import resource
            resource.setrlimit(resource.RLIMIT_NOFILE, (1000000, 1000000))
            logging.info(
                'current process RLIMIT_NOFILE resource: soft %d hard %d' % resource.getrlimit(resource.RLIMIT_NOFILE))
        except:
            pass

        try:
            while True:
                load_config()
                db_instance.load_cfg()
                try:
                    #保存端口流量记录
                    db_instance.push_db_all_user()
                    db_instance.detect_text_ischanged = False
                    #读取所有端口参数
                    rows = db_instance.pull_db_all_user()
                    #db_instance.detect_text_ischanged = False
                    if rows:
                        db_instance.pull_ok = True

                        #从接口获取节点信息
                        node_info = db_instance.node_info
                        config = {}
                        if node_info['type'] == 1: #SSR
                           if node_info['single'] == 1: #单端口多用户
                                config['additional_ports'] ={
                                    node_info['single_port'] : {
                                        "passwd": node_info['single_passwd'],
                                        "method": node_info['single_method'],
                                        "protocol": node_info['single_protocol'],
                                        "protocol_param": "#",
                                        "obfs": node_info['single_obfs'],
                                        "obfs_param": ''
                                   }
                               }

                        for port in config['additional_ports']:
                            val = config['additional_ports'][port]
                            val['port'] = int(port)
                            val['enable'] = 1
                            val['transfer_enable'] = 1024 ** 7
                            val['u'] = 0
                            val['d'] = 0
                            val['is_udp'] = node_info['is_udp']
                            if "password" in val:
                                val["passwd"] = val["password"]
                            
                            #md5参数用来判断节点信息是否修改
                            val['unique'] = hashlib.md5((json.dumps(val)).encode(encoding='UTF-8')).hexdigest()                           
                                
                            if db_instance.node_info_unique == None:
                                db_instance.node_info_unique = val['unique']
                           
                            rows.append(val)
                    #①停止超流的服务,②重启配置更改的服务,③启动新增的服务
                    db_instance.del_server_out_of_bound_safe(last_rows, rows)
                    db_instance.push_all_port_and_connect()
                    last_rows = rows
                except Exception as e:
                    trace = traceback.format_exc()
                    logging.error(trace)
                    #logging.warn('db thread except:%s' % e)
                if db_instance.event.wait(get_config().UPDATE_TIME) or not ServerPool.get_instance().thread.is_alive():
                    break
        except KeyboardInterrupt as e:
            pass
        db_instance.del_servers()
        ServerPool.get_instance().stop()
        db_instance = None

    @staticmethod
    def thread_db_stop():
        global db_instance
        db_instance.event.set()

class DbTransfer(TransferBase):
    def __init__(self):
        super(DbTransfer, self).__init__()
        self.user_pass = {}  # 记录更新此用户流量时被跳过多少次
        self.cfg = get_mysql_config()

        print('DbTransfer')

        
        # self.detect_text_list = {}
        # self.detect_text_ischanged = False

    def pull_db_all_user(self):

        rows = self.pull_db_users()
        logging.info("pull user from data is finished!")

        if not rows:
            logging.warn('no user in db')
        return rows
        

    # #单端口多用户统计在线用户信息
    def push_all_port_and_connect(self):
        config = shell.get_config(False)
        keys = ['node_id', 'port', 'type', 'ip']
        tcp_poll = None
        udp_poll = None
        if 'server_ipv6' in config:
            tcp_poll = ServerPool.get_instance().tcp_ipv6_servers_pool
            # udp_poll = ServerPool.get_instance().udp_ipv6_servers_pool #不统计udp
        else:
            tcp_poll = ServerPool.get_instance().tcp_servers_pool
            # udp_poll = ServerPool.get_instance().udp_servers_pool
        # 结果集


        result = []
        for (k, v) in tcp_poll.items():
            if len(v['one_minute_ips']) > 0:
                for (kk, vv) in v['one_minute_ips'].items():
                    result.append({
                        'node_id': self.cfg['node_id'],
                        'port': str(kk), #用户用户的端口号,判断用户身份
                        'type': 'tcp',
                        'ip': ','.join([ from_map_ipv6_get_ipv4(x) for x in vv ]),
                        'created_at': time.time(),
                        # 'used_port': k #使用流量的端口
                })

        # for (k, v) in udp_poll.items():
        #     if len(v['one_minute_ips']) > 0:
        #         result.append({
        #             'node': self.cfg['node_id'],
        #             'port': k,
        #             'type': 'udp',
        #             'ip': ','.join([from_map_ipv6_get_ipv4(x) for x in v['one_minute_ips']]),
        #             'created_at': time.time()
        #         })
        # 如果结果集不为空则更新数据库
        if len(result) > 0:
            self.post('api/insertSsNodeIp',{'data': json.dumps(result)})
            # with database.atomic():
            #     SsNodeIp.insert_many(result).execute()
            logging.info("push all user one minute connections finished")

class Dbv3Transfer(DbTransfer):
    def __init__(self):
        super(Dbv3Transfer, self).__init__()
        self.update_node_state = True 
        if self.update_node_state:
            self.key_list += ['id']
        self.key_list += ['method','obfs', 'protocol']

        self.key_list += []
        self.start_time = time.time()

    def update_all_user(self, dt_transfer):
        update_transfer = {}

        query_head = 'UPDATE user'
        query_sub_when = ''
        query_sub_when2 = ''
        query_sub_in = None
        last_time = time.time()

        alive_user_count = len(self.onlineuser_cache)
        bandwidth_thistime = 0

        for id in dt_transfer.keys():
            transfer = dt_transfer[id]
            bandwidth_thistime = bandwidth_thistime + transfer[0] + transfer[1]

            update_trs = 1024 * (2048 - self.user_pass.get(id, 0) * 64)
            if transfer[0] + transfer[1] < update_trs:
                self.user_pass[id] = self.user_pass.get(id, 0) + 1
                continue
            if id in self.user_pass:
                del self.user_pass[id]

            query_sub_when += ' WHEN %s THEN u+%s' % (id, int(transfer[0] * int(self.cfg["transfer_mul"])))
            query_sub_when2 += ' WHEN %s THEN d+%s' % (id, int(transfer[1] * int(self.cfg["transfer_mul"])))
            update_transfer[id] = transfer

            if self.update_node_state:
                try:
                    if id in self.port_uid_table:
                        self.post('api/userTrafficLog',{
                            'user_id' : str(self.port_uid_table[id]),
                            'u' : str(transfer[0]),
                            'd' : str(transfer[1]),
                            'node_id' : str(self.cfg["node_id"]),
                            'rate' : str(self.cfg["transfer_mul"]),
                            'traffic' : self.traffic_format((transfer[0] + transfer[1]) * int(self.cfg["transfer_mul"])) ,
                        })
                except:
                    logging.warn('no `user_traffic_log` in db')


            if query_sub_in is not None:
                query_sub_in += ',%s' % id
            else:
                query_sub_in = '%s' % id
        if query_sub_when != '':#更新用户表、U/D,直接传sql语句运行，存在安全问题，以后记得改，现在懒得改了 2022-02-05
            
            query_sql = query_head + ' SET u = CASE port' + query_sub_when + \
                        ' END, d = CASE port' + query_sub_when2 + \
                        ' END, t = ' + str(int(last_time)) + \
                        ' WHERE port IN (%s)' % query_sub_in
            r = self.post('api/updateUserUD',{
                'query_sql' : query_sql,
            })

            #原mysql代码
            # query_sql = query_head + ' SET u = CASE port' + query_sub_when + \
            #             ' END, d = CASE port' + query_sub_when2 + \
            #             ' END, t = ' + str(int(last_time)) + \
            #             ' WHERE port IN (%s)' % query_sub_in
           
            # print(query_sql)
            # cur = conn.cursor()
            # try:
            #     print(query_sql)
            #     cur.execute(query_sql)
            # except Exception as e:
            #     logging.error(e)
            # cur.close()

        if self.update_node_state:
            try:
                self.post('api/updateNodeOnlineLog',{
                    'node_id': str(self.cfg["node_id"]) ,
                    'online_user': str(alive_user_count),                
                })

                self.post('api/updateNodeInfo',{
                    'node_id': str(self.cfg["node_id"]) ,
                    'uptime' : str(self.uptime()),   
                    'load' : str(self.load()),
                })
            except:
                logging.warn('no `ss_node_online_log` or `" + self.ss_node_info_name + "` in db')


        #统计审计记录
        detect_log_list = ServerPool.get_instance().get_servers_detect_log()
        for port in detect_log_list.keys():
            for user_str in detect_log_list[port]:
                user_array = user_str.split('#')
                user_port = int(user_array[0])
                is_black = user_array[1] 
                rule_id = user_array[2]
                now_time = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
                if user_port not in self.port_uid_table :
                    continue
                data = {
                    'user_id' : str(self.port_uid_table[user_port]),
                    'node_id' : str(self.cfg["node_id"]),
                    'rule_id' : str(rule_id),
                    'created_at' : now_time,
                    'updated_at' : now_time,
                    'is_black' : is_black

                };
                r = self.post('api/createRuleLog',data)
        # conn.close()
        return update_transfer

    def pull_db_users(self):
        # print('pull_db_users v3')
        keys = copy.copy(self.key_list)
        try:
            switchrule = importloader.load('switchrule')
            keymap = switchrule.getRowMap()
            for key in keymap:
                if keymap[key] in keys:
                    keys.remove(keymap[key])
                keys.append(key)
            keys = switchrule.getKeys(keys)
        except Exception as e:
            logging.error('load switchrule.py fail')


        if self.update_node_state:
            try:
                #获取节点信息
                nodeinfo = self.post('api/getNode')
            except Exception as e:
                logging.error(e)
                nodeinfo = None
            if nodeinfo == None:
                rows = []
                logging.warn('None result when select node info from ss_node in db, maybe you set the incorrect node id')
                return rows
            
            if nodeinfo['type'] != 1: #不是ssr节点，退出
                logging.error('This node is not an SSR,Exit()')
                sys.exit()

            node_info_dict = {}
            for key,column in nodeinfo.items():
                node_info_dict[key] = column
            self.cfg['transfer_mul'] = float(node_info_dict['traffic_rate'])
            self.cfg['node_id'] = node_info_dict['id']
            self.node_info = node_info_dict
            
            #读取审计规则
            rules = self.post('api/ruleList')
            exist_id_list = []
            for r in rules:
                id = int(r['id'])
                exist_id_list.append(id)
                if id not in self.detect_text_list:
                    self.detect_text_list[id] = r
                    self.detect_text_ischanged = True
                else:
                    if (r['id'] != self.detect_text_list[id]['id']):
                        del self.detect_text_list[id]
                        self.detect_text_list[id] = r
                        self.detect_text_ischanged = True
            
            deleted_id_list = []
            for id in self.detect_text_list:
                if id not in exist_id_list:
                    deleted_id_list.append(id)
                    self.detect_text_ischanged = True

            for id in deleted_id_list:
                del self.detect_text_list[id]

        #获取正常用户列表
        return self.post('api/userList')

    def load(self):
        import os
        return os.popen("cat /proc/loadavg | awk '{ print $1\" \"$2\" \"$3 }'").readlines()[0]

    def uptime(self):
        return time.time() - self.start_time

    def traffic_format(self, traffic):
        if traffic < 1024 * 8:
            return str(int(traffic)) + "B";

        if traffic < 1024 * 1024 * 2:
            return str(round((traffic / 1024.0), 2)) + "KB";

        return str(round((traffic / 1048576.0), 2)) + "MB";

    #自定义post方法
    def post(self, url,data={},headers={}):
        headers['token'] = self.cfg["token"]
        r = requests.post(self.cfg["base_url"] + url, data=data, headers=headers)

        if r.status_code != 200:
            print('status_code:' + str(r.status_code) + ',url:'+ url);
            sys.exit()

        r = r.json()
        if r['status'] != 200:
            print(url)
            print(r)
            sys.exit()
        return r['data']
