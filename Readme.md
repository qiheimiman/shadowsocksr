
基于ssrpanel4.8开源版修改，面板和后端代码已改，不兼容源版
======
**ssrpanel-(ssr)python后端 docker版本**
------

### 环境：centos7、docker ###

### 构建镜像： docker build .   ###
### 运行容器： docker run -itd --name ssrpanel_python -p 998:998 -p 998:998/udp --restart=always -e m_node_id=111 -e m_base_url=http://101.132.166.136:81/ -e m_token=5  ec391a449b86 /mysql.sh ###
### 参数：m_node_id：节点id, 随便传已经废弃  ###
###  m_base_url: ssrpanel面板地址,改为请求接口更新数据 ###
###  m_token：python节点请求接口token (ss_node表的token)   ###
### ec391a449b86：镜像id  ### 
### /mysql.sh 容器启动后运行的脚本  ###