#!/bin/bash
title="/root/shadowsocksr/usermysql.json"
host=""
port=3306
user="root"
password=""
db="ssrpanel"
node_id=0
transfer_mul="1.0"
ssl_enable=0
ssl_ca=""
ssl_cert=""
ssl_key=""
token=""
base_url=""

if [ ${m_token} ]
then
token=${m_token}
fi

if [ ${m_base_url} ]
then
base_url=${m_base_url}
fi

if [ ${m_host} ]
then
host=${m_host}
fi

if [ ${m_port} ]
then
port=${m_port}
fi

if [ ${m_user} ]
then
user=${m_user}
fi

if [ ${m_password} ]
then
password=${m_password}
fi

if [ ${m_db} ]
then
db=${m_db}
fi


if [ ${m_node_id} ]
then
node_id=${m_node_id}
fi


if [ ${m_transfer_mul} ]
then
transfer_mul=${m_transfer_mul}
fi

if [ ${m_ssl_enable} ]
then
ssl_enable=${m_ssl_enable}
fi



echo -e "{" > ${title}
echo -e "\t\"host\":\"${host}\"," >> ${title}

echo -e "\t\"port\":\"${port}\"," >> ${title}

echo -e "\t\"user\":\"${user}\"," >> ${title}

echo -e "\t\"password\":\"${password}\"," >> ${title}

echo -e "\t\"db\":\"${db}\"," >> ${title}

echo -e "\t\"node_id\":\"${node_id}\"," >> ${title}

echo -e "\t\"token\":\"${token}\"," >> ${title}

echo -e "\t\"base_url\":\"${base_url}\"," >> ${title}

echo -e "\t\"transfer_mul\":\"${transfer_mul}\"," >> ${title}

echo -e "\t\"ssl_enable\":\"${ssl_enable}\"," >> ${title}

echo -e "\t\"ssl_ca\":\"${ssl_ca}\"," >> ${title}

echo -e "\t\"ssl_cert\":\"${ssl_cert}\"," >> ${title}

echo -e "\t\"ssl_key\":\"${ssl_key}\"" >> ${title}

echo -e "}" >> ${title}
cd /root/shadowsocksr
sh ./stop.sh
python3 server.py
