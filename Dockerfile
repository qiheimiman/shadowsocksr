FROM centos:7
ADD ./shadowsocksr /root/shadowsocksr
ADD ./mysql.sh /mysql.sh
RUN buildDeps= ls / && cd /root && ls \
  && yum install -y  net-tools \
  && yum install -y  python3 && python3 --version \
  && pip3 install --user  peewee \
  && pip3 install --user  pymysql \
  && pip3 install --user requests
