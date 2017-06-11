#!/usr/bin/python
# -*- coding:utf-8 -*-
# by caiwenhao
import sys

reload(sys)
import optparse
import os
import re
import time
import subprocess
import shlex
import httplib
import json

usage = "usage: %prog [options] arg1 arg2"
parser = optparse.OptionParser()
parser.add_option("-m", "--zabbix", dest = "zabbix", default = '', help = u"方法")
parser.add_option("-p", "--parameter", dest = "parameter", default = '', help = u"参数")
(options, args) = parser.parse_args()

try:
    for d in os.listdir('/data/apps/deps/'):
        if re.match(r'^jdk', d):
            JAVA_BIN = '/data/apps/deps/%s/bin/java' % d
            continue
except:
    JAVA_BIN = 'java'


def get_cmd_data(cmd):
    pipe = os.popen(cmd)
    data = pipe.read().strip()
    return data


# ip发现规则
def ip_discovery():
    ip_list = []
    all_ip = get_cmd_data("/sbin/ifconfig |awk -F\: '/inet addr/ {print $2}'|awk '{print $1}'").split()
    wan_ip = get_cmd_data('/bin/grep -o -E "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" /root/.bashrc')
    all_ip.append(wan_ip)
    all_ip = list(set(all_ip))
    import platform
    if platform.platform().find('tlinux') != -1 and len(all_ip) > 1:
        for ip in all_ip and len:
            if re.match(r'^10.\d+.', ip):
                data = {}
                data['{#MCIP}'] = ip
                ip_list.append(data)
    else:
        for ip in all_ip:
            data = {}
            data['{#MCIP}'] = ip
            ip_list.append(data)
    result = {'data': ip_list}
    print str(result).replace("'", '"').replace(" ", "")


# 服务发现规则
def service_discovery():
    service_name = []
    for d in os.listdir('/data/web/webapps/'):
        if re.match(r'lsservice-.+', d):
            data = {}
            data['{#NAME}'] = d
            service_name.append(data)
    result = {'data': service_name}
    print str(result).replace("'", '"').replace(" ", "")


# tomcat发现规则
def tomcat_discovery():
    tomcat_list = []
    JMX_PORT_LIST = []
    APPS_DIR = os.path.join('/', 'data', 'apps')
    # APPS_DIR = os.path.join('/', 'Users', 'XJ', 'Downloads')
    XML_FILE = os.path.join('conf', 'server.xml')
    for d in os.listdir(APPS_DIR):
        CONF_DIR = os.path.join(APPS_DIR, d)
        if os.path.isdir(CONF_DIR) and re.match('tomcat\d+$', d):
            f = open(os.path.join(CONF_DIR, XML_FILE), 'r')
            s = f.read()
            JMX_PORT_LIST.append(re.sub('"', '', re.search(r'rmiRegistryPortPlatform="\d+"', s).group(0)).split('=')[1])
            f.close()
    for JMX_PORT in JMX_PORT_LIST:
        port = JMX_PORT
        key = sys.argv[4]
        tomcat_info = get_cmd_data(
            "%s -jar /usr/local/zabbix/sbin/cmdline-jmxclient-0.10.3.jar - "
            "127.0.0.1:%s 2> /dev/null" % (JAVA_BIN, port))
        re_result = re.compile(r'Catalina:(name|port)="*(.+[^"])"*,type=%s' % key)
        if key == "Manager":
            re_result = re.compile(r'Catalina:(context)="*(.+[^"])"*,host=(.+),type=%s' % key)
        if not tomcat_info:
            continue
        match = re_result.findall(tomcat_info)
        for tomcat in match:
            data = {}
            data['{#NAME}'] = tomcat[1]
            data['{#PORT}'] = port
            data['{#TYPE}'] = key
            if key == "Manager":
                data['{#HOST}'] = tomcat[2]
            tomcat_list.append(data)
    result = {'data': tomcat_list}
    print str(result).replace("'", '"').replace(" ", "")


# jetty发现规则
def jetty_discovery():
    jetty_list = []
    JMX_PORT_LIST = []
    APPS_DIR = os.path.join('/', 'data', 'apps')
    # APPS_DIR = os.path.join('/', 'Users', 'XJ', 'Downloads')
    XML_FILE = os.path.join('etc', 'jetty-jmx.xml')
    for d in os.listdir(APPS_DIR):
        CONF_DIR = os.path.join(APPS_DIR, d)
        if os.path.isdir(CONF_DIR) and re.match('jetty\d+$', d):
            f = open(os.path.join(CONF_DIR, XML_FILE), 'r')
            s = f.read()
            JMX_PORT_LIST.append(re.sub('"', '', re.search(r' default="\d+" ', str(
                re.findall(r' name="jetty.jmxrmiport" .*/>',
                           str(re.findall(r' id="ConnectorServer" .*', s, re.S))))).group(0)).split('=')[1])
            f.close()
    for JMX_PORT in JMX_PORT_LIST:
        jetty_info = get_cmd_data(
            "%s -jar /usr/local/zabbix/sbin/cmdline-jmxclient-0.10.3.jar - 127.0.0.1:%s 'java.lang:type=Runtime' SystemProperties 2>&1" % (
            JAVA_BIN, JMX_PORT))
        JETTY_PORT = re.search(r'^value: %s/jetty\d+$' % APPS_DIR,
                               str(re.findall(r'key: jetty.home\n.*', jetty_info))).group().split('/')[-1]
        data = {}
        data['{#NAME}'] = JETTY_PORT
        data['{#PORT}'] = JMX_PORT
        jetty_list.append(data)
    result = {'data': jetty_list}
    print str(result).replace("'", '"').replace(" ", "")


# redis发现规则
def redis_discovery():
    redis_list = []
    redis_info = get_cmd_data("/bin/netstat -ntlp|/bin/grep redis-server")
    re_result = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\:(\d+)')
    match = re_result.findall(redis_info)
    for port in match:
        if port not in redis_list:
            data = {}
            data['{#PORT}'] = port
            redis_list.append(data)
    result = {'data': redis_list}
    print str(result).replace("'", '"').replace(" ", "")


# redis_check 检查计步器状态
def redis_check():
    type = sys.argv[3]
    try:
        cmd = "%s -jar /usr/local/zabbix/sbin/check.jar %s" % (JAVA_BIN, type)
        redis_info = get_cmd_data(cmd)
        print redis_info
    except:
        pass


# redis 状态
def redis_status():
    port = sys.argv[3]
    key = sys.argv[4]
    redis_info = get_cmd_data(
        "/bin/netstat -ntlp|/bin/grep redis-server | /bin/egrep '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:%s '" % port)
    re_result = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\:%s' % port)
    try:
        match = re_result.findall(redis_info)[0]
        if re.match(r'(0.0.0.0|127.0.0.1)', match):
            ip = 'localhost'
        else:
            ip = match
        cmd = "/usr/local/redis/bin/redis-cli -h %s -p %s info" % (ip, port)
        re_result = re.compile(r'%s:(?P<value>.+)\r' % key)
        if key in ['keys', 'expires', 'avg_ttl']:
            cmd = "/usr/local/redis/bin/redis-cli -h %s -p %s info|/bin/grep db0:" % (ip, port)
            re_result = re.compile(r'%s=(\d+)' % key)
        elif key == 'PING':
            cmd = "/usr/local/redis/bin/redis-cli -h %s -p %s PING 'ok'" % (ip, port)
            re_result = re.compile(r'(^ok$)')
        redis_info = get_cmd_data(cmd)
        match = re_result.search(redis_info)
        result = match.groups()[0]
        print result
    except:
        pass


# tomcate 状态
def tomcat_status():
    port = sys.argv[3]
    type = sys.argv[4]
    name = sys.argv[5]
    value = sys.argv[6]
    if type == "GlobalRequestProcessor" or type == "ThreadPool":
        tomcat_info = get_cmd_data(
            "%s -jar /usr/local/zabbix/sbin/cmdline-jmxclient-0.10.3.jar - 127.0.0.1:%s 'Catalina:name=\"%s\",type=%s' %s 2>&1" % (
            JAVA_BIN, port, name, type, value))
    if type == "ProtocolHandler":
        tomcat_info = get_cmd_data(
            "%s -jar /usr/local/zabbix/sbin/cmdline-jmxclient-0.10.3.jar - 127.0.0.1:%s 'Catalina:port=%s,type=%s' %s 2>&1" % (
            JAVA_BIN, port, name, type, value))
    if type == "Manager":
        tomcat_info = get_cmd_data(
            "%s -jar /usr/local/zabbix/sbin/cmdline-jmxclient-0.10.3.jar - 127.0.0.1:%s 'Catalina:context=%s,host=localhost,type=%s' %s 2>&1" % (
            JAVA_BIN, port, name, type, value))
    if type == "OperatingSystem" or type == "Runtime" or type == "Memory":
        tomcat_info = ""
        tomcat_info = get_cmd_data(
            "%s -jar /usr/local/zabbix/sbin/cmdline-jmxclient-0.10.3.jar - 127.0.0.1:%s 'java.lang:type=%s' %s 2>&1" % (
            JAVA_BIN, port, type, value))
    re_result = re.compile(r'^.+: (.+)$')
    if type == "Memory":
        re_result = re.compile(r"%s: (\d+)" % name)
        print re_result.findall(tomcat_info)[0]
        return
    print re_result.match(tomcat_info).groups()[0]


# disk发现规则
def disk_discovery():
    disk_list = []
    file = open('/proc/partitions')
    lines = file.readlines()
    file.close()
    for line in lines:
        try:
            disk_name = line.split()[3]
        except:
            continue
        if disk_name == "" or disk_name == "name":
            continue
        if re.compile(r'.*\d+').match(disk_name):
            continue
        data = {}
        data['{#DISK}'] = disk_name
        disk_list.append(data)
    result = {'data': disk_list}
    print str(result).replace("'", '"').replace(" ", "")


# 磁盘性能
def disk_performance():
    p = subprocess.Popen("cat /proc/diskstats |/bin/grep -w %s" % sys.argv[3], shell = True, stdout = subprocess.PIPE)
    disk_info = p.communicate()[0].split()
    if sys.argv[4] == "read.ops":
        print disk_info[2 + 1]
    elif sys.argv[4] == "read.ms":
        print disk_info[2 + 4]
    elif sys.argv[4] == "write.ops":
        print disk_info[2 + 5]
    elif sys.argv[4] == "write.ms":
        print disk_info[2 + 8]
    elif sys.argv[4] == "io.active":
        print disk_info[2 + 9]
    elif sys.argv[4] == "io.ms":
        print disk_info[2 + 10]
    elif sys.argv[4] == "read.sectors":
        print disk_info[2 + 3]
    elif sys.argv[4] == "write.sectors":
        print disk_info[2 + 7]


# 网络连接
def tcp_ss():
    tcp_info = get_cmd_data('/usr/sbin/ss -s')
    pattern = re.compile(r'estab (?P<estab>\d+), closed (?P<closed>\d+).+ timewait (?P<timewait>\d+)')
    m = pattern.search(tcp_info)
    result = m.groupdict()
    try:
        print result[sys.argv[3]]
    except:
        pass


# mysql发现规则
def mysql_discovery():
    mysql_list = []
    mysql_info = get_cmd_data("/bin/netstat -ntlp|/bin/grep mysqld")
    re_result = re.compile(r'0.0.0.0|:::(\d+)')
    match = re_result.findall(mysql_info)
    for port in match:
        data = {}
        data['{#PORT}'] = port
        mysql_list.append(data)
    result = {'data': mysql_list}
    print str(result).replace("'", '"').replace(" ", "")


# mysql性能
def mysql_status():
    try:
        port = sys.argv[4]
    except:
        port = 3306
    if sys.argv[3] == "version":
        print get_cmd_data('/usr/local/mysql/bin/mysql --socket=/tmp/mysql%s.sock -V' % port)
    elif sys.argv[3] == "alive":
        print get_cmd_data(
            '/usr/local/mysql/bin/mysqladmin --login-path=zabbix --socket=/tmp/mysql%s.sock ping|grep alive|wc -l' % port)
    elif sys.argv[3] == "Slave_SQL_Running" or sys.argv[3] == "Slave_IO_Running":
        print get_cmd_data(
            '/usr/local/mysql/bin/mysql --login-path=zabbix --socket=/tmp/mysql%s.sock -e "show slave status \G"|/bin/grep %s' % (
                port, sys.argv[3]))
    elif sys.argv[3] == "binlog_diff":
        try:
            import pickle
            pkl_file = open('/tmp/binlog%s.pkl' % port, 'rb')
            old_binlog = pickle.load(pkl_file)
            pkl_file.close()
        except:
            binlog = get_cmd_data(
                '/usr/local/mysql/bin/mysql --login-path=zabbix --socket=/tmp/mysql%s.sock -e "show master logs"' % port).split(
                '\n')
            output = open('/tmp/binlog%s.pkl' % port, 'wb')
            pickle.dump(binlog, output)
            output.close()
            print 0
            sys.exit(0)
        binlog = get_cmd_data(
            '/usr/local/mysql/bin/mysql --login-path=zabbix --socket=/tmp/mysql%s.sock -e "show master logs"' % port).split(
            '\n')
        new_diff = list(set(binlog) - set(old_binlog))
        new_diff_dict = {}
        for row in new_diff:
            new_diff_dict[row.split('\t')[0]] = row.split('\t')[1]
        old_diff = list(set(old_binlog) - set(binlog))
        old_diff_dict = {}
        for row in old_diff:
            old_diff_dict[row.split('\t')[0]] = row.split('\t')[1]
        if sorted(old_diff_dict.keys())[-1] not in new_diff_dict.keys():
            print sum([int(i) for i in new_diff_dict.values()])
        else:
            print sum([int(i) for i in new_diff_dict.values()]) - int(old_diff_dict[sorted(old_diff_dict.keys())[-1]])
        output = open('/tmp/binlog%s.pkl' % port, 'wb')
        pickle.dump(binlog, output)
        output.close()
    elif sys.argv[3] == "binlog":
        binlog = get_cmd_data(
            '/usr/local/mysql/bin/mysql --login-path=zabbix --socket=/tmp/mysql%s.sock -e "show master logs"' % port).split(
            '\n')
        binlog_dict = {}
        for row in binlog:
            binlog_dict[row.split('\t')[0]] = row.split('\t')[1]
        print sum([int(i) for i in binlog_dict.values() if i != "File_size"])
    elif sys.argv[3] == "Seconds_Behind_Master":
        print get_cmd_data(
            '/usr/local/mysql/bin/mysql --login-path=zabbix --socket=/tmp/mysql%s.sock -e "show slave status \G"|/bin/grep %s | awk -F ": " "{print \$NF}" ' % (
            port, sys.argv[3]))
    else:
        try:
            status = get_cmd_data(
                '/usr/local/mysql/bin/mysql --login-path=zabbix --socket=/tmp/mysql%s.sock -e "show global status"| /bin/grep %s' % (
                    port, sys.argv[3]))
            pattern = re.compile(r'%s\s*(?P<closed>\d+)' % sys.argv[3])
            m = pattern.search(status)
            result = m.groups()
            print result[0]
        except:
            pass


# 监控mysql_schema
def mysql_schema():
    def mysql_information(type1, type2 = None, type3 = None):
        # type1 for type
        # type2 for database name
        # type3 for table name
        if type1 == "dbtotal":
            sqlquery = "select sum(data_length+index_length) from information_schema.tables where table_schema='%s';" % (
            type2)
        elif type1 == "dbdata":
            sqlquery = "select sum(data_length)              from information_schema.tables where table_schema='%s';" % (
            type2)
        elif type1 == "dbidx":
            sqlquery = "select sum(index_length)             from information_schema.tables where table_schema='%s';" % (
            type2)
        elif type1 == "tbtotal":
            sqlquery = "select (data_length+index_length)    from information_schema.tables where table_schema='%s' and table_name='%s';" % (
            type2, type3)
        elif type1 == "tbdata":
            sqlquery = "select (data_length)                 from information_schema.tables where table_schema='%s' and table_name='%s';" % (
            type2, type3)
        elif type1 == "tbidx":
            sqlquery = "select (index_length)                from information_schema.tables where table_schema='%s' and table_name='%s';" % (
            type2, type3)
        else:
            sys.exit(0)
        return (sqlquery)

    try:
        port = sys.argv[3]
        type1 = sys.argv[4]
        try:
            type2 = sys.argv[5]
        except:
            type2 = None
        try:
            type3 = sys.argv[6]
        except:
            type3 = None
        information = get_cmd_data(
            '/usr/local/mysql/bin/mysql --login-path=zabbix --socket=/tmp/mysql%s.sock -e "%s"' % (
            port, mysql_information(type1, type2, type3))).split('\n')
        print information[1]
    except:
        print 0


# nginx状态
def nginx_status():
    if sys.argv[3] == "version":
        for version in get_cmd_data('/usr/local/nginx/sbin/nginx -v').split():
            if version:
                print version
    else:
        nginx_status_info = get_cmd_data("/usr/bin/curl -s 'http://127.0.0.1/nginx-status'")
        pattern = re.compile(r'%s:(?P<status>\d+)' % sys.argv[3])
        m = pattern.search(nginx_status_info)
        if m:
            result = m.groups()
            print result[0]
        else:
            re_result = re.compile(
                r'Active connections: (?P<connections>\d+) \nserver accepts handled requests request_time\n (?P<accepts>\d+) (?P<handled>\d+) (?P<requests>\d+) (?P<request_time>\d+)\nReading: (?P<Reading>\d+) Writing: (?P<Writing>\d+) Waiting: (?P<Waiting>\d+)',
                re.M)
            match = re_result.match(nginx_status_info)
            if match:
                print match.groupdict()[sys.argv[3]]


# 任务计划数
def crond_num():
    crond_num = get_cmd_data("ps -ef | awk '/cron$|crond$/ && $3==1' | wc -l")
    print crond_num


# 获取组
def get_group():
    group = ["MC"]
    fp = open('/root/.bashrc', "r")
    alllines = fp.read()
    fp.close()
    if os.path.exists("/data/web/minggame/config/config.php"):
        group.append('mcsd')
    elif re.findall(r'M11_|tgzt_', alllines):
        group.append('tgzt')
    elif re.findall(r'M8_|xlfc_', alllines):
        group.append('xlfc')
    elif re.findall(r'M10_|ljxz_', alllines):
        group.append('ljxz')
    elif re.findall(r'M2_|mccq_', alllines):
        group.append('mccq')
    elif re.findall(r'backup', alllines):
        group.append('backup')
    else:
        result = re.findall(r'@(.+)_', alllines)
        name = result[0].split('_')[0]
        group.append(name)
    if re.findall(r'elex', alllines):
        group.append('elex')
    import platform
    if platform.platform().find('tlinux') != -1:
        group.append('tencent')
    if os.path.exists("/tmp/zabbix_proxy.pid"):
        group.append('zabbix_proxy')
    print ",".join(group)


# 获取服务
def get_service():
    service_list = ['mingchao']
    import commands
    if commands.getoutput("ls /data/*_*_*/server/setting/common.config 2>/dev/null|wc -l") != "0":
        fp = open('/usr/local/zabbix/etc/zabbix_agentd.conf', "r")
        alllines = fp.read()
        fp.close()
        m = re.findall(r'192.168.4.31', alllines)
        if not m:
            service_list.append('game')
            if os.path.exists('/root/test'):
                service_list.remove('game')
    process = commands.getoutput('ps aux')
    if re.findall(r'mysqld_safe', process):
        service_list.append('mysql')
    if re.findall(r'memcached', process):
        service_list.append('memcached')
    if re.findall(r'nginx', process):
        service_list.append('nginx')
    if re.findall(r'php-cgi', process):
        service_list.append('php-cgi')
    if re.findall(r'mlog_app', process):
        service_list.append('mlog')
    if re.findall(r'bgp', process):
        service_list.append('bgp')
    if os.path.exists('/data/msalt'):
        service_list.append('msalt')
    if re.findall(r'metrilyx', process):
        service_list.append('openstdb')
    print ','.join(service_list)


# 输出值
def echo():
    print sys.argv[3]


# 删除key
def del_key():
    key_name = sys.argv[3]
    if not key_name:
        print 1
        return
    subprocess.Popen("""sed -i "/%s/d" /root/.ssh/authorized_keys""" % key_name, shell = True)
    if os.path.isdir("/root/.ssh2/keys"):
        for key in os.listdir('/root/.ssh2/keys/'):
            if key.find(key_name) != -1:
                subprocess.Popen("""/bin/mv /root/.ssh2/keys/%s* /data/backup/""" % key_name, shell = True)
    print 1


def check_iptables():
    iptables_status = 0
    import platform
    if platform.platform().find('tlinux') != -1:
        iptables_status = 0
    else:
        iptables_status = get_cmd_data("/etc/init.d/iptables status|grep 'Chain INPUT (policy DROP)'>/dev/null;echo $?")
    print iptables_status


def check_timezone():
    time_zone = ""
    result = 0
    fp = open('/root/.bashrc', "r")
    alllines = fp.read()
    fp.close()
    p = re.compile(r'TimeZone=(?P<time_zone>.*)')
    m = p.search(alllines)
    if m:
        time_zone = m.groupdict()['time_zone']
        local_time = get_cmd_data('/bin/date +%Z')
        if time_zone != local_time:
            result = 1
    print result


def ES_check(host = '127.0.0.1', port = '9200', url = '/_cluster/health'):
    # 检查ES的健康状态
    dic_status = {'green': 0, 'yellow': 1, 'red': 2}
    # 正常          警告          严重
    try:
        Httpclient = httplib.HTTPConnection(host, port, timeout = 3)
        Httpclient.request('GET', url)
        res = Httpclient.getresponse()
        print dic_status[json.loads(res.read())['status']]
    except Exception:
        print 3
        # 灾难
    Httpclient.close()


def http_check():
    # http状态码监控
    statuscode = sys.argv[3]
    Second = 300
    Time = time.time()
    S_index_name = time.strftime('logstash-%Y.%m.%d.%H', time.localtime(Time - 8 * 60 * 60 - Second))
    E_index_name = time.strftime('logstash-%Y.%m.%d.%H', time.localtime(Time - 8 * 60 * 60))
    url = '/' + S_index_name + ',' + E_index_name + '/_search'
    last_timestamp = int(Time * 1000) - int(Second) * 1000
    timestamp = int(Time * 1000)
    data = {
        "facets": {
            "terms": {
                "terms": {
                    "field": "status",
                    "size": 20,
                    "order": "count",
                    "exclude": []
                },
                "facet_filter": {
                    "fquery": {
                        "query": {
                            "filtered": {
                                "query": {
                                    "bool": {
                                        "should": [
                                            {
                                                "query_string": {
                                                    "query": "*"
                                                }
                                            }
                                        ]
                                    }
                                },
                                "filter": {
                                    "bool": {
                                        "must": [
                                            {
                                                "range": {
                                                    "@timestamp": {
                                                        "from": last_timestamp,
                                                        "to": timestamp
                                                    }
                                                }
                                            },
                                            {
                                                "fquery": {
                                                    "query": {
                                                        "query_string": {
                                                            "query": "type:(\"nginx_access\")"
                                                        }
                                                    }
                                                }
                                            },
                                            {
                                                "terms": {
                                                    "status": [
                                                        statuscode
                                                    ]
                                                }
                                            }
                                        ],
                                        "must_not": [
                                            {
                                                "terms": {
                                                    "servername": ["www.lifesense.com"]
                                                }
                                            },
                                            {
                                                "terms": {
                                                    "servername": ["dev.sports.lifesense.com"]
                                                }
                                            },
                                            {
                                                "terms": {
                                                    "servername": ["websocket.lifesense.com"]
                                                }
                                            }
                                        ]
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "size": 0
    }

    data_urlencode = json.dumps(data)
    try:
        Httpclient = httplib.HTTPConnection('127.0.0.1', '9200', timeout = 3)
        Httpclient.request('GET', url, data_urlencode)
        res = json.loads(Httpclient.getresponse().read())
        count = res['facets']['terms']['total']
        print count
    except Exception:
        print 0
    Httpclient.close()


def http_interface_check():
    # http接口访问监控
    interface = sys.argv[3]
    gt_S = sys.argv[4]
    percent = sys.argv[5]
    Second = 300
    Time = time.time()
    S_index_name = time.strftime('logstash-%Y.%m.%d.%H', time.localtime(Time - 8 * 60 * 60 - Second))
    E_index_name = time.strftime('logstash-%Y.%m.%d.%H', time.localtime(Time - 8 * 60 * 60))
    url = '/' + S_index_name + ',' + E_index_name + '/_search'
    last_timestamp = int(Time * 1000) - int(Second) * 1000
    timestamp = int(Time * 1000)
    data = {
        "facets": {
            "1": {
                "terms": {
                    "field": "interface",
                    "size": 20,
                    "order": "count",
                    "exclude": []
                },
                "facet_filter": {
                    "fquery": {
                        "query": {
                            "filtered": {
                                "query": {
                                    "bool": {
                                        "should": [
                                            {
                                                "query_string": {
                                                    "query": "*"
                                                }
                                            }
                                        ]
                                    }
                                },
                                "filter": {
                                    "bool": {
                                        "must": [
                                            {
                                                "range": {
                                                    "@timestamp": {
                                                        "from": last_timestamp,
                                                        "to": timestamp
                                                    }
                                                }
                                            },
                                            {
                                                "fquery": {
                                                    "query": {
                                                        "query_string": {
                                                            "query": "type:(\"nginx_access\")"
                                                        }
                                                    }
                                                }
                                            },
                                            {
                                                "fquery": {
                                                    "query": {
                                                        "query_string": {
                                                            "query": "REQtime:>%s" % gt_S
                                                        },
                                                    }
                                                }
                                            },
                                            {
                                                "terms": {
                                                    "interface": [
                                                        interface
                                                    ]
                                                }
                                            }
                                        ]
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "2": {
                "terms": {
                    "field": "interface",
                    "size": 20,
                    "order": "count",
                    "exclude": []
                },
                "facet_filter": {
                    "fquery": {
                        "query": {
                            "filtered": {
                                "query": {
                                    "bool": {
                                        "should": [
                                            {
                                                "query_string": {
                                                    "query": "*"
                                                }
                                            }
                                        ]
                                    }
                                },
                                "filter": {
                                    "bool": {
                                        "must": [
                                            {
                                                "range": {
                                                    "@timestamp": {
                                                        "from": last_timestamp,
                                                        "to": timestamp
                                                    }
                                                }
                                            },
                                            {
                                                "fquery": {
                                                    "query": {
                                                        "query_string": {
                                                            "query": "type:(\"nginx_access\")"
                                                        }
                                                    }
                                                }
                                            },
                                            {
                                                "fquery": {
                                                    "query": {
                                                        "query_string": {
                                                            "query": "REQtime:<=%s" % gt_S
                                                        },
                                                    }
                                                }
                                            },
                                            {
                                                "terms": {
                                                    "interface": [
                                                        interface
                                                    ]
                                                }
                                            }
                                        ]
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "size": 0
    }

    data_urlencode = json.dumps(data)
    try:
        Httpclient = httplib.HTTPConnection('127.0.0.1', '9200', timeout = 3)
        Httpclient.request('GET', url, data_urlencode)
        res = json.loads(Httpclient.getresponse().read())
        count = res['facets']['1']['total']
        info = count
        if percent == 'percent':
            count2 = res['facets']['2']['total']
            info = round(float(count) / float(count + count2) * 100, 3)
        print info
    except Exception:
        print 0
    Httpclient.close()


def mysql_slow_check():
    # mysql慢查询监控
    gt_S = sys.argv[3]
    Second = 300
    Time = time.time()
    S_index_name = time.strftime('mysql_slow-%Y.%m.%d.%H', time.localtime(Time - 8 * 60 * 60 - Second))
    E_index_name = time.strftime('mysql_slow-%Y.%m.%d.%H', time.localtime(Time - 8 * 60 * 60))
    url = '/' + S_index_name + ',' + E_index_name + '/_search'
    last_timestamp = int(Time * 1000) - int(Second) * 1000
    timestamp = int(Time * 1000)
    data = {
        "facets": {
            "terms": {
                "terms": {
                    "field": "tags",
                    "size": 20,
                    "order": "count",
                    "exclude": []
                },
                "facet_filter": {
                    "fquery": {
                        "query": {
                            "filtered": {
                                "query": {
                                    "bool": {
                                        "should": [
                                            {
                                                "query_string": {
                                                    "query": "*"
                                                }
                                            }
                                        ]
                                    }
                                },
                                "filter": {
                                    "bool": {
                                        "must": [
                                            {
                                                "range": {
                                                    "@timestamp": {
                                                        "from": last_timestamp,
                                                        "to": timestamp
                                                    }
                                                }
                                            },
                                            {
                                                "fquery": {
                                                    "query": {
                                                        "query_string": {
                                                            "query": "type:(\"mysql_slow\")"
                                                        }
                                                    }
                                                }
                                            },
                                            {
                                                "fquery": {
                                                    "query": {
                                                        "query_string": {
                                                            "query": "MySql_Query_time:>%s" % gt_S
                                                        },
                                                    }
                                                }
                                            }
                                        ],
                                        "must_not": [
                                            {
                                                "terms": {
                                                    "MySql_IP": [
                                                        "10.10.70.202"
                                                    ]
                                                }
                                            }
                                        ]
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "size": 0
    }

    data_urlencode = json.dumps(data)
    try:
        Httpclient = httplib.HTTPConnection('127.0.0.1', '9200', timeout = 3)
        Httpclient.request('GET', url, data_urlencode)
        res = json.loads(Httpclient.getresponse().read())
        count = res['facets']['terms']['total']
        print count
    except Exception:
        print 0
    Httpclient.close()


def nginx_readserver_check():
    # 监控nginx后端服务器存活状态
    # 输出的值为后端宕机的个数，999可能是nginx宕机
    url = '/upstream-status?format=json&status=down'
    try:
        Httpclient = httplib.HTTPConnection('127.0.0.1', '80', timeout = 3)
        Httpclient.request('GET', url)
        res = eval(Httpclient.getresponse().read())
        count = res['servers']['total']
        print count
    except Exception:
        print 999
    Httpclient.close()


def monitorP():
    # 监控进程，异常可执行设定命令
    P_cmdline = sys.argv[3]
    cmd = "ps aux | grep '%s' | grep -Ev 'monitorP %s|grep' > /dev/null 2>&1" % (P_cmdline, P_cmdline)
    status = os.system(cmd)
    if status <> 0:
        if len(sys.argv) >= 5:
            status = os.system('%s > /dev/null 2>&1' % sys.argv[4])
    print status


# 监控日志系统积压队列
def log_queue():
    key = sys.argv[3]
    ip = sys.argv[4]
    port = sys.argv[5]
    info = \
    get_cmd_data("/data/apps/center_logs/redis-3.0.4/src/redis-cli -h %s -p %s LLEN %s 2>&1" % (ip, port, key)).split(
        '\n')[0]
    if re.match(r'\d+', info):
        print info
    else:
        print -999


def dockerDiscovery():
    # 自动发现k8s的docker
    zabbixDiscovery = {"data": []}
    Pods = []
    try:
        Httpclient = httplib.HTTPConnection('127.0.0.1', '4194', timeout = 3)
        Httpclient.request('GET', '/api/v2.0/spec?recursive=true&type=docker&count=1')
        specAll = json.loads(Httpclient.getresponse().read())
        for i in specAll:
            # k8s_POD.bbf70036_sport-services-rest-u1opf_default_ebd3ce3d-11c8-11e6-9437-5254008033ff_90c2145d
            # k8s_sport-services-rest.eda100f8_sport-services-rest-u1opf_default_ebd3ce3d-11c8-11e6-9437-5254008033ff_4c6d917f
            dockerName = specAll[i]["aliases"][0]
            # f7acec1e02c06624a9a4fbca523f819832c5ad6dc5d4ec484e7096e125e9afc0
            # bcfa1931e8be0e225d0a547d33391df45441e507c69b0dca2fa6139b8aa54b55
            dockerID = specAll[i]["aliases"][1]

            # 如果列表内没有对应的pod名字对应的元素，则新建
            try:
                Pods[dockerName.split('_')[2]]
            except:
                Pods = dict(Pods, **{dockerName.split('_')[2]: {}})

            # 将容器id与容器名对应起来
            if 'POD.' in dockerName.split('_')[1]:
                Pods[dockerName.split('_')[2]] = dict(Pods[dockerName.split('_')[2]], **{"{#NID}": dockerID})
            else:
                Pods[dockerName.split('_')[2]] = dict(Pods[dockerName.split('_')[2]], **{"{#CID}": dockerID})

        # 将数据组装成zabbix能看懂的格式
        for i in Pods:
            try:
                zabbixDiscovery["data"].append({"{#NAME}": i, "{#NID}": Pods[i]["{#NID}"], "{#CID}": Pods[i]["{#CID}"]})
            except:
                pass
    except:
        pass
    Httpclient.close()
    print json.dumps(zabbixDiscovery)


def dockerStatus():
    # 收集k8s的docker指定指标的状态
    dockerID = sys.argv[4]
    key = sys.argv[5]
    status = 0
    type = 'stats'
    if key == 'cpu':
        type = 'summary'

    try:
        Httpclient = httplib.HTTPConnection('127.0.0.1', '4194', timeout = 3)
        Httpclient.request('GET', '/api/v2.0/%s/%s?count=1&type=docker' % (type, dockerID))
        info = Httpclient.getresponse().read()
        if key == 'Read' or key == 'Write':
            info = re.search(r'"io_service_bytes":(.*),"io_serviced":', info).group(1)
            for j in re.compile(r'"%s":(\d+)' % key).findall(info):
                status += int(j)
        else:
            status = re.search(r'("%s":)(\d+)' % key, info).group(2)
    except:
        pass
    print status
    Httpclient.close()


def docker_API_Discovery():
    # 通过docker api自动发现docker容器
    zabbixDiscovery = {"data": []}
    # try:
    #     Httpclient = httplib.HTTPConnection('127.0.0.1', '2375', timeout=3)
    #     Httpclient.request('GET', '/containers/json')
    #     info = json.loads(Httpclient.getresponse().read())
    #     for i in info:
    #         # 将数据组装成zabbix能看懂的格式
    #         zabbixDiscovery["data"].append({"{#NAME}": i["Names"][0][1:], "{#CID}": i["Id"][:12]})
    # except:
    #     pass
    # Httpclient.close()

    info = get_cmd_data("docker ps | grep -v '^CONTAINER ' | awk '{print $1, $NF}'").split('\n')
    for i in info:
        zabbixDiscovery["data"].append({"{#NAME}": i.split(' ')[1], "{#CID}": i.split(' ')[0]})

    print json.dumps(zabbixDiscovery)


def docker_API_Status():
    # 通过docker api收集docker容器指定指标的状态
    dockerID = sys.argv[4]
    key = sys.argv[5]
    status = 0

    try:
        Httpclient = httplib.HTTPConnection('127.0.0.1', '2375', timeout = 3)
        Httpclient.request('GET', '/containers/%s/stats?stream=false' % dockerID)
        info = Httpclient.getresponse().read()
        if key == 'Read' or key == 'Write':
            info = re.search(r'"io_service_bytes_recursive":\[(.*)\],"io_serviced_recursive":', info).group(1)
            for j in re.compile(r'"op"\:"%s"\,"value"\:(\d+)' % key).findall(info):
                status += int(j)
        else:
            status = re.search(r'("%s":)(\d+)' % key, info).group(2)
    except:
        pass
    print status
    Httpclient.close()


def kafkaLag():
    # 收集kafka消息信息
    url = sys.argv[3]
    group = sys.argv[4]
    topic = sys.argv[5]
    type = sys.argv[6]
    count = 0
    info = json.loads(get_cmd_data("/usr/bin/curl -s '%s/group/%s'" % (url, group)))['offsets']
    for partition in info:
        if partition['topic'] == topic:
            if type == 'lag':
                count = partition['logSize'] - partition['offset'] + count
            else:
                count += partition[type]
    print count


def kafkaLastSeen():
    # 收集kafka消息最后被消费至今的时间差
    url = sys.argv[3]
    group = sys.argv[4]
    topic = sys.argv[5]
    owner = sys.argv[6]
    difftime = 0
    info = json.loads(get_cmd_data("/usr/bin/curl -s '%s/group/%s'" % (url, group)))['offsets']
    for partition in info:
        if partition['topic'] == topic and partition['owner'] == owner:
            if partition['logSize'] - partition['offset'] > 0:
                difftime = time.time() - float(partition['modified']) / 1000
                break
    print float(difftime)


def kafkaConsumerDiscovery():
    # kafka消费者自动发现
    import threading
    zabbixDiscovery = {"data": []}
    tp = []
    url = sys.argv[3]
    try:
        ifInfo = sys.argv[4]
    except:
        ifInfo = False
    # 处理函数
    def action(url, group):
        try:
            info = json.loads(get_cmd_data("/usr/bin/curl -s '%s/group/%s'" % (url, group)))['offsets']
            for partition in info:
                # 没有订阅则跳过
                if len(partition) <= 7:
                    continue
                if ifInfo:
                    zabbixDiscovery['data'].append(
                        {"{#URL}": url, "{#GROUP}": group, "{#TOPIC}": str(partition['topic']), "{#OWNER}": str(partition['owner'])})
                else:
                    if partition['partition'] == 0:
                        zabbixDiscovery['data'].append(
                            {"{#URL}": url, "{#GROUP}": group, "{#TOPIC}": str(partition['topic'])})
        except:
            pass
    # 创建线程池
    for group1 in json.loads(get_cmd_data("/usr/bin/curl -s '%s/group'" % url)):
        group = str(group1)
        t = threading.Thread(target=action, args=(url, group))
        t.setDaemon(True)
        tp.append(t)
    # 控制并发数量
    while tp:
        tp.pop().start()
        if threading.activeCount() > 10:
            while threading.activeCount() > 10:
                time.sleep(1)
        elif threading.activeCount() == 0:
            break
        else:
            pass
    print json.dumps(zabbixDiscovery)


def kafkaStatus():
    # kafka服务的健康状态
    url = sys.argv[3]
    group = sys.argv[4]
    info = json.loads(get_cmd_data("/usr/bin/curl -s '%s/group/%s'" % (url, group)))['brokers']
    count = len(info)
    print count


def code_log_check():
    # 代码日志监控
    data = sys.argv[3]
    Second = 300
    Time = time.time()
    S_index_name = time.strftime('code-%Y.%m.%d.%H', time.localtime(Time - 8 * 60 * 60 - Second))
    E_index_name = time.strftime('code-%Y.%m.%d.%H', time.localtime(Time - 8 * 60 * 60))
    url = '/' + S_index_name + ',' + E_index_name + '/_search'
    last_timestamp = int(Time * 1000) - int(Second) * 1000
    timestamp = int(Time * 1000)
    data = {
        "facets": {
            "terms": {
                "terms": {
                    "field": "tags",
                    "size": 20,
                    "order": "count",
                    "exclude": []
                },
                "facet_filter": {
                    "fquery": {
                        "query": {
                            "filtered": {
                                "query": {
                                    "bool": {
                                        "should": [
                                            {
                                                "query_string": {
                                                    "query": "*"
                                                }
                                            }
                                        ]
                                    }
                                },
                                "filter": {
                                    "bool": {
                                        "must": [
                                            {
                                                "range": {
                                                    "@timestamp": {
                                                        "from": last_timestamp,
                                                        "to": timestamp
                                                    }
                                                }
                                            },
                                            {
                                                "terms": {
                                                    "headers.deploy_env": [
                                                        "online"
                                                    ]
                                                }
                                            },
                                            {
                                                "terms": {
                                                    "message": [
                                                        data
                                                    ]
                                                }
                                            }
                                        ]
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        "size": 0
    }

    data_urlencode = json.dumps(data)
    try:
        Httpclient = httplib.HTTPConnection('127.0.0.1', '9200', timeout = 3)
        Httpclient.request('GET', url, data_urlencode)
        res = json.loads(Httpclient.getresponse().read())
        count = res['facets']['terms']['missing']
        print count
    except Exception:
        print 0
    Httpclient.close()


def DocketDStatus():
    # docker守护进程健康状态
    timeout = sys.argv[3]
    status = get_cmd_data("timeout %s docker ps -ql >/dev/null 2>&1;echo $?" % timeout)
    print status


all_zabbix = {'check_timezone': check_timezone, 'check_iptables': check_iptables, 'del_key': del_key, 'http_interface_check': http_interface_check, 'get_service': get_service, 'get_group': get_group, 'ip_discovery': ip_discovery, 'tcp_ss': tcp_ss, 'monitorP': monitorP, 'nginx_readserver_check': nginx_readserver_check, 'log_queue': log_queue, 'kafkaLag': kafkaLag, 'kafkaConsumerDiscovery': kafkaConsumerDiscovery, 'service_discovery': service_discovery, 'dockerDiscovery': dockerDiscovery, 'dockerStatus': dockerStatus, 'mysql_status': mysql_status, 'nginx_status': nginx_status, "crond_num": crond_num, 'http_check': http_check, 'disk_performance': disk_performance, 'disk_discovery': disk_discovery, 'echo': echo, 'mysql_slow_check': mysql_slow_check, 'tomcat_discovery': tomcat_discovery, 'tomcat_status': tomcat_status, 'redis_discovery': redis_discovery, 'redis_status': redis_status, 'redis_check': redis_check, 'ES_check': ES_check, 'mysql_discovery': mysql_discovery, 'jetty_discovery': jetty_discovery, 'mysql_schema': mysql_schema, "docker_API_Discovery": docker_API_Discovery, "docker_API_Status": docker_API_Status, "kafkaStatus": kafkaStatus, "code_log_check": code_log_check, "kafkaLastSeen": kafkaLastSeen, "DocketDStatus": DocketDStatus}
all_zabbix[options.zabbix]()
