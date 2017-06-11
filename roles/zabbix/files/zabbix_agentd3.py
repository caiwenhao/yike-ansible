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
import shelve
import urllib
import hashlib


try:
    from kazoo.client import KazooClient
except:
    pass

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

def zbx_fail():
    print "ZBX_NOTSUPPORTED"
    sys.exit(2)

def use_cache(file):
    if not os.access(file,os.F_OK):
        return False
    now = int(time.time())
    file_modified = int(os.stat(file).st_mtime)
    if now - file_modified < 59:
       return True
    else:
       return False

# ip发现规则
def ip_discovery():
    ip_list = []
    all_ip = get_cmd_data("/sbin/ip a|awk '/inet / {print $NF\"_\"$2}'|awk -F/ '{print $1}'").split()
    all_ip = list(set(all_ip))
    for ip in all_ip:
        data = {}
        data['{#IP}'] = ip.split('_')[1]
        data['{#INT}'] = ip.split('_')[0]
        ip_list.append(data)
    result = {'data': ip_list}
    print str(result).replace("'", '"').replace(" ", "")


# mysql发现规则
def mysql_discovery():
    mysql_list = []
    mysql_info = get_cmd_data("/bin/netstat -ntlp|/bin/grep mysqld")
    re_result = re.compile(r'(0.0.0.0:|:::)(\d+)')
    match = re_result.findall(mysql_info)
    for port in match:
        data = {}
        data['{#PORT}'] = port[1]
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
        try:
            if sorted(old_diff_dict.keys())[-1] not in new_diff_dict.keys():
                print sum([int(i) for i in new_diff_dict.values()])
            else:
                print sum([int(i) for i in new_diff_dict.values()]) - int(
                    old_diff_dict[sorted(old_diff_dict.keys())[-1]])
        except:
            print 0
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
        result = get_cmd_data(
            '/usr/local/mysql/bin/mysql --login-path=zabbix --socket=/tmp/mysql%s.sock -e "show slave status \G"|/bin/grep %s | head -1 | awk -F ": " "{print \$NF}" ' % (
            port, sys.argv[3]))
        if result == "":
            print 0
        else:
            print result
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
            print 0


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


# redis 状态
def redis_status():

    def get_redis_ip():
        redis_p = get_cmd_data(
            "/bin/netstat -ntlp|/bin/grep redis-server | /bin/egrep '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:%s '" % port)
        re_result = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\:%s' % port)
        match = re_result.findall(redis_p)[0]
        if re.match(r'(0.0.0.0|127.0.0.1)', match):
            return 'localhost'
        else:
            return match

    port = sys.argv[3]
    key = sys.argv[4]
    redis_cachefile = "/tmp/zabbix_redis_%s.cache" %port
    if use_cache(redis_cachefile):
        redis_info = shelve.open(redis_cachefile)['info']
    else:
        try:
            ip = get_redis_ip()
            shelf = shelve.open(redis_cachefile)
            cmd = "/usr/local/redis/bin/redis-cli -h %s -p %s info" % (ip, port)
            cmd_result = get_cmd_data(cmd)
            pattern = re.compile(r'(.+):(.+)\r')
            redis_info = dict(pattern.findall(cmd_result))
            redis_info["PING"] = get_cmd_data("/usr/local/redis/bin/redis-cli -h %s -p %s PING 'ok'" % (ip, port))
            pattern_db0 = re.compile(r'(\w+)=(\d+)')
            db0_info = dict(pattern_db0.findall(cmd_result))
            redis_info = dict(redis_info,**db0_info)
            shelf["info"] = redis_info
            shelf.close()
        except:
            zbx_fail()

    try:
        print redis_info[key]
    except:
        if key in ["keys", "expires", "avg_ttl"]:
            print 0
        else:
            zbx_fail()

# nginx状态
def nginx_status():

    nginx_cachefile = "/tmp/zabbix_nginx.cache"
    if use_cache(nginx_cachefile):
        nginx_info = shelve.open(nginx_cachefile)['info']
    else:
        try:
            nginx_status_info = get_cmd_data("/usr/bin/curl -s 'http://127.0.0.1/nginx-status'")
            re_result = re.compile(
                r'Active connections: (?P<connections>\d+) \nserver accepts handled requests request_time\n (?P<accepts>\d+) (?P<handled>\d+) (?P<requests>\d+) (?P<request_time>\d+)\nReading: (?P<Reading>\d+) Writing: (?P<Writing>\d+) Waiting: (?P<Waiting>\d+)',
                re.M)
            match = re_result.match(nginx_status_info)
            nginx_info = match.groupdict()
            nginx_info["version"] = get_cmd_data('/data/apps/nginx/sbin/nginx -v 2>&1').split()[2]
            shelf = shelve.open(nginx_cachefile)
            shelf["info"] = nginx_info
            shelf.close()
        except:
            zbx_fail()
    try:
        print nginx_info[sys.argv[3]]
    except:
        zbx_fail()

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
    disk_cachefile = "/tmp/zabbix_disk.cache"
    if use_cache(disk_cachefile):
        disk_info = shelve.open(disk_cachefile)['stats']
    else:
        shelf = shelve.open(disk_cachefile)
        p = subprocess.Popen("cat /proc/diskstats |/bin/grep -w %s" % sys.argv[3], shell=True, stdout=subprocess.PIPE)
        disk_info = p.communicate()[0].split()
        shelf['stats'] = disk_info
        shelf.close()
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
    else:
        zbx_fail()

# zookeeper
def zookeeper_stauts():
    zookeeper_cachefile = "/tmp/zabbix_zookeeper.cache"
    if use_cache(zookeeper_cachefile):
        zookeeper_info = shelve.open(zookeeper_cachefile)['info']
    else:
        try:
           shelf = shelve.open(zookeeper_cachefile)
           ruok = get_cmd_data("echo ruok | nc 127.0.0.1 2181")
           info = get_cmd_data("echo mntr | nc 127.0.0.1 2181")
           pattern = re.compile(r'(.+)\t(.+)')
           zookeeper_info = dict(pattern.findall(info))
           zookeeper_info["ruok"] = ruok
           shelf["info"] = zookeeper_info
           shelf.close()
        except:
            zbx_fail()
    try:
        print zookeeper_info[sys.argv[3]]
    except:
        zbx_fail()


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
            try:
                if dockerName.split('_')[3] != sys.argv[3]:
                    # 过滤不同命名空间的pod
                    continue
            except:
                pass
            # f7acec1e02c06624a9a4fbca523f819832c5ad6dc5d4ec484e7096e125e9afc0
            # bcfa1931e8be0e225d0a547d33391df45441e507c69b0dca2fa6139b8aa54b55
            dockerID = specAll[i]["aliases"][1]

            # 如果列表内没有对应的pod名字对应的元素，则新建
            try:
                Pods[dockerName.split('_')[2]]
            except:
                Pods = dict(Pods, **{dockerName.split('_')[2]: {}})

            # 将容器id与容器名对应起来
            if 'POD' in dockerName.split('_')[1]:
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
    if not os.path.isdir('/tmp/zabbix_docker/'):
        os.makedirs('/tmp/zabbix_docker/')
    cacheFile = '/tmp/zabbix_docker/%s' % dockerID
    try:
        if type == 'stats' and use_cache(cacheFile):
            info = open(cacheFile, 'r').read()
        else:
            Httpclient = httplib.HTTPConnection('127.0.0.1', '4194', timeout = 3)
            Httpclient.request('GET', '/api/v2.0/%s/%s?count=1&type=docker' % (type, dockerID))
            info = Httpclient.getresponse().read()
            Httpclient.close()
            if type == 'stats':
                open(cacheFile, 'w').write(info)
        if key == 'Read' or key == 'Write':
            info = re.search(r'"io_service_bytes":(.*),"io_serviced":', info).group(1)
            for j in re.compile(r'"%s":(\d+)' % key).findall(info):
                status += int(j)
        else:
            status = re.search(r'("%s":)(\d+)' % key, info).group(2)
        if sys.argv[6] == 'online':
            try:
                body = urllib.urlencode({"name":sys.argv[3],"type":key,"lastvalue":status,"acl":"#c12&lW9$epHyR&tCTG1h67O3^@Soe"})
                get_cmd_data("/usr/bin/curl -s 'http://botlocal.lifesense.com:8000/api/pushDockerStatus' -d '%s'" % (body))
            except:
                pass
    except:
        pass
    print status



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


def monitorP():
    # 监控进程，异常可执行设定命令
    P_cmdline = sys.argv[3]
    cmd = "ps aux | grep '%s' | grep -Ev 'monitorP %s|grep' > /dev/null 2>&1" % (P_cmdline, P_cmdline)
    status = os.system(cmd)
    if status <> 0:
        if len(sys.argv) >= 5:
            status = os.system('%s > /dev/null 2>&1' % sys.argv[4])
    print status


def kafkaLag():
    # 收集kafka消息信息
    url = sys.argv[3]
    group = sys.argv[4]
    topic = sys.argv[5]
    type = sys.argv[6]
    count = 0
    if not os.path.isdir('/tmp/zabbix_kafka/'):
        os.makedirs('/tmp/zabbix_kafka/')
    cacheFile = '/tmp/zabbix_kafka/%s' % hashlib.md5('%s|%s' % (url, group)).hexdigest()
    if use_cache(cacheFile):
        info = json.load(open(cacheFile, 'r'))
    else:
        info = json.loads(get_cmd_data("/usr/bin/curl -s '%s/group/%s'" % (url, group)))['offsets']
        json.dump(info, open(cacheFile, 'w'))
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
    if not os.path.isdir('/tmp/zabbix_kafka/'):
        os.makedirs('/tmp/zabbix_kafka/')
    cacheFile = '/tmp/zabbix_kafka/%s' % hashlib.md5('%s|%s' % (url, group)).hexdigest()
    if use_cache(cacheFile):
        info = json.load(open(cacheFile, 'r'))
    else:
        info = json.loads(get_cmd_data("/usr/bin/curl -s '%s/group/%s'" % (url, group)))['offsets']
        json.dump(info, open(cacheFile, 'w'))
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
    if not os.path.isdir('/tmp/zabbix_kafka/'):
        os.makedirs('/tmp/zabbix_kafka/')
    # 处理函数
    def action(url, group):
        try:
            cacheFile = '/tmp/zabbix_kafka/%s' % hashlib.md5('%s|%s' % (url, group)).hexdigest()
            if use_cache(cacheFile):
                info = json.load(open(cacheFile, 'r'))
            else:
                info = json.loads(get_cmd_data("/usr/bin/curl -s '%s/group/%s'" % (url, group)))['offsets']
                json.dump(info, open(cacheFile, 'w'))
            for partition in info:
                # 没有订阅则跳过
                if len(partition) <= 7:
                    continue
                if ifInfo :
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
        Httpclient = httplib.HTTPConnection('10.10.146.22', '9200', timeout = 3)
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


def ES_cluster(host = '127.0.0.1', port = '9200', url = '/_cluster/health'):
    try:
        Httpclient = httplib.HTTPConnection(host, port, timeout = 3)
        Httpclient.request('GET', url)
        res = Httpclient.getresponse()
        print json.loads(res.read())[sys.argv[3]]
    except Exception:
        print "ZBX_NOTSUPPORTED"
    Httpclient.close()


def ES_status(host = '127.0.0.1', port = '9200', url = '/'):
    try:
        Httpclient = httplib.HTTPConnection(host, port, timeout = 3)
        Httpclient.request('GET', url)
        res = Httpclient.getresponse()
        print json.loads(res.read())['status']
    except Exception:
        print "ZBX_NOTSUPPORTED"
    Httpclient.close()


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


def code_task_Discovery():
    # 业务代码定时任务自动发现
    zabbixDiscovery = {"data": []}
    zk = KazooClient(timeout=2, read_only=True)
    zk.start(2)
    for svc in zk.get_children('/dis_tasks/v2/'):
        for task in zk.get_children('/dis_tasks/v2/%s/' % svc):
            if task != 'nodes':
                zabbixDiscovery['data'].append({"{#SVC}":svc, "{#TASK}":task})
    zk.stop()
    zk.close()
    print json.dumps(zabbixDiscovery)


def code_task():
    # 业务代码定时任务监控，0正常，1故障，2未知异常
    svc = sys.argv[3]
    task = sys.argv[4]
    type = sys.argv[5]
    try:
        zk = KazooClient(timeout=2, read_only=True)
        zk.start(2)
        status = 1
        info = json.loads(re.sub('.*\{','{',zk.get('/dis_tasks/v2/%s/%s/' % (svc, task))[0]))
        if type == 'nextFireTime':
            if time.time() < time.mktime(time.strptime(info[type], '%Y-%m-%d %H:%M:%S')) + 3600:
                status = 0
        else:
            if info[type] in zk.get_children('/dis_tasks/v2/%s/nodes/' % svc):
                status = 0
        zk.stop()
        zk.close()
    except:
        status = 2
    print status


all_zabbix = {'ip_discovery': ip_discovery, 'mysql_discovery': mysql_discovery, 'mysql_status': mysql_status, 'redis_discovery': redis_discovery, 'redis_status': redis_status, 'nginx_status': nginx_status, 'disk_discovery': disk_discovery, 'disk_performance': disk_performance, 'zookeeper_stauts': zookeeper_stauts, 'dockerDiscovery': dockerDiscovery, 'dockerStatus': dockerStatus, 'monitorP': monitorP, 'kafkaLag': kafkaLag, 'kafkaConsumerDiscovery': kafkaConsumerDiscovery, 'tcp_ss': tcp_ss, 'http_interface_check': http_interface_check, 'ES_cluster': ES_cluster, "docker_API_Discovery": docker_API_Discovery, "docker_API_Status": docker_API_Status, "kafkaStatus": kafkaStatus, "code_log_check": code_log_check, "kafkaLastSeen": kafkaLastSeen, "DocketDStatus": DocketDStatus,"http_check":http_check,"mysql_slow_check":mysql_slow_check,"ES_status":ES_status, "code_task_Discovery":code_task_Discovery, "code_task":code_task}
all_zabbix[options.zabbix]()
