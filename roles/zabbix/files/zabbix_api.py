#!/usr/bin/env python
from pyzabbix import ZabbixAPI
import os
import re

zapi = ZabbixAPI("http://zabbix3.yw.lifesense.com:10080")
zapi.login("caiwenhao", "cwh0802lx")
print("Connected to Zabbix API Version %s" % zapi.api_version())


def get_nginx_vhost(file,remove_list=["/"]):
    f = open(file)
    nginx_content = f.read()
    f.close()
    p = re.compile(r'location (/.*) {')
    url_path_list =  p.findall(nginx_content)
    url_path_list = [i for i in url_path_list if i not in remove_list]
    p = re.compile(r'server_name (.*)')
    host =  p.findall(nginx_content)[0].split()[0]
    nginx_info = {}
    nginx_info["host"] = host
    nginx_info["url_paths"] = url_path_list
    return nginx_info

def create_scenario(name,url,required):
    scenario={}
    scenario["name"] = name
    scenario["url"] = url
    scenario["status_codes"] = 200
    scenario["no"] = 1
    scenario["required"] = required
    return  [scenario]

def create_httptest(nginx_info_list,url_p="/echo?requestId=88",required='"code":200'):
    httptest_list = []
    for nginx_info in nginx_info_list:
        for path in nginx_info["url_paths"]:
            httptest={}
            httptest["name"] = nginx_info["host"]+ path
            url = "http://"+nginx_info["host"]+path + url_p
            httptest["steps"] = create_scenario(path,url,required)
            httptest_list.append(httptest)
    return httptest_list

def create_httptest_trigger(templatename,httpname):
    trigger = {}
    trigger["description"] = "%s down" % httpname
    trigger["expression"] = "{%s:web.test.fail[%s].count(#3,1,ge)}>2" %(templatename,httpname)
    trigger["priority"] = 4
    return trigger

def create_screenitems(graph_list,columns=2,width=500,height=100):
    screenitems = []
    x = 0
    y = 0
    if len(graph_list) % columns == 0:
        vsize = len(graph_list) / columns
    else:
        vsize = (len(graph_list) / columns) + 1
    for graph in graph_list:
        screen = {}
        screen["resourcetype"] = graph["graphtype"]
        screen["resourceid"] = graph["graphid"]
        screen["rowspan"] = 1
        screen["colspan"] = 1
        screen["x"] = x
        screen["y"] = y
        screen["width"] = width
        screen["height"] = height
        screenitems.append(screen)
        x += 1
        if x == columns:
            x = 0
            y += 1
    return columns,vsize,screenitems

def build_httptest():
    templateid = ""
    for h in  zapi.template.get(output="extend",filter={"host":["web-monitor"]}):
        templateid = h["templateid"]
    file = "/data/apps/nginx/conf/vhost/sports.lifesense.com.conf"
    remove_list=["/","/wxapi","/devicedataservice","/devicegatewayservice","/lxyd_admin"]
    nginx_info = get_nginx_vhost(file,remove_list)
    for http in create_httptest([nginx_info]):
        print zapi.httptest.create(name=http["name"],hostid=templateid,steps=http["steps"])
        print zapi.trigger.create(create_httptest_trigger("web-monitor",name=http["name"]))

def build_screen(group,group_graph):
    common_graph = ["CPU load", "Memory usage", "Network traffic on eth0", "disk vdb ms"]
    if group == "mysql":
        common_graph.remove("Network traffic on eth0")
        common_graph.append("Network traffic on eth1")
    group_graph = group_graph + common_graph
    group_id = zapi.hostgroup.get(filter={"name":[group]},output=["groupid"])[0]["groupid"]
    graph_list = zapi.graph.get(groupids=group_id,output=["graphid","name","graphtype"])
    graphs = []
    for graph in group_graph:
        graphs.extend([i for i in graph_list if re.compile(graph).match(i["name"])])
    columns, vsize, screenitems = create_screenitems(graphs)
    return zapi.screen.create(name=group,hsize=columns,vsize=vsize,screenitems=screenitems)

mysql_graph = ["L1 MySQL.3306 QPS","L1 MySQL.3306 SlowQuery","L1 MySQL.3306 QPS","L1 MySQL.3306 TPS"]
#print build_screen("mysql",mysql_graph)

redis_graph = [r'L1 Redis.\d+ Memory',r'L1 Redis.\d+ Connection',r'L2 Redis.\d+ Commands',r'L2 Redis.\d+ Keyspace']
#print build_screen("redis",redis_graph)

nginx_graph = ['nginx connection',"nginx requests"]
#print build_screen("nginx",nginx_graph)

zookeeper_graph = ["zk_queue","zk_latency"]
print build_screen("zookeeper",zookeeper_graph)



