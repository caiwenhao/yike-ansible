#乐心ansible配置
##等待完善的配置
```
sed -i "s#PasswordAuthentication yes#PasswordAuthentication no#g"  /etc/ssh/sshd_config
#PermitRootLogin no   #root用户黑客都知道，禁止它远程登录
#ssh普通用户(非root用户)的密钥登录
#http://blog.csdn.net/jom_ch/article/details/9285683
```
> mount 参数优化


##常用命令
```
ansible-playbook site.yml --tags="ntp"
git fetch --all
git reset --hard origin/master
ansible-playbook -i Inventory/yw yw.yml -v
```

##语法
```
#实现大文件下载
get_url: url=http://10.10.10.67:8000/ceshi?ip={{ ansible_hostname }} dest=/etc/ansible/facts.d/vhost.fact mode=0777
不支持中文
```
