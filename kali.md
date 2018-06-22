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
