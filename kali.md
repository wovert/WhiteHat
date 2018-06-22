# kali

## Setup kali

[Kali官网](http:/kali.org)

虚拟机 （Debian 64，20G）

## 添加 Kali 更新源

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

## 启动 postgresql 服务

``` shell
# service postgresql start
# service metasploit start

在终端启动 metasploit 框架

# msfconsole

msf >
```

## 代理简介
