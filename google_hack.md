# GOOGLE Hack 搜索技术

## 搜索也是一门艺术

> 在我们平时使用搜索引擎的过程中，通常是将需要搜索的关键字输入搜索引擎，然后就开始了漫长的信息提取过程。其实Google对于搜索的关键字提供了多种语法，合理使用这些语法，将使我们得到的搜索结果更加精确。当然，Google允许用户使用这些语法的目的是为了获得更加精确的结果，但是黑客却可以利用这些语法构造出特殊的关键字，使搜索的结果中绝大部分都是存在漏洞的网站。

## 看看Google的部分语法

- `intitle`：搜索**网页标题**中包含有特定字符的网页。例如输入`intitle: cbi`，这样网页标题中带有cbi的网页都会被搜索出来。

- `inurl`：搜索包含有特定字符的**URL**。例如输入`inurl:cbi`，则可以找到带有cbi字符的URL。

- `intext`:搜索**网页正文内容**中的指定字符，例如输入`intext:cbi`。这个语法类似我们平时在某些网站中使用的**文章内容搜索**功能。

- `filetype`:搜索指定**文件类型**的。例如输入`filetype:cbi`，将返回所有以cbi结尾的文件URL。

- `site`：找到与指定**网站地址URL所有页面**。例如输入`Site：domain.com`。所有和这个网站有联系的URL都会被显示。

## 语法在Google Hack中的作用

黑客是如何使用这些语法进行**Google Hack**的，这些语法在入侵的过程中又会起到怎样的作用呢？

### intitle

> `intitle`语法通常被用来搜索**网站的后台、特殊页面和文件**，通过在Google中搜索`intitle:登录`、`intitle:管理`就可以找到很多网站的后台登录页面。此外，`intitle`语法还可以被用在**搜索文件**上，例如搜索`intitle:"indexof"etc/shadow`就可以找到Linux中因为配置不合理而泄露出来的用户密码文件。

### inurl

> Google Hack中，`inurl`发挥的作用的最大，主要可以分为以下两个方面:寻找网站**后台登录地址**，搜索特殊URL。

寻找网站后台登录地址：和`intitle`不同的是，`inurl`可以指定**URL中的关键字**，我们都知道网站的后台URL都是类似`login.asp、admin.asp`为结尾的，那么我们只要以`inurl:login.asp`、`inurl:admin.asp`为关键字进行搜索，同样可以找到很多网站的后台。此外，我们还可以搜索一下**网站的数据库地址**，以`inurl:data`、`inurl:db`为关键字进行搜索即可。

### 1. 寻找网站的后台登录页面

**inurl**: 搜索特殊`URL：通过inurl语法搜索特殊URL`，我们可以找到很多网站程序的漏洞，例如最早**IIS中的Uncode目录遍历漏洞**，我们可以构造`inurl:／winnt／system32／cmd exe?／c+dir`这样的关键字进行搜索，不过目前要搜索到存在这种古董漏洞的网站是比较困难的。再比如前段日子很火的**上传漏洞**，我们使用`inurl:upload.asp`或`inurl:upload_soft.asp`即可找到很多上传页面，此时再用工具进行**木马上传**就可以完成**入侵**。

**intext**: `intext`的作用是搜索**网页中的指定字符**，这貌似在Google Hack中没有什么作用，不过在以`intext:to parent directory`为关键字进行搜索后，我们会很惊奇的发现，无数网站的目录暴露在我们眼前。我们可以在其中随意切换目录，浏览文件，就像拥有了一个简单的`Webshell`。形成这种现象的原因是由于**IIS的配置疏忽**。同样，中文IIS配置疏忽也可能出现类似的漏洞，我们用`intext:转到父目录`就可以找到很多有漏洞的中文网站。

### 2. 随意浏览网站中的文件

**filetype**: `filetype`的作用是**搜索指定文件**。假如我们要搜索网站的数据库文件，那么可以以`filetype:mdb`为关键字进行搜索，很快就可以下载到不少网站的数据库文件。当然，`filetype`语法的作用不仅于此，在和其他语法配合使用的时候更能显示出其强大作用。

**site**: 黑客使用`site`，通常都是做**入侵前的信息刺探**。`site`语法可以显示所有和目标网站有联系的页面，从中或多或少存在一些关于**目标网站的资料**，这对于黑客而言就是**入侵的突破口**，是关于目标网站的一份详尽的报告。

**语法组合，威力加倍**: 虽然上文中介绍的这几个语法能各自完成入侵中的一些步骤，但是只使用一个语法进行入侵，其效率是很低下的。Google Hack的威力在于能将多个语法组合起来，这样就可以快速地找到我们需要的东西。下面我们来模拟黑客是如何使用Google语法组合来入侵一个网站的。

#### 信息刺探

> 黑客想入侵一个网站，通常第一步都是对目标网站进行信息刺探。这时可以使用`site:目标网站`来获取相关网页，从中提取有用的资料。

### 3.搜索相关页面

#### 下载网站的数据库

搜索`site:目标网站 filetype:mdb`就可以寻找目标**网站的数据库**，其中的`site`语法限定**搜索范围**，`filetype`决定**搜索目标**。用这种方法有一个缺点，就是下载到数据库的成功率较低。在这里我们还可以采用另一种语法组合，前提是目标网站存在**IIS配置缺陷**，即可以**随意浏览站点文件夹**，我们搜索`Site:目标网站 intext:to parent directory`来确定其是否存在此漏洞。在确定漏洞存在后，可以使用`Site:目标网站 intext:to parent directory+intext.mdb`进行数据库的搜索。

### 4.找到网站数据库

#### 登录后台管理

下载到数据库后，我们就可以从中找到网站的**管理员帐户和密码**，并登录网站的后台。对于网站后台的查找，可以使用语法组合`site:目标网站 intitle:管理`或者`site:目标网站 inurl:login.asp`进行搜索，当然我们可以在这里进行联想，以不同的字符进行搜索，这样就有很大的概率可以找到网站的后台管理地址。接下去黑客就可以在**后台上传Webshll**，进一步**提升权限**。

#### 利用其他漏洞

如果下载数据库不成功，我们还可以尝试其他的入侵方法。例如寻找**上传漏洞**，搜索`site:目标网站 inurl:upload.asp`。此外，我们还可以根据一些**程序漏洞的特征**，定制出Google Hack的语句。

Google Hack可以灵活地组合法语，合理的语法组合将使入侵显得易如反掌，再加入自己的搜索字符，Google完全可以成为你独一无二的黑客工具。

#### 5. 合理设置网站 防范Google Hack

Google Hack貌似无孔不入，实则无非是利用了我们配置网站时的疏忽。例如上文中搜索`intext:to parent directory`即可找到很多可以浏览目录文件的网站，这都是由于没有设置好网站权限所造成的。在**IIS中，设置用户访问网站权限时有一个选项**，叫做**目录浏览**，如果你不小心**选中了该项**，那么其结果就如上文所述，可以让黑客肆意浏览你网站中的文件。

这种漏洞的防范方法十分简单，在**设置用户权限时不要选中`目录浏览`选项即可**。

#### 6.不要选中该项

编写`robots.txt`文件

`robot.txt`是专门针对搜索引擎机器人robot编写的一个纯文本文件。我们可以在这个文件中说明网站中不想被robot访问的部分，这样，我们网站的部分或全部内容就可以不被搜索引擎收录了，或者让搜索引擎只收录指定的内容。因此我们可以利用`robots.txt`让Google的机器人访问不了我们网站上的重要文件，Google Hack的威胁也就不存在了。

编写的robots.txt文件内容如下：

```
User-agent: *
Disallow: /data/
Disallow: /db/
```

其中`Disallow`参数后面的是**禁止robot收录部分的路径**，例如我们要让robot禁止收录网站目录下的`data`文件夹，只需要在Disallow参数后面加上`/data/`即可。如果想增加其他目录，只需按此格式继续添加。文件编写完成后将其上传到网站的根目录，就可以让网站远离Google Hack了。

## 站内搜索

站内搜索地址为：`http://www.google.com/custom?domains=(这里写我们要搜索的站点，比如domain.com)`

进去可以选择www和feelids.com， 当然再选我们要的站内搜索哦！

黑客专用信息和资料搜索地址为： `http://www.google.com/custom?hl=xx-hacker`

这里是google关键字的用法，要设置它为中文，则是`http://www.google.com/custom?hl=zh-CN` 英文则是`http://www.google.com/custom?hl=en`

### 常用的google关键字

- foo1 foo2 (也就是关联，比如搜索xx公司 xx美女) 
- operator:foo
- allinurl:foo 搜索xx网站的所有相关连接。（踩点必备）
- links:foo 不要说就知道是它的相关链接
- allintilte:foo.com

我们可以辅助"-" "+"来调整搜索的精确程度

直接搜索密码：(引号表示为精确搜索)

当然我们可以再延伸到上面的结果里进行二次搜索 

"index of" htpasswd / passwd

filetype:xls username password email

"ws_ftp.log"

"config.php"

allinurl:admin mdb

service filetype:pwd ....或者某个比如pcanywhere的密码后缀cif等

越来越有意思了，再来点更敏感信息

"robots.txt" "Disallow:" filetype:txt

inurl:_vti_cnf (FrontPage的关键索引啦，扫描器的CGI库一般都有地)

allinurl: /msadc/Samples/selector/showcode.asp

/../../../passwd

/examples/jsp/snp/snoop.jsp

phpsysinfo

intitle:index of /admin

intitle:"documetation"

inurl: 5800(vnc的端口)或者desktop port等多个关键字检索 

webmin port 10000

inurl:/admin/login.asp

intext:Powered by GBook365

intitle:"php shell*" "Enable stderr" filetype:php 直接搜索到phpwebshell 

foo.org filetype:inc

ipsec filetype:conf

intilte:"error occurred" ODBC request WHERE (select|insert) 说白了就是说，
可以直接试着查查数据库检索，针对目前流行的sql注射，会发达哦

intitle:"php shell*" "Enable stderr" filetype:php

"Dumping data for table" username password

intitle:"Error using Hypernews"

"Server Software"

intitle:"HTTP_USER_AGENT=Googlebot"

"HTTP_USER_ANGET=Googlebot" THS ADMIN

filetype:.doc site:.mil classified 直接搜索军方相关word

检查多个关键字：

- intitle:config confixx login password
- "mydomain.com" nessus report
- "report generated by"
- "ipconfig"
- "winipconfig"

google缓存利用（hoho，最有影响力的东西）推荐大家搜索时候多"选搜索所有网站"
特别推荐：administrator users 等相关的东西，比如名字，生日等……最惨也可以拿来做字典

`cache:foo.com`

可以查阅类似结果

先找找网站的管理后台地址：

```
site:xxxx.com intext:管理
site:xxxx.com inurl:login
site:xxxx.com intitle:管理
site:a2.xxxx.com inurl:file
site:a3.xxxx.com inurl:load
site:a2.xxxx.com intext:ftp://*:*
site:a2.xxxx.com filetype:asp
site:xxxx.com //得到N个二级域名
site:xxxx.com intext:*@xxxx.com //得到N个邮件地址，还有邮箱的主人的名字什么的
site:xxxx.com intext:电话 //N个电话
intitle:"index of" etc
intitle:"Index of" .sh_history
intitle:"Index of" .bash_history
intitle:"index of" passwd
intitle:"index of" people.lst
intitle:"index of" pwd.db
intitle:"index of" etc/shadow
intitle:"index of" spwd
intitle:"index of" master.passwd
intitle:"index of" htpasswd
"# -FrontPage-" inurl:service.pwd

allinurl:bbs data
filetype:mdb inurl:database
filetype:inc conn
inurl:data filetype:mdb
intitle:"index of" data
```

### 一些技巧集合

- "http://*:*@www" domainname 找一些ISP站点，可以查对方ip的虚拟主机
- auth_user_file.txt 不实用了，太老了
- The Master List 寻找邮件列表的
- intitle:"welcome.to.squeezebox" 一种特殊的管理系统，默认开放端口90
- passlist.txt (a better way) 字典
- "A syntax error has occurred" filetype:ihtml
- ext:php program_listing intitle:MythWeb.Program.Listing
- intitle:index.of abyss.conf
- ext:nbe nbe
- intitle:"SWW link" "Please wait....."
- intitle:"Freifunk.Net - Status" -site:commando.de
- intitle:"WorldClient" intext:"? (2003|2004) Alt-N Technologies."
- intitle:open-xchange inurl:login.pl
- intitle:"site administration: please log in" "site designed by emarketsouth"
- ORA-00921: unexpected end of SQL command
- intitle:"YALA: Yet Another LDAP Administrator"
- welcome.to phpqladmin "Please login" -cvsweb
- intitle:"SWW link" "Please wait....."
- inurl:"port_255" -htm
- intitle:"WorldClient" intext:"? (2003|2004) Alt-N Technologies." 


这些是新的一些漏洞技巧，在0days公告公布

`ext:php program_listing intitle:MythWeb.Program.Listing `

`inurl:preferences.ini "[emule]"`

`intitle:"Index of /CFIDE/" administrator`

`"access denied for user" "using password"`

`ext:php intext:"Powered by phpNewMan Version" 可以看到：path/to/news/browse.php?clang=../../../../../../file/i/want`

`inurl:"/becommunity/community/index.php?pageurl="`

`intitle:"ASP FileMan" Resend -site:iisworks.com`

`"Enter ip" inurl:"php-ping.php"`

`ext:conf inurl:rsyncd.conf -cvs -man`

`intitle: private, protected, secret, secure, winnt`

`intitle:"DocuShare" inurl:"docushare/dsweb/" -faq -gov -edu`

`"#mysql dump" filetype:sql`

`"allow_call_time_pass_reference" "PATH_INFO"`

`"Certificate Practice Statement" inurl:(PDF | DOC)`

`LeapFTP intitle:"index.of./" sites.ini modified`

`master.passwd`

`mysql history files`

`NickServ registration passwords`

`passlist`

`passlist.txt (a better way)`

`passwd`

passwd / etc (reliable) 
people.lst 
psyBNC config files 
pwd.db 
signin filetype:url 
spwd.db / passwd 
trillian.ini 
wwwboard WebAdmin inurl:passwd.txt wwwboard|webadmin 

"# -FrontPage-" ext:pwd inurl:(service | authors | administrators | users) "# -FrontPage-" 

inurl:service.pwd 
"AutoCreate=TRUE password=*" 
"http://*:*@www" domainname 
"index of/" "ws_ftp.ini" "parent directory" 
"liveice configuration file" ext:cfg -site:sourceforge.net 
"powered by ducalendar" -site:duware.com 
"Powered by Duclassified" -site:duware.com 
"Powered by Duclassified" -site:duware.com "DUware All Rights reserved" 
"powered by duclassmate" -site:duware.com 
"Powered by Dudirectory" -site:duware.com 
"powered by dudownload" -site:duware.com 
"Powered By Elite Forum Version *.*" 
"Powered by Link Department" 
"sets mode: +k" 
"Powered by DUpaypal" -site:duware.com 
allinurl: admin mdb 
auth_user_file.txt 
config.php 
eggdrop filetype:user user 
etc (index.of) 
ext:ini eudora.ini 
ext:ini Version=... password 
ext:txt inurl:unattend.txt 

filetype:bak inurl:"htaccess|passwd|shadow|htusers" 

filetype:cfg mrtg "target[*]" -sample -cvs -example 

filetype:cfm "cfapplication name" password 

filetype:conf oekakibbs 
filetype:conf sc_serv.conf 

filetype:conf slapd.conf 

filetype:config config intext:appSettings "User ID" 

filetype:dat "password.dat" 

filetype:dat wand.dat 

filetype:inc dbconn 

filetype:inc intext:mysql_connect 
filetype:inc mysql_connect OR mysql_pconnect 

filetype:inf sysprep 

filetype:ini inurl:"serv-u.ini" 
filetype:ini inurl:flashFXP.ini 
filetype:ini ServUDaemon 
filetype:ini wcx_ftp 
filetype:ini ws_ftp pwd 

filetype:ldb admin 

filetype:log "See `ipsec copyright" 

filetype:log inurl:"password.log" 

filetype:mdb inurl:users.mdb 

filetype:mdb wwforum 

filetype:netrc password 

filetype:pass pass intext:userid 

filetype:pem intext:private 

filetype:properties inurl:db intext:password 

filetype:pwd service 
filetype:pwl pwl 

filetype:reg reg +intext:"defaultusername" +intext:"defaultpassword" 
filetype:reg reg HKEY_CURRENT_USER SSHHOSTKEYS 
filetype:sql ("values * MD" | "values * password" | "values * encrypt") 
filetype:sql ("passwd values" | "password values" | "pass values" ) 
filetype:sql +"IDENTIFIED BY" -cvs 
filetype:sql password 

filetype:url +inurl:"ftp://" +inurl:";@" 

filetype:xls username password email 

htpasswd 
htpasswd / htgroup 
htpasswd / htpasswd.bak 

intext:"enable secret $" 
intext:"powered by Web Wiz Journal" 

intitle:"index of" intext:connect.inc 
intitle:"index of" intext:globals.inc 
intitle:"Index of" passwords modified 

intitle:dupics inurl:(add.asp | default.asp | view.asp | voting.asp) -site:duware.com 

intitle:index.of intext:"secring.skr"|"secring.pgp"|"secring.bak" 

inurl:"GRC.DAT" intext:"password" 

inurl:"slapd.conf" intext:"credentials" -manpage -"Manual Page" -man: -sample 

inurl:"slapd.conf" intext:"rootpw" -manpage -"Manual Page" -man: -sample 

inurl:"wvdial.conf" intext:"password" 

inurl:/db/main.mdb 

inurl:chap-secrets -cvs 

inurl:config.php dbuname dbpass 
inurl:filezilla.xml -cvs 

inurl:lilo.conf filetype:conf password -tatercounter -bootpwd -man 

inurl:nuke filetype:sql 

inurl:ospfd.conf intext:password -sample -test -tutorial -download 路由配置 
inurl:pap-secrets -cvs 

inurl:perform filetype:ini 
inurl:secring ext:skr | ext:pgp | ext:bak 

inurl:vtund.conf intext:pass -cvs 

inurl:zebra.conf intext:password -sample -test -tutorial -download 

"Generated by phpSystem" 
"generated by wwwstat" 

"Host Vulnerability Summary Report" ] 

"HTTP_FROM=googlebot" googlebot.com "Server_Software=" 

"Index of" / "chat/logs" 聊天室 
"Installed Objects Scanner" inurl:default.asp 

"Mecury Version" "Infastructure Group" 
"Microsoft (R) Windows * (TM) Version * DrWtsn Copyright (C)" ext:log 

"Most Submitted Forms and Scripts" "this section" 

"Network Vulnerability Assessment Report" 

"not for distribution" confidential 
"phone * * *" "address *" "e-mail" intitle:"curriculum vitae" 

"phpMyAdmin" "running on" inurl:"main.php" 

"produced by getstats" 
"Request Details" "Control Tree" "Server Variables" 
"robots.txt" "Disallow:" filetype:txt 

"Running in Child mode" 

"sets mode: +p" 
"sets mode: +s" 
"Thank you for your order" +receipt 
"This is a Shareaza Node" 
"This report was generated by WebLog" 
( filetype:mail | filetype:eml | filetype:mbox | filetype:mbx ) intext:password|subject 

(inurl:"robot.txt" | inurl:"robots.txt" ) intext:disallow filetype:txt 

-site:php.net -"The PHP Group" inurl:source inurl:url ext:pHp 

FBR "ADOBE PHOTOSHOP" 
AIM buddy lists 
allinurl:/examples/jsp/snp/snoop.jsp 
allinurl:servlet/SnoopServlet 
cgiirc.conf 

data filetype:mdb -site:gov -site:mil 

exported email addresses 

ext:asp inurl:pathto.asp 

ext:cgi inurl:editcgi.cgi inurl:file= 

ext:conf inurl:rsyncd.conf -cvs -man 
ext:conf NoCatAuth -cvs 

ext:dat bpk.dat 
ext:gho gho 

ext:ini intext:env.ini 
ext:ldif ldif 

ext:log "Software: Microsoft Internet Information Services *.*" 

ext:mdb inurl:*.mdb inurl:fpdb shop.mdb 

filetype:bkf bkf 
filetype:blt "buddylist" 
filetype:blt blt +intext:screenname 

filetype:cfg auto_inst.cfg 

filetype:conf inurl:firewall -intitle:cvs 
filetype:config web.config -CVS 

filetype:ctt ctt messenger 

filetype:fp fp 
filetype:fp fp -site:gov -site:mil -"cvs log" 

filetype:inf inurl:capolicy.inf 
filetype:lic lic intext:key 


filetype:myd myd -CVS 
filetype:ns ns 
filetype:ora ora 
filetype:ora tnsnames 
filetype:pdb pdb backup (Pilot | Pluckerdb) 


filetype:pot inurl:john.pot 


filetype:pst inurl:"outlook.pst" 
filetype:pst pst -from -to -date 
filetype:qbb qbb 
filetype:rdp rdp 

filetype:reg "Terminal Server Client" 
filetype:vcs vcs 
filetype:wab wab 

filetype:xls -site:gov inurl:contact 
filetype:xls inurl:"email.xls" 
Financial spreadsheets: finance.xls 
Financial spreadsheets: finances.xls 

Ganglia Cluster Reports 

haccess.ctl (one way) 
haccess.ctl (VERY reliable) 
ICQ chat logs, please... 

iletype:log cron.log 
intext:"Session Start * * * *:*:* *" filetype:log 
intext:"Tobias Oetiker" "traffic analysis" 

intext:(password | passcode) intext:(username | userid | user) filetype:csv 
intext:gmail invite intext:http://gmail.google.com/gmail/a 

intext:SQLiteManager inurl:main.php 

intitle:"Apache::Status" (inurl:server-status | inurl:status.html | inurl:apache.html) 

intitle:"AppServ Open Project" -site:www.appservnetwork.com 
intitle:"ASP Stats Generator *.*" "ASP Stats Generator" "- weppos" 


intitle:"FTP root at" 
intitle:"index of" +myd size 

intitle:"Index Of" -inurl:maillog maillog size 

intitle:"Index Of" cookies.txt size 

intitle:"index of" mysql.conf OR mysql_config 
intitle:"Index of" upload size parent directory 

intitle:"index.of" .diz .nfo last modified 
intitle:"Multimon UPS status page" 
intitle:"PHP Advanced Transfer" (inurl:index.php | inurl:showrecent.php ) 
intitle:"PhpMyExplorer" inurl:"index.php" -cvs

intitle:"statistics of" "advanced web statistics" 
intitle:"System Statistics" +"System and Network Information Center" 
intitle:"Usage Statistics for" "Generated by Webalizer" 
intitle:"wbem" compaq login "Compaq Information Technologies Group" 

intitle:"Web Server Statistics for ****" 
intitle:"web server status" SSH Telnet 
intitle:"welcome.to.squeezebox" 

intitle:admin intitle:login 
intitle:index.of "Apache" "server at" 
intitle:index.of cleanup.log 
intitle:index.of dead.letter 
intitle:index.of inbox 
intitle:index.of inbox dbx 

intitle:intranet inurl:intranet +intext:"phone" 
inurl:"/axs/ax-admin.pl" -script 
inurl:"/cricket/grapher.cgi" 
inurl:"bookmark.htm" 

inurl:"cacti" +inurl:"graph_view.php" +"Settings Tree View" -cvs -RPM 
inurl:"newsletter/admin/" 
inurl:"newsletter/admin/" intitle:"newsletter admin" 
inurl:"putty.reg" 
inurl:"smb.conf" intext:"workgroup" filetype:conf conf


Welcome to ntop! 

"adding new user" inurl:addnewuser -"there are no domains" 
(inurl:/cgi-bin/.cobalt/) | (intext:"Welcome to the Cobalt RaQ") 

filetype:php HAXPLORER "Server Files Browser" 
intitle:"Web Data Administrator - Login" 


inurl:ConnectComputer/precheck.htm | inurl:Remote/logon.aspx 
PHP Shell (unprotected) 
PHPKonsole PHPShell filetype:php -echo 
Public PHP FileManagers 

"index of" / picasa.ini 
"index of" inurl:recycler 
"Index of" rar r nfo Modified 
"intitle:Index.Of /" stats merchant cgi-* etc 
"Powered by Invision Power File Manager" (inurl:login.php) | (intitle:"Browsing directory /" ) 
"Web File Browser" "Use regular expression" 


filetype:ini Desktop.ini intext:mydocs.dll 


intext:"d.aspx?id" || inurl:"d.aspx?id" 
intext:"Powered By: TotalIndex" intitle:"TotalIndex" 
intitle:"album permissions" "Users who can modify photos" "EVERYBODY" 
intitle:"Directory Listing For" intext:Tomcat -intitle:Tomcat 
intitle:"HFS /" +"HttpFileServer" 
intitle:"Index of *" inurl:"my shared folder" size modified

"File Upload Manager v." "rename to" 


ext:asp "powered by DUForum" inurl:(messages|details|login|default|register) -site:duware.com 
ext:asp inurl:DUgallery intitle:"." -site:dugallery.com -site:duware.com 
ext:cgi inurl:ubb_test 

ezBOO "Administrator Panel" -cvs 

filetype:cgi inurl:cachemgr.cgi 
filetype:cnf my.cnf -cvs -example 
filetype:inc inc intext:setcookie 


filetype:php inurl:"viewfile" -"index.php" -"idfil 
filetype:wsdl wsdl 

intitle:"ASP FileMan" Resend -site:iisworks.com 

intitle:"Index of /" modified php.exe 

intitle:"phpremoteview" filetype:php "Name, Size, Type, Modify" 

inurl:" WWWADMIN.PL" intitle:"wwwadmin" 
inurl:"nph-proxy.cgi" "Start browsing through this CGI-based proxy" 
inurl:"plog/register.php" 
inurl:cgi.asx?StoreID 


inurl:robpoll.cgi filetype:cgi 

The Master List 

"More Info about MetaCart Free" 


　　大家都知道goolge是最强大的搜索引擎之一。比如我们在入侵目标之前 就可以通过google充分掌握目标的相关信息，在发布了某个漏洞之后。　　我们也可以利用goolge来搜索有漏洞的网站进行入侵　　或者也可以直 ...
　　大家都知道goolge是最强大的搜索引擎之一。比如我们在入侵目标之前 就可以通过google充分掌握目标的相关信息，在发布了某个漏洞之后。
　　我们也可以利用goolge来搜索有漏洞的网站进行入侵
　　或者也可以直接搜索别人留下的后门，或者别人盗的Q号之类的 做收渔翁之利。 就因为google如此强大
　　所以一个新的词出来了。就是google hack 也就是利用google强大的能力来应用到我们的hack当中去
　　我简单介绍一下google的基本语法
　　首先就是单引号
　　比如我在google搜索伤心的鱼' 注意后面有个单引号。 这样出来的第一个就是我的博客
　　看图
　　但是如果我们只搜索伤心的鱼那么结果就是不一样的
　　以为不加单引号往往是把伤心的鱼几个字拆出来查询的。 如果想搜索某人的博客什么的就可以在名字后面加一个单引号一般来说就可以了
　　然后就是inurl语法 这是要搜索地址里包含指定字符串的语法
　　比如我博客
　　我们搜索包含hack521.cn所有的信息 就是 inurl hack521.cn
　　inurl还有一个更精确的就是allinurl某木JJ的人告诉我的
　　intext语法 有的时候一些网页的特征字符是出现在页面里的。 比如我们要搜索管理员后台
　　就可以直接intitle:管理员登陆 或者 intext:"管理中心"
　　然后就是site语法了 这个是我最常用的一个
　　比如我们在google里输入site:163.com 就可以找到163被google收录的所有信息
　　结合一些其他的语法很容易就能找到突破口
　　比如我们搜索site:hack521.cn inurl asp?id= 这个就是找出hack521.cn里带有asp?id=字样的连接
　　用 啊D里搜索直接就能找到很多注射点。 是非常方便的。 上次帮某矮人贼入侵联众我就是这样找注射点PS 找了一些ACCESS的注射点没一个找
　　到表段的。着实郁闷了一下午
　　还一个就是我们使用site来查找的话最好输入hack521.cn 而不是www.hack521.cn 这样搜索比较准确
　　再来说一个filetype 这个语法以前是不知道的。有天学校让写一个关于就职方向的论文 我就问某人该如何搜索..
　　这个其实主要是用于来搜索文件类型吧 比如 论文 filetype.doc就是搜索word文档格式的 也可以该成PDF TXT HTM这些随便
　　也可以用来搜索MDB类型的数据库文件 呵呵
　　现在说几实例，比如DVBBS8.0爆出了最新漏洞 我们就可以利用
　　Powered By Dvbbs Version 8.0.0 来搜索所有的动网论坛 比如当初那个PW5.X漏洞...偶就跟某人就第一个开始黑一直黑了二十多个
　　（虽然偶拿到EXP的时候已经很晚了）
　　Powered By Dvbbs Version 8.0.0 这个版本可以改的7.1 7.0都可以进行搜索 动网的默认数据库 管理员默认密码..虽然几率不大 但是在入侵
　　的时候都是要实验一下的
　　最后来给大家说一个最常用的找漏洞网站方法。 我主要是用这个来搞日本站 DB跟SA权限的非常多
　　打开啊D 搜索asp?id= 语言为日语 每页显示100条信息 asp?id=这个跟上面一样 寻找带有参数连接的ASP站点
　　3楼   回复：巧用google 菜鸟也能变hack
　　剩下的就直接用啊D该干嘛干嘛吧。 不过我现在已经很少这样了。用某矮人贼的话说就是啊D造就了企业杀手
　　我已经转行了...
　　最后加上一点
　　查看上传漏洞：
　　site:xx.com inurl:file
　　site:xx.com inurl:load
　　info:xx.com 返回一些基本信息
　　site:xx.com 返回所有与该有关的url
　　link:xx.com 返回所有与该站做了连接的站
　　就说这些吧 这几天心情太不好 总拿键盘发泄了 呵呵

http://www.safebase.cn




















