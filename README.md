# 前言

借助3x-ui面板可以部署V2Ray、Xray、SS、Trojan、Reality等协议的节点，并且有后台面板方便查看和设置节点信息，对小白非常友好，请结合以下步骤进行操作。

这里首先给出一个多功能面板工具，包含多种工具，他人脚本改良而来，仅供自用。

```
curl -sS -O https://raw.githubusercontent.com/railzen/DownloadStation/main/Shell/cherry/ludo.sh && chmod +x ludo.sh && ./ludo.sh
```



# SSH连接工具

任选其中一个即可

FinalShell(推荐): [FinalShell下载](http://www.hostbuf.com/t/988.html)

MobaXterm: [MobaXterm官网](https://mobaxterm.mobatek.net/)



# 使用GOST实现端口转发

```
gost -L tcp://:37020/yourdomain:37020
```



# 正式安装、搭建节点

### 1、必要更新操作(Debian/Ubuntu)

```
apt update -y
```

```
apt install -y curl socat wget
```

\*注意：如果是centos系统，则运行
```
yum update -y
```

```
yum install -y curl socat wget
```
若要单独安装wget
```
yum install -y wget
```
### 2、安装管理面板

目前常用的有宝塔面板和1Panel  [宝塔面板官网](https://www.bt.cn/new/download.html)  [1Panel官网](https://1panel.cn/docs/installation/online_installation)


##### 一键安装1Panel：
Centos：

```
curl -sSL https://resource.fit2cloud.com/1panel/package/quick_start.sh -o quick_start.sh && sh quick_start.sh
```
Ubuntu：
```
curl -sSL https://resource.fit2cloud.com/1panel/package/quick_start.sh -o quick_start.sh && sudo bash quick_start.sh
```
修改密码：

```
1pctl update password
```
##### 一键安装宝塔：

```
if [ -f /usr/bin/curl ];then curl -sSO https://download.bt.cn/install/install_panel.sh;else wget -O install_panel.sh https://download.bt.cn/install/install_panel.sh;fi;bash install_panel.sh ed8484bec
```


### 3、安装x-ui

```
bash <(curl -Ls https://raw.githubusercontent.com/FranzKafkaYu/x-ui/master/install.sh)
```

**更建议使用3X-UI，一键安装脚本如下：**

```
bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh)
```



### 4、证书申请(可选)

[Ping工具](https://ping.chinaz.com/)   [ITDOG](https://www.itdog.cn/ping/)

安装Acme

```
curl https://get.acme.sh | sh
```

“你的邮箱”改成你的邮箱地址

```
~/.acme.sh/acme.sh --register-account -m admin@railzen.com
```

“你的域名”改成你前面解析好的域名

```
~/.acme.sh/acme.sh --issue -d railzen.com --standalone
```

### 5、常见防火墙命令
```
sudo apt-get install ufw  
# 安装ufw，一般为默认安装
sudo ufw status 
# 查看防火墙状态,也可以看到开放的端口
sudo ufw status verbose  
#查看当前规则
sudo ufw version 
# 查看防火墙版本

sudo ufw enable
#打开防火墙
sudo ufw disable 
# 关闭防火墙
sudo ufw reload  
# 重启防火墙

sudo ufw allow 22 
# 开放端口,以ssh连接的22端口为例
sudo ufw deny 22 
# 关闭端口
sudo ufw delete allow 22  
# 关闭22端口

sudo ufw allow 26101/tcp 
# 指定开放26101的tcp协议,udp未开
sudo ufw delete allow 26101/tcp 
# 指定开放26101的tcp协议,udp未开

sudo ufw allow from 192.168.121.1 to any port 3306 
#开放限定ip地址端口
sudo ufw delete allow from 192.168.121.1 to any port 3306 
#关闭限定ip地址端口

```

### 6.安装网络工具ifconfig

```
apt-get install net-tools
```

### 7.启动Hysteria2协议

```
curl -sS -O https://raw.githubusercontent.com/railzen/DownloadStation/main/Shell/setup_hysteria.sh && chmod +x setup_hysteria.sh && ./setup_hysteria.sh
```

# BBR加速

个人备份的四合一 BBR Plus / 原版BBR一键脚本（Centos 7, Debian 10, Ubuntu 20/22 测试通过）

```
wget -N --no-check-certificate "https://raw.githubusercontent.com/railzen/DownloadStation/main/Shell/BBR/tcp.sh" && chmod +x tcp.sh && ./tcp.sh
```
多内核BBR一键脚本
```
wget -N --no-check-certificate "https://raw.githubusercontent.com/railzen/DownloadStation/main/Shell/BBR/tcpx.sh" && chmod +x tcpx.sh && ./tcpx.sh
```
**Kejilion 脚本（不建议）**

```c
curl -sS -O https://raw.githubusercontent.com/kejilion/sh/main/kejilion.sh && chmod +x kejilion.sh && ./kejilion.sh
```

# 客户端下载

**Windows：** [v2rayN下载](https://github.com/2dust/v2rayN/releases)

**安卓：** [V2RayNG](https://github.com/2dust/v2rayNG/releases)     [NekoBox下载](https://github.com/MatsuriDayo/NekoBoxForAndroid/releases/)

**苹果MAC OS**： [V2RayU下载](https://github.com/yanue/V2rayU/releases)     [NekoRay下载](https://github.com/abbasnaqdi/nekoray-macos/releases/)

# 结尾

**郑重声明：请合理使用科学上网于学习知识、外贸或科研工作方面，遵守相关规定**





#### 附录1 常用Reality协议伪装域名
```
# Apple
gateway.icloud.com
itunes.apple.com
swdist.apple.com
swcdn.apple.com
updates.cdn-apple.com
mensura.cdn-apple.com
osxapps.itunes.apple.com
aod.itunes.apple.com

# mozilla
download-installer.cdn.mozilla.net
addons.mozilla.org

# aws
s0.awsstatic.com
d1.awsstatic.com
images-na.ssl-images-amazon.com
m.media-amazon.com

# 其他
player.live-video.net
one-piece.com
lol.secure.dyn.riotcdn.net
www.lovelive-anime.jp
www.swift.com
academy.nvidia.com
www.cisco.com
www.asus.com
www.samsung.com
www.amd.com
cdn-dynmedia-1.microsoft.com
update.microsoft
software.download.prss.microsoft.com

# google
www.googletagmanager.com
dl.google.com
www.google-analytics.com

# TVB
www.mytvsuper.com
```



#### 附录2 DNS优化有关内容

##### 系统服务- systemd-resolved.service

在Linux系统下关闭DNS服务有多种方法，以下是其中一种常见的方法：

1. 使用Systemd管理DNS服务：

   – 打开终端并以root用户身份登录。
   – 使用以下命令停止DNS服务：`systemctl stop systemd-resolved.service`
   – 禁用DNS服务自启动：`systemctl disable systemd-resolved.service`
   – 修改`/etc/resolv.conf`文件，将`nameserver 127.0.0.53`改为其他DNS服务器的IP地址。例如，你可以使用谷歌的DNS服务器IP地址：`nameserver 8.8.8.8`

2. 使用NetworkManager管理DNS服务：

   – 打开终端并以root用户身份登录。
   – 使用以下命令停止NetworkManager服务：`systemctl stop NetworkManager.service`
   – 编辑`/etc/NetworkManager/NetworkManager.conf`文件，找到`[main]`部分，在其下方添加以下内容：
     “`
     dns=none
     “`
   – 保存文件并重新启动NetworkManager服务：`systemctl start NetworkManager.service`

3. 临时禁用DNS服务：

   – 打开终端并以root用户身份登录。
   – 使用以下命令修改`/etc/resolv.conf`文件，将原来的DNS服务器IP地址注释掉或删除，然后保存文件。
   – 使用以下命令禁用文件的写入权限，防止系统自动更新该文件：`chattr +i /etc/resolv.conf`

请注意，在关闭DNS服务后，你将无法解析域名，因此在进行此操作前，请确保你知道如何手动配置IP地址和DNS服务器IP地址，以确保网络正常工作。



##### 软件功能-resolvconf软件

1、首先安装 resolvconf 如果未安装

```
apt update
apt install resolvconf
```

2、检查已启动并启用的解析服务

```
systemctl status resolvconf.service
```
3、如果未启用服务，则可以通过以下方式启动和启用它： 
```
systemctl start resolvconf.service
systemctl enable resolvconf.service
```
4、现在编辑 resolv.conf.d/head 配置文件
```
vim /etc/resolvconf/resolv.conf.d/head
```
5、将您的 DNS 地址添加到此文件中，例如我使用（223.5.5.5 和 223.6.6.6） 

```
nameserver 223.5.5.5 
nameserver 223.6.6.6 
```
6、现在强制 resolvevconf 在使用 -u 调用时运行更新脚本 

```
resolvconf --enable-updates 
```
7、现在运行更新

```
resolvconf -u
```
 8、修改 /etc/resolv.conf 文件链接
```
rm -rf /etc/resolv.conf
ln -sf /run/resolvconf/resolv.conf /etc/resolv.conf
```
9、现在，如果您检查，则必须在此文件中查看您的DNS配置，如果不尝试这些命令并再次检查

```
cat /etc/resolv.conf 

systemctl restart resolvconf.service
systemctl restart systemd-resolved.service
```

