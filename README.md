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

##### 一键安装宝塔：

```
if [ -f /usr/bin/curl ];then curl -sSO https://download.bt.cn/install/install_panel.sh;else wget -O install_panel.sh https://download.bt.cn/install/install_panel.sh;fi;bash install_panel.sh ed8484bec
```
面板降级
```
curl -L https://github.com/weiwang3056/baota_release/blob/main/LinuxPanel/LinuxPanel-7.9.10.zip\?raw\=true > LinuxPanel-7.9.10.zip && unzip LinuxPanel-7.9.10.zip && chmod 700 ./panel/update.sh && ./panel/update.sh
```
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



### 3、安装x-ui

```
bash <(curl -Ls https://raw.githubusercontent.com/FranzKafkaYu/x-ui/master/install.sh)
```

**更建议使用3X-UI，一键安装脚本如下：**

```
bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh)
```



### 4、证书申请

[ping工具（检测解析域名是否生效）](https://ping.chinaz.com/)

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

个人备份的魔改bbr脚本地址：

```
https://github.com/railzen/Download-Station/tree/main/BBR/tcp.sh
```

四合一 BBR Plus / 原版BBR / 魔改BBR一键脚本（Centos 7, Debian 8/9, Ubuntu 16/18 测试通过）

```
wget -N --no-check-certificate "https://raw.githubusercontent.com/railzen/Download-Station/main/BBR/tcp.sh" && chmod +x tcp.sh && ./tcp.sh
```
多内核BBR一键脚本
```
wget -N --no-check-certificate "https://raw.githubusercontent.com/railzen/DownloadStation/main/BBR/tcpx.sh" && chmod +x tcpx.sh && ./tcpx.sh
```
**Kejilion 脚本（不建议）**

```c
curl -sS -O https://raw.githubusercontent.com/kejilion/sh/main/kejilion.sh && chmod +x kejilion.sh && ./kejilion.sh
```

# 客户端下载

**Windows：** [v2rayN下载](https://github.com/2dust/v2rayN/releases)

**安卓：** [V2RayNG](https://github.com/2dust/v2rayNG/releases)  [NekoBox下载](https://github.com/MatsuriDayo/NekoBoxForAndroid/releases/tag/1.2.9)

**苹果MAC OS**： [V2RayU下载](https://github.com/yanue/V2rayU/releases)  [NekoRay下载](https://github.com/abbasnaqdi/nekoray-macos/releases/)

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
