#!/usr/bin/env bash
# 检测区
# -------------------------------------------------------------
# 检查系统
export LANG=en_US.UTF-8

echoType='echo -e'
 
function rand() { 
 min=$1 
 max=$(($2-$min+1)) 
 num=$(($RANDOM+$RANDOM+$RANDOM+1000000000)) #增加一个10位的数再求余 
 echo $(($num%$max+$min)) 
}  


echoContent() {
    case $1 in
    # 红色
    "red")
        # shellcheck disable=SC2154
        ${echoType} "\033[31m${printN}$2 \033[0m"
        ;;
        # 天蓝色
    "skyBlue")
        ${echoType} "\033[1;36m${printN}$2 \033[0m"
        ;;
        # 绿色
    "green")
        ${echoType} "\033[32m${printN}$2 \033[0m"
        ;;
        # 白色
    "white")
        ${echoType} "\033[37m${printN}$2 \033[0m"
        ;;
    "magenta")
        ${echoType} "\033[31m${printN}$2 \033[0m"
        ;;
        # 黄色
    "yellow")
        ${echoType} "\033[33m${printN}$2 \033[0m"
        ;;
    esac
}

setup_hysteria() {
#安装ifconfig命令
apt -y install net-tools

#变量初始化，这里ip使用ifconfig只是因为我想顺手装上
ipv4=`ifconfig | grep 'inet[^6]' | awk '{print $2}' | cut -d/ -f1 | grep -v "127.0.0.1"`
port=$(rand 10000 59999) 
uuid=$(cat /dev/urandom | od -x | head -1 | awk '{print $2$3"-"$4"-"$5"-"$6"-"$7$8$9}')

#下载官方安装
bash <(curl -fsSL https://get.hy2.sh/)

#生成ssh自签证书
openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) -keyout /etc/hysteria/server.key -out /etc/hysteria/server.crt -subj "/CN=apple.com" -days 3650 && sudo chown hysteria /etc/hysteria/server.key && sudo chown hysteria /etc/hysteria/server.crt

#写配置文件
cat <<EOF > /etc/hysteria/config.yaml
listen: :$port
 
# 以下 acme 和 tls 字段，二选一
# 有域名部署的选择 acme ，无域名的选择 tls
# 选择 acme，必须注释掉 tls，反之一样
 
#acme:
#  domains:
#    - your.domin        # 域名
#  email: your@email.com   # 邮箱，格式正确即可
 
tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key
 
auth:
  type: password
  password: "$uuid"
 
masquerade:
  type: proxy
  proxy:
    url: https://apple.com # 伪装网站
    rewriteHost: true
EOF

#服务启用
systemctl restart hysteria-server.service
systemctl enable hysteria-server.service

echoContent skyBlue "您可以复制到任意客户端："
echoContent skyBlue "hysteria2://${uuid}@${ipv4}:${port}?sni=apple.com&insecure=1#Hysteria2\n"
}

read -r -p "Are your sure tools continue?(Y/N)" selectStart

if [[ "${selectStart}" == "Y" ]]; then
    setup_hysteria
    exit
elif [[ "${selectStart}" == "y" ]]; then
    setup_hysteria
    exit
else
    exit
fi
