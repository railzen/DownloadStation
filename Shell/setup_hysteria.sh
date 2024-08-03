#!/usr/bin/env bash
# 检测区
# -------------------------------------------------------------
# 检查系统
export LANG=en_US.UTF-8
sh_ver="V1.0.5 build240803"
echoType='echo -e'
 
Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m" && Yellow_font_prefix="\033[0;33m"
 
function rand() { 
 min=$1 
 max=$(($2-$min+1)) 
 num=$(($RANDOM+$RANDOM+$RANDOM+1000000000)) #增加一个10位的数再求余 
 echo $(($num%$max+$min)) 
}  

ip_address() {
ipv4=$(curl -s ipv4.ip.sb)
ipv6_address=$(curl -s --max-time 1 ipv6.ip.sb)
}

open_firewall_port() {
    ufw allow $1 > /dev/null 2>&1
    sudo firewall-cmd --permanent --add-port=$1 > /dev/null 2>&1
    sed -i "/COMMIT/i -A INPUT -p tcp --dport $1 -j ACCEPT" /etc/iptables/rules.v4 > /dev/null 2>&1
    sed -i "/COMMIT/i -A INPUT -p udp --dport $1 -j ACCEPT" /etc/iptables/rules.v4 > /dev/null 2>&1
    iptables-restore < /etc/iptables/rules.v4 > /dev/null 2>&1
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
#ipv4=`ifconfig | grep 'inet[^6]' | awk '{print $2}' | cut -d/ -f1 | grep -v "127.0.0.1"`
ip_address
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

open_firewall_port $port

echoContent skyBlue "您可以复制到任意客户端："
echoContent skyBlue "hysteria2://${uuid}@${ipv4}:${port}?sni=apple.com&insecure=1&tfo=1#Hysteria2\n"
echo "hysteria2://${uuid}@${ipv4}:${port}?sni=apple.com&insecure=1&tfo=1#Hysteria2" >> ~/Proxy.txt
}

check_status(){
	status=`systemctl status hysteria-server | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1`
}

while true;do
    clear
    echo -e "======================================
 Hysteria2 脚本 $sh_ver 
======================================\n
 ${Green_font_prefix} 1.${Font_color_suffix} 安装 Hysteria2 Server
 ${Green_font_prefix} 2.${Font_color_suffix} 卸载 Hysteria2 Server
 ${Green_font_prefix} 3.${Font_color_suffix} 启停 Hysteria2 Server
\n======================================
 ${Green_font_prefix} 0.${Font_color_suffix} 退出脚本
======================================" && echo
        if [[ -e "/etc/systemd/system/hysteria-server.service" ]]; then
            check_status
            if [[ "$status" == "running" ]]; then
                echo -e " 当前状态:  ${Green_font_prefix}已安装${Font_color_suffix} 并 ${Green_font_prefix}已启动${Font_color_suffix}"
            else
                echo -e " 当前状态:  ${Green_font_prefix}已安装${Font_color_suffix} 但 ${Red_font_prefix}未启动${Font_color_suffix}"
            fi
        else
            echo -e " 当前状态: ${Red_font_prefix}未安装${Font_color_suffix}"
        fi
        echo
        read -e -p " 请输入数字[0-3]:" num
        case "$num" in
            1)
                echo
                read -r -p " Are your sure to continue?(Y/N) " selectStart

                if [[ "${selectStart}" == "Y" ]]; then
                    setup_hysteria
                    read -p "按任意键继续……" temp
                elif [[ "${selectStart}" == "y" ]]; then
                    setup_hysteria
                    read -p "按任意键继续……" temp
                else
                    read -p "取消操作, 按任意键继续……" temp
                fi
            ;;
            2)
                bash <(curl -fsSL https://get.hy2.sh/) --remove > /dev/null
                rm -rf /etc/hysteria
                userdel -r hysteria
                rm -f /etc/systemd/system/multi-user.target.wants/hysteria-server.service
                rm -f /etc/systemd/system/multi-user.target.wants/hysteria-server@*.service
                systemctl daemon-reload
                echoContent green "卸载完成！"
                read -p "按任意键继续……" temp
            ;;
            3)
                if [[ -e "/etc/systemd/system/hysteria-server.service" ]]; then
                    check_status
                    if [[ "$status" == "running" ]]; then
                        systemctl stop hysteria-server.service
                        systemctl disable hysteria-server.service
                    else
                        systemctl restart hysteria-server.service
                        systemctl enable hysteria-server.service
                    fi
                else
                    echo -e " 尚未安装Hysteria2"
                    read -p "按任意键继续……" temp
                fi
            ;;
            0)
            exit 0
            ;;
            *)
            echo "请输入正确数字${Yellow_font_prefix}[0-9]${Font_color_suffix}"
            sleep 0.3
            ;;
        esac
done

