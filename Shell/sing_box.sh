#!/usr/bin/env bash

# 当前脚本版本号
VERSION='v1.0.070 build240803'

function rand() {  min=$1 ; max=$(($2-$min+1)) ; num=$(date +%s%n) ; echo $(($num%$max+$min)) ; } #增加一个十位数再求余
# 各变量默认值
TEMP_DIR='/tmp/cherry-sing-box'
WORK_DIR_SUB='/opt/CherryScript/work/sing-box'
MIN_PORT=1000
MAX_PORT=65520
START_PORT_DEFAULT=$(rand $MIN_PORT $MAX_PORT) 
TLS_SERVER_DEFAULT=addons.mozilla.org
PROTOCOL_LIST=("XTLS + reality" "hysteria2" "tuic" "ShadowTLS" "shadowsocks" "trojan" "vmess + ws" "vless + ws + tls" "H2 + reality" "gRPC + reality")
NODE_TAG=("xtls-reality" "hysteria2" "tuic" "ShadowTLS" "shadowsocks" "trojan" "vmess-ws" "vless-ws-tls" "h2-reality" "grpc-reality")
CONSECUTIVE_PORTS=${#PROTOCOL_LIST[@]}
SUBSCRIBE_TEMPLATE="https://raw.githubusercontent.com/fscarmen/client_template/main"

trap "rm -rf $TEMP_DIR >/dev/null 2>&1 ; echo -e '\n' ;exit 1" INT QUIT TERM EXIT

mkdir -p $TEMP_DIR

# 自定义字体彩色，read 函数
error() { echo -e "\033[31m\033[01m$*\033[0m" && exit 1; } # 红色
warning() { echo -e "\033[33m\033[01m$*\033[0m"; }   # 黄色
info() { echo -e "\033[32m\033[01m$*\033[0m"; }   # 绿色
listchoice() { echo -e "$*"; }
reading() { read -rp "$(info "$1")" "$2"; }


# 字母与数字的 ASCII 码值转换
asc(){
  if [[ "$1" = [a-z] ]]; then
    [ "$2" = '++' ] && printf "\\$(printf '%03o' "$[ $(printf "%d" "'$1'") + 1 ]")" || printf "%d" "'$1'"
  else
    [[ "$1" =~ ^[0-9]+$ ]] && printf "\\$(printf '%03o' "$1")"
  fi
}

open_firewall_port() {
    ufw allow $1 > /dev/null 2>&1
    firewall-cmd --permanent --add-port=$1 > /dev/null 2>&1
    sed -i "/COMMIT/i -A INPUT -p tcp --dport $1 -j ACCEPT" /etc/iptables/rules.v4 > /dev/null 2>&1
    sed -i "/COMMIT/i -A INPUT -p udp --dport $1 -j ACCEPT" /etc/iptables/rules.v4 > /dev/null 2>&1
    iptables-restore < /etc/iptables/rules.v4 > /dev/null 2>&1
}

check_root() {
  [ "$(id -u)" != 0 ] && error "\n 必须以root方式运行脚本，可以输入 sudo -i 后重新下载运行 \n"
}

# 判断处理器架构
check_arch() {
  case $(uname -m) in
    aarch64|arm64 ) SING_BOX_ARCH=arm64; JQ_ARCH=arm64; QRENCODE_ARCH=arm64 ;;
    x86_64|amd64 ) [[ "$(awk -F ':' '/flags/{print $2; exit}' /proc/cpuinfo)" =~ avx2 ]] && SING_BOX_ARCH=amd64v3 || SING_BOX_ARCH=amd64; JQ_ARCH=amd64; QRENCODE_ARCH=amd64 ;;
    armv7l ) SING_BOX_ARCH=armv7; JQ_ARCH=armhf; QRENCODE_ARCH=arm ;;
    * ) error " 当前架构 \$(uname -m) 暂不支持 "
  esac
}

# 查安装及运行状态；状态码: 26 未安装， 27 已安装未运行， 28 运行中
check_install() {
  STATUS="未安装" && [ -s /etc/systemd/system/sing-box.service ] && STATUS="关闭" && [ "$(systemctl is-active sing-box)" = 'active' ] && STATUS="开启"
  if [[ $STATUS = "未安装" ]] && [ ! -s $WORK_DIR_SUB/sing-box ]; then
    {
    local VERSION_LATEST=$(wget --no-check-certificate -qO- "https://api.github.com/repos/SagerNet/sing-box/releases" | awk -F '["v-]' '/tag_name/{print $5}' | sort -r | sed -n '1p')
    local ONLINE=$(wget --no-check-certificate -qO- "https://api.github.com/repos/SagerNet/sing-box/releases" | awk -F '["v]' -v var="tag_name.*$VERSION_LATEST" '$0 ~ var {print $5; exit}')
    ONLINE=${ONLINE:-'1.9.3'}
    wget --no-check-certificate --continue https://github.com/SagerNet/sing-box/releases/download/v$ONLINE/sing-box-$ONLINE-linux-$SING_BOX_ARCH.tar.gz -qO- | tar xz -C $TEMP_DIR sing-box-$ONLINE-linux-$SING_BOX_ARCH/sing-box >/dev/null 2>&1
    [ -s $TEMP_DIR/sing-box-$ONLINE-linux-$SING_BOX_ARCH/sing-box ] && mv $TEMP_DIR/sing-box-$ONLINE-linux-$SING_BOX_ARCH/sing-box $TEMP_DIR
    wget --no-check-certificate --continue -qO $TEMP_DIR/jq https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-linux-$JQ_ARCH >/dev/null 2>&1 && chmod +x $TEMP_DIR/jq >/dev/null 2>&1
    wget --no-check-certificate --continue -qO $TEMP_DIR/qrencode https://github.com/fscarmen/client_template/raw/main/qrencode-go/qrencode-go-linux-$QRENCODE_ARCH >/dev/null 2>&1 && chmod +x $TEMP_DIR/qrencode >/dev/null 2>&1
    }&
  fi
}

# 检测 sing-box 的状态
check_sing_box_status(){
  case "$STATUS" in
    "未安装" )
      error "\n Sing-box 开启 失败 \n"
      ;;
    "关闭" )
      cmd_systemctl enable sing-box && info "\n Sing-box 开启 成功 \n" || error "\n Sing-box 开启 失败 \n"
      ;;
    "开启" )
      info "\n Sing-box 开启 成功 \n"
  esac
}

# 为了适配 alpine，定义 cmd_systemctl 的函数
cmd_systemctl() {
  local ENABLE_DISABLE=$1
  local APP=$2
  if [ "$ENABLE_DISABLE" = 'enable' ]; then
    if [ "$SYSTEM" = 'Alpine' ]; then
      systemctl start $APP
      cat > /etc/local.d/$APP.start << EOF
#!/usr/bin/env bash

systemctl start $APP
EOF
      chmod +x /etc/local.d/$APP.start
      rc-update add local >/dev/null 2>&1
    elif [ "$IS_CENTOS" = 'CentOS7' ]; then
      systemctl enable --now $APP
    else
      systemctl enable --now $APP
    fi
  elif [ "$ENABLE_DISABLE" = 'disable' ]; then
    if [ "$SYSTEM" = 'Alpine' ]; then
      systemctl stop $APP
      rm -f /etc/local.d/$APP.start
    elif [ "$IS_CENTOS" = 'CentOS7' ]; then
      systemctl disable --now $APP
    else
      systemctl disable --now $APP
    fi
  fi
}

check_system_info() {
  # 判断虚拟化
  if [ $(type -p systemd-detect-virt) ]; then
    VIRT=$(systemd-detect-virt)
  elif [ $(type -p hostnamectl) ]; then
    VIRT=$(hostnamectl | awk '/Virtualization/{print $NF}')
  elif [ $(type -p virt-what) ]; then
    VIRT=$(virt-what)
  fi

  [ -s /etc/os-release ] && SYS="$(awk -F '"' 'tolower($0) ~ /pretty_name/{print $2}' /etc/os-release)"
  [[ -z "$SYS" && $(type -p hostnamectl) ]] && SYS="$(hostnamectl | awk -F ': ' 'tolower($0) ~ /operating system/{print $2}')"
  [[ -z "$SYS" && $(type -p lsb_release) ]] && SYS="$(lsb_release -sd)"
  [[ -z "$SYS" && -s /etc/lsb-release ]] && SYS="$(awk -F '"' 'tolower($0) ~ /distrib_description/{print $2}' /etc/lsb-release)"
  [[ -z "$SYS" && -s /etc/redhat-release ]] && SYS="$(cat /etc/redhat-release)"
  [[ -z "$SYS" && -s /etc/issue ]] && SYS="$(sed -E '/^$|^\\/d' /etc/issue | awk -F '\\' '{print $1}' | sed 's/[ ]*$//g')"

  REGEX=("debian" "ubuntu" "centos|red hat|kernel|alma|rocky" "arch linux" "alpine" "fedora")
  RELEASE=("Debian" "Ubuntu" "CentOS" "Arch" "Alpine" "Fedora")
  EXCLUDE=("")
  MAJOR=("9" "16" "7" "3" "" "37")
  PACKAGE_UPDATE=("apt -y update" "apt -y update" "yum -y update" "pacman -Sy" "apk update -f" "dnf -y update")
  PACKAGE_INSTALL=("apt -y install" "apt -y install" "yum -y install" "pacman -S --noconfirm" "apk add --no-cache" "dnf -y install")
  PACKAGE_UNINSTALL=("apt -y autoremove" "apt -y autoremove" "yum -y autoremove" "pacman -Rcnsu --noconfirm" "apk del -f" "dnf -y autoremove")

  for int in "${!REGEX[@]}"; do
    [[ "${SYS,,}" =~ ${REGEX[int]} ]] && SYSTEM="${RELEASE[int]}" && break
  done

  # 针对各厂商的订制系统
  if [ -z "$SYSTEM" ]; then
    [ $(type -p yum) ] && int=2 && SYSTEM='CentOS' || error "本脚本只支持 Debian、Ubuntu、CentOS、Alpine、Fedora 或 Arch 系统"
  fi

  # 先排除 EXCLUDE 里包括的特定系统，其他系统需要作大发行版本的比较
  for ex in "${EXCLUDE[@]}"; do [[ ! "{$SYS,,}"  =~ $ex ]]; done &&
  [[ "$(echo "$SYS" | sed "s/[^0-9.]//g" | cut -d. -f1)" -lt "${MAJOR[int]}" ]] && error " 当前操作是 \$SYS\\\n 不支持 $SYSTEM ${MAJOR[int]} 以下系统 "

  # 针对部分系统作特殊处理
  [ "$SYSTEM" = 'CentOS' ] && IS_CENTOS="CentOS$(echo "$SYS" | sed "s/[^0-9.]//g" | cut -d. -f1)"
}

# 检测 IPv4 IPv6 信息
check_system_ip() {
  IP4=$(wget -4 -qO- --no-check-certificate --user-agent=Mozilla --tries=2 --timeout=1 http://ip-api.com/json/) &&
  WAN4=$(expr "$IP4" : '.*query\":[ ]*\"\([^"]*\).*') &&
  COUNTRY4=$(expr "$IP4" : '.*country\":[ ]*\"\([^"]*\).*') &&
  ASNORG4=$(expr "$IP4" : '.*isp\":[ ]*\"\([^"]*\).*')
}

# 输入起始 port 函数
enter_start_port() {
  local NUM=$1
  local PORT_ERROR_TIME=6
  while true; do
    [ "$PORT_ERROR_TIME" -lt 6 ] && unset IN_USED START_PORT
    (( PORT_ERROR_TIME-- )) || true
    if [ "$PORT_ERROR_TIME" = 0 ]; then
      error "\n 输入错误达5次,脚本退出 \n"
    else
      [ -z "$START_PORT" ] && info "\n (2/6) 请输入开始的端口号，必须是 ${MIN_PORT} - ${MAX_PORT}，需要连续${NUM}个空闲的端口 (默认为: ${START_PORT_DEFAULT}): "&& read START_PORT
    fi
    START_PORT=${START_PORT:-"$START_PORT_DEFAULT"}
    if [[ "$START_PORT" =~ ^[1-9][0-9]{2,4}$ && "$START_PORT" -ge "$MIN_PORT" && "$START_PORT" -le "$MAX_PORT" ]]; then
      for port in $(eval echo {$START_PORT..$[START_PORT+NUM-1]}); do
      ss -nltup | grep -q ":$port" && IN_USED+=("$port")
      done
      [ "${#IN_USED[*]}" -eq 0 ] && break || warning "\n 正在使用中的端口: ${IN_USED[*]} \n"
    fi
  done
}

# 定义 Sing-box 变量
sing_box_variables() {
while true; do
    clear
    echo "  
==================================================
Sing-Box 管理脚本V1 $VERSION 
=================================================="
  # 选择安装的协议，由于选项 a 为全部协议，所以选项数不是从 a 开始，而是从 b 开始，处理输入：把大写全部变为小写，把不符合的选项去掉，把重复的选项合并
  MAX_CHOOSE_PROTOCOLS=$(asc $[CONSECUTIVE_PORTS+96+1])
  if [ -z "$CHOOSE_PROTOCOLS" ]; then
    listchoice "\n 多选需要安装协议(比如 bcdf):\n "
    for e in "${!PROTOCOL_LIST[@]}"; do
      [[ "$e" =~ '6'|'7' ]] && listchoice " $(asc $[e+98]). ${PROTOCOL_LIST[e]} (必须在 Cloudflare 解析自有域名) " || listchoice " $(asc $[e+98]). ${PROTOCOL_LIST[e]} "
    done
    echo -e "\n=================================================="
    echo -e " 0.退出"
    echo -e "==================================================\n"
    if [[ "${flagInstallSS2022}" == "Install" ]]; then
      clear
      CHOOSE_PROTOCOLS="e"
      break;
    else
      reading "\n 请选择: " CHOOSE_PROTOCOLS
    fi;
      
  fi
  
  if [[ "${CHOOSE_PROTOCOLS}" == "0" ]]; then
      exit 0
  elif [[ ! "${CHOOSE_PROTOCOLS,,}" =~ [b-$MAX_CHOOSE_PROTOCOLS] ]]; then
      warning "\n 输入错误，请重新输入"
      unset CHOOSE_PROTOCOLS
      sleep 0.5
  else
      break;
  fi 
done

  check_system_ip
  if grep -qi 'cloudflare' <<< "$ASNORG4"; then
    local a=6
    until [ -n "$SERVER_IP" ]; do
      ((a--)) || true
      [ "$a" = 0 ] && error "\n 输入错误达5次,脚本退出 \n"
      reading "\n 检测到 warp / warp-go 正在运行，请输入确认的服务器 IP: " SERVER_IP
    done
    WARP_ENDPOINT=162.159.193.10
    DOMAIN_STRATEG=prefer_ipv4
  else
    SERVER_IP_DEFAULT=$WAN4
    WARP_ENDPOINT=162.159.193.10
    DOMAIN_STRATEG=prefer_ipv4
  fi
 
  # 对选择协议的输入处理逻辑：先把所有的大写转为小写，并把所有没有去选项剔除掉，最后按输入的次序排序。如果选项为 a(all) 和其他选项并存，将会忽略 a，如 abc 则会处理为 bc
  [[ ! "${CHOOSE_PROTOCOLS,,}" =~ [b-$MAX_CHOOSE_PROTOCOLS] ]] && INSTALL_PROTOCOLS=($(eval echo {b..$MAX_CHOOSE_PROTOCOLS})) || INSTALL_PROTOCOLS=($(grep -o . <<< "$CHOOSE_PROTOCOLS" | sed "/[^b-$MAX_CHOOSE_PROTOCOLS]/d" | awk '!seen[$0]++'))

  # 显示选择协议及其次序，输入开始端口号
  if [ -z "$START_PORT" ]; then
    listchoice "\n 选择的协议及端口次序如下: "
    for w in "${!INSTALL_PROTOCOLS[@]}"; do
      [ "$w" -ge 9 ] && listchoice " $[w+1]. ${PROTOCOL_LIST[$(($(asc ${INSTALL_PROTOCOLS[w]}) - 98))]} " || listchoice " $[w+1] . ${PROTOCOL_LIST[$(($(asc ${INSTALL_PROTOCOLS[w]}) - 98))]} "
    done
    enter_start_port ${#INSTALL_PROTOCOLS[@]}
  fi
  # 输入服务器 IP,默认为检测到的服务器 IP，如果全部为空，则提示并退出脚本
  [ -z "$SERVER_IP" ] && reading "\n (4/6) 请输入 VPS IP (默认为: ${SERVER_IP_DEFAULT}): " SERVER_IP
  SERVER_IP=${SERVER_IP:-"$SERVER_IP_DEFAULT"} && WS_SERVER_IP_SHOW=$SERVER_IP
  [ -z "$SERVER_IP" ] && error " 没有 server ip，脚本退出 "

  # 如选择有 h. vmess + ws 或 i. vless + ws 时，先检测是否有支持的 http 端口可用，如有则要求输入域名和 cdn
  if [[ "${INSTALL_PROTOCOLS[@]}" =~ 'h' ]]; then
    local DOMAIN_ERROR_TIME=5
    until [ -n "$VMESS_HOST_DOMAIN" ]; do
      (( DOMAIN_ERROR_TIME-- )) || true
      [ "$DOMAIN_ERROR_TIME" != 0 ] && TYPE=VMESS && reading "\n 请输入 $TYPE 域名: " VMESS_HOST_DOMAIN || error "\n 输入错误达5次,脚本退出 \n"
    done
  fi

  if [[ "${INSTALL_PROTOCOLS[@]}" =~ 'i' ]]; then
    local DOMAIN_ERROR_TIME=5
    until [ -n "$VLESS_HOST_DOMAIN" ]; do
      (( DOMAIN_ERROR_TIME-- )) || true
      [ "$DOMAIN_ERROR_TIME" != 0 ] && TYPE=VLESS && reading "\n 请输入 $TYPE 域名: " VLESS_HOST_DOMAIN || error "\n 输入错误达5次,脚本退出 \n"
    done
  fi

  # 输入 UUID ，错误超过 5 次将会退出
  UUID_DEFAULT=$(cat /proc/sys/kernel/random/uuid)
  [ -z "$UUID_CONFIRM" ] && reading "\n (5/6) 请输入 UUID (默认为 ${UUID_DEFAULT}): " UUID_CONFIRM
  local UUID_ERROR_TIME=5
  until [[ -z "$UUID_CONFIRM" || "${UUID_CONFIRM,,}" =~ ^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$ ]]; do
    (( UUID_ERROR_TIME-- )) || true
    [ "$UUID_ERROR_TIME" = 0 ] && error "\n 输入错误达5次,脚本退出 \n" || reading "\n UUID 应为36位字符,请重新输入 \(剩余${UUID_ERROR_TIME}次\): \n" UUID_CONFIRM
  done
  UUID_CONFIRM=${UUID_CONFIRM:-"$UUID_DEFAULT"}

  # 输入节点名，以系统的 hostname 作为默认
  if [ -z "$NODE_NAME_CONFIRM" ]; then
    if [ $(type -p hostname) ]; then
      NODE_NAME_DEFAULT="$(hostname)"
    elif [ -s /etc/hostname ]; then
      NODE_NAME_DEFAULT="$(cat /etc/hostname)"
    else
      NODE_NAME_DEFAULT="Sing-Box"
    fi
    reading "\n (6/6) 请输入节点名称 (默认为 ${NODE_NAME_DEFAULT}): " NODE_NAME_CONFIRM
    NODE_NAME_CONFIRM="${NODE_NAME_CONFIRM:-"$NODE_NAME_DEFAULT"}"
  fi
}

check_dependencies() {
  # 如果是 Alpine，先升级 wget ，安装 systemctl-py 版
  if [ "$SYSTEM" = 'Alpine' ]; then
    local CHECK_WGET=$(wget 2>&1 | head -n 1)
    grep -qi 'busybox' <<< "$CHECK_WGET" && ${PACKAGE_INSTALL[int]} wget >/dev/null 2>&1
    local DEPS_CHECK=("bash" "rc-update" "virt-what" "python3")
    local DEPS_INSTALL=("bash" "openrc" "virt-what" "python3")
    for g in "${!DEPS_CHECK[@]}"; do
      [ ! $(type -p ${DEPS_CHECK[g]}) ] && DEPS_ALPINE+=(${DEPS_INSTALL[g]})
    done
    if [ "${#DEPS_ALPINE[@]}" -ge 1 ]; then
      info "\n 安装依赖列表: $(sed "s/ /,&/g" <<< ${DEPS_ALPINE[@]}) \n"
      ${PACKAGE_UPDATE[int]} >/dev/null 2>&1
      ${PACKAGE_INSTALL[int]} >/dev/null 2>&1
      ${DEPS_ALPINE[@]} >/dev/null 2>&1
      [[ -z "$VIRT" && "${DEPS_ALPINE[@]}" =~ 'virt-what' ]] && VIRT=$(virt-what)
    fi

    [ ! $(type -p systemctl) ] && wget --no-check-certificate --quiet https://raw.githubusercontent.com/gdraheim/docker-systemctl-replacement/master/files/docker/systemctl3.py -O /bin/systemctl && chmod a+x /bin/systemctl
  fi

  # 检测 Linux 系统的依赖，升级库并重新安装依赖
  local DEPS_CHECK=("wget" "tar" "systemctl" "ss" "bash" "openssl")
  local DEPS_INSTALL=("wget" "tar" "systemctl" "iproute2" "bash" "openssl")
  for g in "${!DEPS_CHECK[@]}"; do
    [ ! $(type -p ${DEPS_CHECK[g]}) ] && DEPS+=(${DEPS_INSTALL[g]})
  done
  if [ "${#DEPS[@]}" -ge 1 ]; then
    info "\n 安装依赖列表: $(sed "s/ /,&/g" <<< ${DEPS[@]}) \n"
    [ "$SYSTEM" != 'CentOS' ] && ${PACKAGE_UPDATE[int]} >/dev/null 2>&1
    ${PACKAGE_INSTALL[int]} ${DEPS[@]} >/dev/null 2>&1
  else
    info "\n 所有依赖已存在，不需要额外安装 \n"
  fi
}

# 生成100年的自签证书
ssl_certificate() {
  mkdir -p $WORK_DIR_SUB/cert
  openssl ecparam -genkey -name prime256v1 -out $WORK_DIR_SUB/cert/private.key && openssl req -new -x509 -days 36500 -key $WORK_DIR_SUB/cert/private.key -out $WORK_DIR_SUB/cert/cert.pem -subj "/CN=$(awk -F . '{print $(NF-1)"."$NF}' <<< "$TLS_SERVER_DEFAULT")"
}

# 处理防火墙规则
check_firewall_configuration() {
  if [[ -s /etc/selinux/config && $(type -p getenforce) && $(getenforce) = 'Enforcing' ]]; then
    listchoice "\n 设置 SElinux: enforcing --> disabled "
    setenforce 0
    sed -i 's/^SELINUX=.*/# &/; /SELINUX=/a\SELINUX=disabled' /etc/selinux/config
  fi
}

# 生成 sing-box 配置文件
sing_box_json() {
  local IS_CHANGE=$1
  mkdir -p $WORK_DIR_SUB/conf $WORK_DIR_SUB/logs $WORK_DIR_SUB/subscribe

  # 判断是否为新安装，不为 change 就是新安装
  if [ "$IS_CHANGE" = 'change' ]; then
    # 判断 sing-box 主程序所在路径
    DIR=$WORK_DIR_SUB
  else
    DIR=$TEMP_DIR

    # 生成 dns 配置
    cat > $WORK_DIR_SUB/conf/00_log.json << EOF
{
    "log":{
        "disabled":false,
        "level":"error",
        "output":"$WORK_DIR_SUB/logs/box.log",
        "timestamp":true
    }
}
EOF

    # 生成 outbound 配置
    cat > $WORK_DIR_SUB/conf/01_outbounds.json << EOF
{
    "outbounds":[
        {
            "type":"direct",
            "tag":"direct",
            "domain_strategy":"$DOMAIN_STRATEG"
        },
        {
            "type":"direct",
            "tag":"warp-IPv4-out",
            "detour":"wireguard-out",
            "domain_strategy":"ipv4_only"
        },
        {
            "type":"direct",
            "tag":"warp-IPv6-out",
            "detour":"wireguard-out",
            "domain_strategy":"ipv6_only"
        },
        {
            "type":"wireguard",
            "tag":"wireguard-out",
            "server":"${WARP_ENDPOINT}",
            "server_port":2408,
            "local_address":[
                "172.16.0.2/32",
                "2606:4700:110:8a36:df92:102a:9602:fa18/128"
            ],
            "private_key":"YFYOAdbw1bKTHlNNi+aEjBM3BO7unuFC5rOkMRAz9XY=",
            "peer_public_key":"bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
            "reserved":[
                78,
                135,
                76
            ],
            "mtu":1280
        },
        {
            "type":"block",
            "tag":"block"
        }
    ]
}
EOF

    # 生成 route 配置
    cat > $WORK_DIR_SUB/conf/02_route.json << EOF
{
    "route":{
        "rule_set":[
            {
                "tag":"geosite-openai",
                "type":"remote",
                "format":"binary",
                "url":"https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-openai.srs"
            }
        ],
        "rules":[
            {
                "domain":"api.openai.com",
                "outbound":"direct"
            },
            {
                "rule_set":"geosite-openai",
                "outbound":"direct"
            }
        ]
    }
}
EOF

    # 生成缓存文件
    cat > $WORK_DIR_SUB/conf/03_experimental.json << EOF
{
    "experimental": {
        "cache_file": {
            "enabled": true,
            "path": "$WORK_DIR_SUB/cache.db"
        }
    }
}
EOF

    # 生成 dns 配置文件
    cat > $WORK_DIR_SUB/conf/04_dns.json << EOF
{
    "dns":{
        "servers":[
            {
                "address":"local"
            }
        ]
    }
}
EOF
  fi

  # 生成 Reality 公私钥，第一次安装的时候使用新生成的；添加协议的时，使用相应数组里的第一个非空值，如全空则像第一次安装那样使用新生成的
  if [[ "${#REALITY_PRIVATE[@]}" = 0 || "${#REALITY_PUBLIC[@]}" = 0 ]]; then
    REALITY_KEYPAIR=$($DIR/sing-box generate reality-keypair) && REALITY_PRIVATE=$(awk '/PrivateKey/{print $NF}' <<< "$REALITY_KEYPAIR") && REALITY_PUBLIC=$(awk '/PublicKey/{print $NF}' <<< "$REALITY_KEYPAIR")
  else
    REALITY_PRIVATE=$(awk '{print $1}' <<< "${REALITY_PRIVATE[@]}") && REALITY_PUBLIC=$(awk '{print $1}' <<< "${REALITY_PUBLIC[@]}")
  fi

  # 生成 TLS 网站
  [ "${#TLS_SERVER[@]}" -gt 0 ] && TLS_SERVER=$(awk '{print $1}' <<< "${TLS_SERVER[@]}") || TLS_SERVER=$TLS_SERVER_DEFAULT

  # 第1个协议为 b  (a为全部)，生成 XTLS + Reality 配置
  CHECK_PROTOCOLS=b
  if [[ "${INSTALL_PROTOCOLS[@]}" =~ "$CHECK_PROTOCOLS" ]]; then
    [ -z "$PORT_XTLS_REALITY" ] && PORT_XTLS_REALITY=$[START_PORT+$(awk -v target=$CHECK_PROTOCOLS '{ for(i=1; i<=NF; i++) if($i == target) { print i-1; break } }' <<< "${INSTALL_PROTOCOLS[*]}")]
    NODE_NAME[11]=${NODE_NAME[11]:-"$NODE_NAME_CONFIRM"} && UUID[11]=${UUID[11]:-"$UUID_CONFIRM"} && TLS_SERVER[11]=${TLS_SERVER[11]:-"$TLS_SERVER"} && REALITY_PRIVATE[11]=${REALITY_PRIVATE[11]:-"$REALITY_PRIVATE"} && REALITY_PUBLIC[11]=${REALITY_PUBLIC[11]:-"$REALITY_PUBLIC"}
    open_firewall_port ${PORT_XTLS_REALITY}
    cat > $WORK_DIR_SUB/conf/11_${NODE_TAG[0]}_inbounds.json << EOF
//  "public_key":"${REALITY_PUBLIC[11]}"
{
    "inbounds":[
        {
            "type":"vless",
            "sniff":true,
            "sniff_override_destination":true,
            "tag":"${NODE_NAME[11]} ${NODE_TAG[0]}",
            "listen":"::",
            "listen_port":$PORT_XTLS_REALITY,
            "users":[
                {
                    "uuid":"${UUID[11]}",
                    "flow":""
                }
            ],
            "tls":{
                "enabled":true,
                "server_name":"${TLS_SERVER[11]}",
                "reality":{
                    "enabled":true,
                    "handshake":{
                        "server":"${TLS_SERVER[11]}",
                        "server_port":443
                    },
                    "private_key":"${REALITY_PRIVATE[11]}",
                    "short_id":[
                        ""
                    ]
                }
            },
            "multiplex":{
                "enabled":true,
                "padding":true,
                "brutal":{
                    "enabled":true,
                    "up_mbps":1000,
                    "down_mbps":1000
                }
            }
        }
    ]
}
EOF
  fi

  # 生成 Hysteria2 配置
  CHECK_PROTOCOLS=$(asc "$CHECK_PROTOCOLS" ++)
  if [[ "${INSTALL_PROTOCOLS[@]}" =~ "$CHECK_PROTOCOLS" ]]; then
    [ -z "$PORT_HYSTERIA2" ] && PORT_HYSTERIA2=$[START_PORT+$(awk -v target=$CHECK_PROTOCOLS '{ for(i=1; i<=NF; i++) if($i == target) { print i-1; break } }' <<< "${INSTALL_PROTOCOLS[*]}")]
    NODE_NAME[12]=${NODE_NAME[12]:-"$NODE_NAME_CONFIRM"} && UUID[12]=${UUID[12]:-"$UUID_CONFIRM"}
    open_firewall_port ${PORT_HYSTERIA2}
    cat > $WORK_DIR_SUB/conf/12_${NODE_TAG[1]}_inbounds.json << EOF
{
    "inbounds":[
        {
            "type":"hysteria2",
            "sniff":true,
            "sniff_override_destination":true,
            "tag":"${NODE_NAME[12]} ${NODE_TAG[1]}",
            "listen":"::",
            "listen_port":$PORT_HYSTERIA2,
            "users":[
                {
                    "password":"${UUID[12]}"
                }
            ],
            "ignore_client_bandwidth":false,
            "tls":{
                "enabled":true,
                "server_name":"",
                "alpn":[
                    "h3"
                ],
                "min_version":"1.3",
                "max_version":"1.3",
                "certificate_path":"$WORK_DIR_SUB/cert/cert.pem",
                "key_path":"$WORK_DIR_SUB/cert/private.key"
            }
        }
    ]
}
EOF
  fi

  # 生成 Tuic V5 配置
  CHECK_PROTOCOLS=$(asc "$CHECK_PROTOCOLS" ++)
  if [[ "${INSTALL_PROTOCOLS[@]}" =~ "$CHECK_PROTOCOLS" ]]; then
    [ -z "$PORT_TUIC" ] && PORT_TUIC=$[START_PORT+$(awk -v target=$CHECK_PROTOCOLS '{ for(i=1; i<=NF; i++) if($i == target) { print i-1; break } }' <<< "${INSTALL_PROTOCOLS[*]}")]
    NODE_NAME[13]=${NODE_NAME[13]:-"$NODE_NAME_CONFIRM"} && UUID[13]=${UUID[13]:-"$UUID_CONFIRM"} && TUIC_PASSWORD=${TUIC_PASSWORD:-"$UUID_CONFIRM"} && TUIC_CONGESTION_CONTROL=${TUIC_CONGESTION_CONTROL:-"bbr"}
    open_firewall_port ${PORT_TUIC}
    cat > $WORK_DIR_SUB/conf/13_${NODE_TAG[2]}_inbounds.json << EOF
{
    "inbounds":[
        {
            "type":"tuic",
            "sniff":true,
            "sniff_override_destination":true,
            "tag":"${NODE_NAME[13]} ${NODE_TAG[2]}",
            "listen":"::",
            "listen_port":$PORT_TUIC,
            "users":[
                {
                    "uuid":"${UUID[13]}",
                    "password":"$TUIC_PASSWORD"
                }
            ],
            "congestion_control": "$TUIC_CONGESTION_CONTROL",
            "zero_rtt_handshake": false,
            "tls":{
                "enabled":true,
                "alpn":[
                    "h3"
                ],
                "certificate_path":"$WORK_DIR_SUB/cert/cert.pem",
                "key_path":"$WORK_DIR_SUB/cert/private.key"
            }
        }
    ]
}
EOF
  fi

  # 生成 ShadowTLS V5 配置
  CHECK_PROTOCOLS=$(asc "$CHECK_PROTOCOLS" ++)
  if [[ "${INSTALL_PROTOCOLS[@]}" =~ "$CHECK_PROTOCOLS" ]]; then
    [ -z "$PORT_SHADOWTLS" ] && PORT_SHADOWTLS=$[START_PORT+$(awk -v target=$CHECK_PROTOCOLS '{ for(i=1; i<=NF; i++) if($i == target) { print i-1; break } }' <<< "${INSTALL_PROTOCOLS[*]}")]
    NODE_NAME[14]=${NODE_NAME[14]:-"$NODE_NAME_CONFIRM"} && UUID[14]=${UUID[14]:-"$UUID_CONFIRM"} && TLS_SERVER[14]=${TLS_SERVER[14]:-"$TLS_SERVER"} && SHADOWTLS_PASSWORD=${SHADOWTLS_PASSWORD:-"$($DIR/sing-box generate rand --base64 16)"} && SHADOWTLS_METHOD=${SHADOWTLS_METHOD:-"2022-blake3-aes-128-gcm"}
    open_firewall_port ${PORT_SHADOWTLS}
    cat > $WORK_DIR_SUB/conf/14_${NODE_TAG[3]}_inbounds.json << EOF
{
    "inbounds":[
        {
            "type":"shadowtls",
            "sniff":true,
            "sniff_override_destination":true,
            "tag":"${NODE_NAME[14]} ${NODE_TAG[3]}",
            "listen":"::",
            "listen_port":$PORT_SHADOWTLS,
            "detour":"shadowtls-in",
            "version":3,
            "users":[
                {
                    "password":"${UUID[14]}"
                }
            ],
            "handshake":{
                "server":"${TLS_SERVER[14]}",
                "server_port":443
            },
            "strict_mode":true
        },
        {
            "type":"shadowsocks",
            "tag":"shadowtls-in",
            "listen":"127.0.0.1",
            "network":"tcp",
            "method":"$SHADOWTLS_METHOD",
            "password":"$SHADOWTLS_PASSWORD",
            "multiplex":{
                "enabled":true,
                "padding":true,
                "brutal":{
                    "enabled":true,
                    "up_mbps":1000,
                    "down_mbps":1000
                }
            }
        }
    ]
}
EOF
  fi

  # 生成 Shadowsocks 配置
  CHECK_PROTOCOLS=$(asc "$CHECK_PROTOCOLS" ++)
  if [[ "${INSTALL_PROTOCOLS[@]}" =~ "$CHECK_PROTOCOLS" ]]; then
    [ -z "$PORT_SHADOWSOCKS" ] && PORT_SHADOWSOCKS=$[START_PORT+$(awk -v target=$CHECK_PROTOCOLS '{ for(i=1; i<=NF; i++) if($i == target) { print i-1; break } }' <<< "${INSTALL_PROTOCOLS[*]}")]
    NODE_NAME[15]=${NODE_NAME[15]:-"$NODE_NAME_CONFIRM"} && UUID[15]=${SHADOWTLS_PASSWORD:-"$($DIR/sing-box generate rand --base64 16)"} && SHADOWSOCKS_METHOD=${SHADOWSOCKS_METHOD:-"aes-128-gcm"}
    open_firewall_port ${PORT_SHADOWSOCKS}
    cat > $WORK_DIR_SUB/conf/15_${NODE_TAG[4]}_inbounds.json << EOF
{
    "inbounds":[
        {
            "type":"shadowsocks",
            "sniff":true,
            "sniff_override_destination":true,
            "tag":"${NODE_NAME[15]} ${NODE_TAG[4]}",
            "listen":"::",
            "listen_port":$PORT_SHADOWSOCKS,
            "method":"${SHADOWSOCKS_METHOD}",
            "password":"${UUID[15]}",
            "multiplex":{
                "enabled":true,
                "padding":true,
                "brutal":{
                    "enabled":true,
                    "up_mbps":1000,
                    "down_mbps":1000
                }
            }
        }
    ]
}
EOF
  fi

  # 生成 Trojan 配置
  CHECK_PROTOCOLS=$(asc "$CHECK_PROTOCOLS" ++)
  if [[ "${INSTALL_PROTOCOLS[@]}" =~ "$CHECK_PROTOCOLS" ]]; then
    [ -z "$PORT_TROJAN" ] && PORT_TROJAN=$[START_PORT+$(awk -v target=$CHECK_PROTOCOLS '{ for(i=1; i<=NF; i++) if($i == target) { print i-1; break } }' <<< "${INSTALL_PROTOCOLS[*]}")]
    NODE_NAME[16]=${NODE_NAME[16]:-"$NODE_NAME_CONFIRM"} && TROJAN_PASSWORD=${TROJAN_PASSWORD:-"$UUID_CONFIRM"}
    open_firewall_port ${PORT_TROJAN}
    cat > $WORK_DIR_SUB/conf/16_${NODE_TAG[5]}_inbounds.json << EOF
{
    "inbounds":[
        {
            "type":"trojan",
            "sniff":true,
            "sniff_override_destination":true,
            "tag":"${NODE_NAME[16]} ${NODE_TAG[5]}",
            "listen":"::",
            "listen_port":$PORT_TROJAN,
            "users":[
                {
                    "password":"$TROJAN_PASSWORD"
                }
            ],
            "tls":{
                "enabled":true,
                "certificate_path":"$WORK_DIR_SUB/cert/cert.pem",
                "key_path":"$WORK_DIR_SUB/cert/private.key"
            },
            "multiplex":{
                "enabled":true,
                "padding":true,
                "brutal":{
                    "enabled":true,
                    "up_mbps":1000,
                    "down_mbps":1000
                }
            }
        }
    ]
}
EOF
  fi

  # 生成 vmess + ws 配置
  CHECK_PROTOCOLS=$(asc "$CHECK_PROTOCOLS" ++)
  if [[ "${INSTALL_PROTOCOLS[@]}" =~ "$CHECK_PROTOCOLS" ]]; then
    [ -z "$PORT_VMESS_WS" ] && PORT_VMESS_WS=$[START_PORT+$(awk -v target=$CHECK_PROTOCOLS '{ for(i=1; i<=NF; i++) if($i == target) { print i-1; break } }' <<< "${INSTALL_PROTOCOLS[*]}")]
    NODE_NAME[17]=${NODE_NAME[17]:-"$NODE_NAME_CONFIRM"} && UUID[17]=${UUID[17]:-"$UUID_CONFIRM"} && WS_SERVER_IP[17]=${WS_SERVER_IP[17]:-"$SERVER_IP"} && CDN[17]=${CDN[17]:-"$CDN"} && VMESS_WS_PATH=${VMESS_WS_PATH:-"${UUID[17]}-vmess"}
    open_firewall_port ${PORT_VMESS_WS}
    cat > $WORK_DIR_SUB/conf/17_${NODE_TAG[6]}_inbounds.json << EOF
//  "WS_SERVER_IP_SHOW": "${WS_SERVER_IP[17]}"
//  "VMESS_HOST_DOMAIN": "$VMESS_HOST_DOMAIN"
//  "CDN": "${CDN[17]}"
{
    "inbounds":[
        {
            "type":"vmess",
            "sniff":true,
            "sniff_override_destination":true,
            "tag":"${NODE_NAME[17]} ${NODE_TAG[6]}",
            "listen":"::",
            "listen_port":$PORT_VMESS_WS,
            "tcp_fast_open":false,
            "proxy_protocol":false,
            "users":[
                {
                    "uuid":"${UUID[17]}",
                    "alterId":0
                }
            ],
            "transport":{
                "type":"ws",
                "path":"/$VMESS_WS_PATH",
                "max_early_data":2048,
                "early_data_header_name":"Sec-WebSocket-Protocol"
            },
            "multiplex":{
                "enabled":true,
                "padding":true,
                "brutal":{
                    "enabled":true,
                    "up_mbps":1000,
                    "down_mbps":1000
                }
            }
        }
    ]
}
EOF
  fi

  # 生成 vless + ws + tls 配置
  CHECK_PROTOCOLS=$(asc "$CHECK_PROTOCOLS" ++)
  if [[ "${INSTALL_PROTOCOLS[@]}" =~ "$CHECK_PROTOCOLS" ]]; then
    [ -z "$PORT_VLESS_WS" ] && PORT_VLESS_WS=$[START_PORT+$(awk -v target=$CHECK_PROTOCOLS '{ for(i=1; i<=NF; i++) if($i == target) { print i-1; break } }' <<< "${INSTALL_PROTOCOLS[*]}")]
    NODE_NAME[18]=${NODE_NAME[18]:-"$NODE_NAME_CONFIRM"} && UUID[18]=${UUID[18]:-"$UUID_CONFIRM"} && WS_SERVER_IP[18]=${WS_SERVER_IP[18]:-"$SERVER_IP"} && CDN[18]=${CDN[18]:-"$CDN"} && VLESS_WS_PATH=${VLESS_WS_PATH:-"${UUID[18]}-vless"}
    open_firewall_port ${PORT_VLESS_WS}
    cat > $WORK_DIR_SUB/conf/18_${NODE_TAG[7]}_inbounds.json << EOF
//  "WS_SERVER_IP_SHOW": "${WS_SERVER_IP[18]}"
//  "CDN": "${CDN[18]}"
{
    "inbounds":[
        {
            "type":"vless",
            "sniff_override_destination":true,
            "sniff":true,
            "tag":"${NODE_NAME[18]} ${NODE_TAG[7]}",
            "listen":"::",
            "listen_port":$PORT_VLESS_WS,
            "tcp_fast_open":false,
            "proxy_protocol":false,
            "users":[
                {
                    "name":"sing-box",
                    "uuid":"${UUID[18]}"
                }
            ],
            "transport":{
                "type":"ws",
                "path":"/$VLESS_WS_PATH",
                "max_early_data":2048,
                "early_data_header_name":"Sec-WebSocket-Protocol"
            },
            "tls":{
                "enabled":true,
                "server_name":"$VLESS_HOST_DOMAIN",
                "min_version":"1.3",
                "max_version":"1.3",
                "certificate_path":"${WORK_DIR_SUB}/cert/cert.pem",
                "key_path":"${WORK_DIR_SUB}/cert/private.key"
            },
            "multiplex":{
                "enabled":true,
                "padding":true,
                "brutal":{
                    "enabled":true,
                    "up_mbps":1000,
                    "down_mbps":1000
                }
            }
        }
    ]
}
EOF
  fi

  # 生成 H2 + Reality 配置
  CHECK_PROTOCOLS=$(asc "$CHECK_PROTOCOLS" ++)
  if [[ "${INSTALL_PROTOCOLS[@]}" =~ "$CHECK_PROTOCOLS" ]]; then
    [ -z "$PORT_H2_REALITY" ] && PORT_H2_REALITY=$[START_PORT+$(awk -v target=$CHECK_PROTOCOLS '{ for(i=1; i<=NF; i++) if($i == target) { print i-1; break } }' <<< "${INSTALL_PROTOCOLS[*]}")]
    NODE_NAME[19]=${NODE_NAME[19]:-"$NODE_NAME_CONFIRM"} && UUID[19]=${UUID[19]:-"$UUID_CONFIRM"} && TLS_SERVER[19]=${TLS_SERVER[19]:-"$TLS_SERVER"} && REALITY_PRIVATE[19]=${REALITY_PRIVATE[19]:-"$REALITY_PRIVATE"} && REALITY_PUBLIC[19]=${REALITY_PUBLIC[19]:-"$REALITY_PUBLIC"}
    open_firewall_port ${PORT_H2_REALITY}
    cat > $WORK_DIR_SUB/conf/19_${NODE_TAG[8]}_inbounds.json << EOF
//  "public_key":"${REALITY_PUBLIC[19]}"
{
    "inbounds":[
        {
            "type":"vless",
            "sniff":true,
            "sniff_override_destination":true,
            "tag":"${NODE_NAME[19]} ${NODE_TAG[8]}",
            "listen":"::",
            "listen_port":$PORT_H2_REALITY,
            "users":[
                {
                    "uuid":"${UUID[19]}"
                }
            ],
            "tls":{
                "enabled":true,
                "server_name":"${TLS_SERVER[19]}",
                "reality":{
                    "enabled":true,
                    "handshake":{
                        "server":"${TLS_SERVER[19]}",
                        "server_port":443
                    },
                    "private_key":"${REALITY_PRIVATE[19]}",
                    "short_id":[
                        ""
                    ]
                }
            },
            "transport": {
                "type": "http"
            },
            "multiplex":{
                "enabled":true,
                "padding":true,
                "brutal":{
                    "enabled":true,
                    "up_mbps":1000,
                    "down_mbps":1000
                }
            }
        }
    ]
}
EOF
  fi

  # 生成 gRPC + Reality 配置
  CHECK_PROTOCOLS=$(asc "$CHECK_PROTOCOLS" ++)
  if [[ "${INSTALL_PROTOCOLS[@]}" =~ "$CHECK_PROTOCOLS" ]]; then
    [ -z "$PORT_GRPC_REALITY" ] && PORT_GRPC_REALITY=$[START_PORT+$(awk -v target=$CHECK_PROTOCOLS '{ for(i=1; i<=NF; i++) if($i == target) { print i-1; break } }' <<< "${INSTALL_PROTOCOLS[*]}")]
    NODE_NAME[20]=${NODE_NAME[20]:-"$NODE_NAME_CONFIRM"} && UUID[20]=${UUID[20]:-"$UUID_CONFIRM"} && TLS_SERVER[20]=${TLS_SERVER[20]:-"$TLS_SERVER"} && REALITY_PRIVATE[20]=${REALITY_PRIVATE[20]:-"$REALITY_PRIVATE"} && REALITY_PUBLIC[20]=${REALITY_PUBLIC[20]:-"$REALITY_PUBLIC"}
    open_firewall_port ${PORT_GRPC_REALITY}
    cat > $WORK_DIR_SUB/conf/20_${NODE_TAG[9]}_inbounds.json << EOF
//  "public_key":"${REALITY_PUBLIC[20]}"
{
    "inbounds":[
        {
            "type":"vless",
            "sniff":true,
            "sniff_override_destination":true,
            "tag":"${NODE_NAME[20]} ${NODE_TAG[9]}",
            "listen":"::",
            "listen_port":$PORT_GRPC_REALITY,
            "users":[
                {
                    "uuid":"${UUID[20]}"
                }
            ],
            "tls":{
                "enabled":true,
                "server_name":"${TLS_SERVER[20]}",
                "reality":{
                    "enabled":true,
                    "handshake":{
                        "server":"${TLS_SERVER[20]}",
                        "server_port":443
                    },
                    "private_key":"${REALITY_PRIVATE[20]}",
                    "short_id":[
                        ""
                    ]
                }
            },
            "transport": {
                "type": "grpc",
                "service_name": "grpc"
            },
            "multiplex":{
                "enabled":true,
                "padding":true,
                "brutal":{
                    "enabled":true,
                    "up_mbps":1000,
                    "down_mbps":1000
                }
            }
        }
    ]
}
EOF
  fi
}

# Sing-box 生成守护进程文件
sing_box_systemd() {
  SING_BOX_SERVICE="[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
User=root
Type=simple
NoNewPrivileges=yes
TimeoutStartSec=0
WorkingDirectory=$WORK_DIR_SUB
"
  SING_BOX_SERVICE+="ExecStart=$WORK_DIR_SUB/sing-box run -C $WORK_DIR_SUB/conf/
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target"

  echo "$SING_BOX_SERVICE" > /etc/systemd/system/sing-box.service
}

# 获取原有各协议的参数，先清空所有的 key-value
fetch_nodes_value() {
  unset FILE NODE_NAME PORT_XTLS_REALITY UUID TLS_SERVER REALITY_PRIVATE REALITY_PUBLIC PORT_HYSTERIA2 OBFS PORT_TUIC TUIC_PASSWORD TUIC_CONGESTION_CONTROL PORT_SHADOWTLS SHADOWTLS_PASSWORD SHADOWSOCKS_METHOD PORT_SHADOWSOCKS PORT_TROJAN TROJAN_PASSWORD PORT_VMESS_WS VMESS_WS_PATH WS_SERVER_IP WS_SERVER_IP_SHOW VMESS_HOST_DOMAIN CDN PORT_VLESS_WS VLESS_WS_PATH VLESS_HOST_DOMAIN PORT_H2_REALITY PORT_GRPC_REALITY

  # 获取公共数据
  ls $WORK_DIR_SUB/conf/*-ws*inbounds.json >/dev/null 2>&1 && SERVER_IP=$(awk -F '"' '/"WS_SERVER_IP_SHOW"/{print $4; exit}' $WORK_DIR_SUB/conf/*-ws*inbounds.json) || SERVER_IP=$(grep -A1 '"tag"' $WORK_DIR_SUB/list | sed -E '/-ws(-tls)*",$/{N;d}' | awk -F '"' '/"server"/{count++; if (count == 1) {print $4; exit}}')
  EXISTED_PORTS=$(awk -F ':|,' '/listen_port/{print $2}' $WORK_DIR_SUB/conf/*_inbounds.json)
  START_PORT=$(awk 'NR == 1 { min = $0 } { if ($0 < min) min = $0; count++ } END {print min}' <<< "$EXISTED_PORTS")

  # 获取 XTLS + Reality key-value
  [ -s $WORK_DIR_SUB/conf/*_${NODE_TAG[0]}_inbounds.json ] && local JSON=$(cat $WORK_DIR_SUB/conf/*_${NODE_TAG[0]}_inbounds.json) && NODE_NAME[11]=$(sed -n "s/.*\"tag\":\"\(.*\) ${NODE_TAG[0]}.*/\1/p" <<< "$JSON") && PORT_XTLS_REALITY=$(sed -n 's/.*"listen_port":\([0-9]\+\),/\1/gp' <<< "$JSON") && UUID[11]=$(awk -F '"' '/"uuid"/{print $4}' <<< "$JSON") && TLS_SERVER[11]=$(awk -F '"' '/"server_name"/{print $4}' <<< "$JSON") && REALITY_PRIVATE[11]=$(awk -F '"' '/"private_key"/{print $4}' <<< "$JSON") && REALITY_PUBLIC[11]=$(awk -F '"' '/"public_key"/{print $4}' <<< "$JSON")

  # 获取 Hysteria2 key-value
  [ -s $WORK_DIR_SUB/conf/*_${NODE_TAG[1]}_inbounds.json ] && local JSON=$(cat $WORK_DIR_SUB/conf/*_${NODE_TAG[1]}_inbounds.json) && NODE_NAME[12]=$(sed -n "s/.*\"tag\":\"\(.*\) ${NODE_TAG[1]}.*/\1/p" <<< "$JSON") && PORT_HYSTERIA2=$(sed -n 's/.*"listen_port":\([0-9]\+\),/\1/gp' <<< "$JSON") && UUID[12]=$(awk -F '"' '/"password"/{count++; if (count == 1) {print $4; exit}}' <<< "$JSON")

  # 获取 Tuic V5 key-value
  [ -s $WORK_DIR_SUB/conf/*_${NODE_TAG[2]}_inbounds.json ] && local JSON=$(cat $WORK_DIR_SUB/conf/*_${NODE_TAG[2]}_inbounds.json) && NODE_NAME[13]=$(sed -n "s/.*\"tag\":\"\(.*\) ${NODE_TAG[2]}.*/\1/p" <<< "$JSON") && PORT_TUIC=$(sed -n 's/.*"listen_port":\([0-9]\+\),/\1/gp' <<< "$JSON") && UUID[13]=$(awk -F '"' '/"uuid"/{print $4}' <<< "$JSON") && TUIC_PASSWORD=$(awk -F '"' '/"password"/{print $4}' <<< "$JSON") && TUIC_CONGESTION_CONTROL=$(awk -F '"' '/"congestion_control"/{print $4}' <<< "$JSON")

  # 获取 ShadowTLS key-value
  [ -s $WORK_DIR_SUB/conf/*_${NODE_TAG[3]}_inbounds.json ] && local JSON=$(cat $WORK_DIR_SUB/conf/*_${NODE_TAG[3]}_inbounds.json) && NODE_NAME[14]=$(sed -n "s/.*\"tag\":\"\(.*\) ${NODE_TAG[3]}.*/\1/p" <<< "$JSON") && PORT_SHADOWTLS=$(sed -n 's/.*"listen_port":\([0-9]\+\),/\1/gp' <<< "$JSON") && UUID[14]=$(awk -F '"' '/"password"/{count++; if (count == 1) {print $4; exit}}' <<< "$JSON") && SHADOWTLS_PASSWORD=$(awk -F '"' '/"password"/{count++; if (count == 2) {print $4; exit}}' <<< "$JSON") && TLS_SERVER[14]=$(awk -F '"' '/"server"/{print $4}' <<< "$JSON") && SHADOWTLS_METHOD=$(awk -F '"' '/"method"/{print $4}' <<< "$JSON")

  # 获取 Shadowsocks key-value
  [ -s $WORK_DIR_SUB/conf/*_${NODE_TAG[4]}_inbounds.json ] && local JSON=$(cat $WORK_DIR_SUB/conf/*_${NODE_TAG[4]}_inbounds.json) && NODE_NAME[15]=$(sed -n "s/.*\"tag\":\"\(.*\) ${NODE_TAG[4]}.*/\1/p" <<< "$JSON") && PORT_SHADOWSOCKS=$(sed -n 's/.*"listen_port":\([0-9]\+\),/\1/gp' <<< "$JSON") && UUID[15]=$(awk -F '"' '/"password"/{print $4}' <<< "$JSON") && SHADOWSOCKS_METHOD=$(awk -F '"' '/"method"/{print $4}' <<< "$JSON")

  # 获取 Trojan key-value
  [ -s $WORK_DIR_SUB/conf/*_${NODE_TAG[5]}_inbounds.json ] && local JSON=$(cat $WORK_DIR_SUB/conf/*_${NODE_TAG[5]}_inbounds.json) && NODE_NAME[16]=$(sed -n "s/.*\"tag\":\"\(.*\) ${NODE_TAG[5]}.*/\1/p" <<< "$JSON") && PORT_TROJAN=$(sed -n 's/.*"listen_port":\([0-9]\+\),/\1/gp' <<< "$JSON") && TROJAN_PASSWORD=$(awk -F '"' '/"password"/{print $4}' <<< "$JSON")

  # 获取 vmess + ws key-value
  [ -s $WORK_DIR_SUB/conf/*_${NODE_TAG[6]}_inbounds.json ] && local JSON=$(cat $WORK_DIR_SUB/conf/*_${NODE_TAG[6]}_inbounds.json) && NODE_NAME[17]=$(sed -n "s/.*\"tag\":\"\(.*\) ${NODE_TAG[6]}.*/\1/p" <<< "$JSON") && PORT_VMESS_WS=$(sed -n 's/.*"listen_port":\([0-9]\+\),/\1/gp' <<< "$JSON") && UUID[17]=$(awk -F '"' '/"uuid"/{print $4}' <<< "$JSON") && VMESS_WS_PATH=$(sed -n 's#.*"path":"/\(.*\)",#\1#p' <<< "$JSON") && WS_SERVER_IP[17]=$(awk  -F '"' '/"WS_SERVER_IP_SHOW"/{print $4}' <<< "$JSON") && VMESS_HOST_DOMAIN=$(awk  -F '"' '/"VMESS_HOST_DOMAIN"/{print $4}' <<< "$JSON") && CDN[17]=$(awk  -F '"' '/"CDN"/{print $4}' <<< "$JSON")

  # 获取 vless + ws + tls key-value
  [ -s $WORK_DIR_SUB/conf/*_${NODE_TAG[7]}_inbounds.json ] && local JSON=$(cat $WORK_DIR_SUB/conf/*_${NODE_TAG[7]}_inbounds.json) && NODE_NAME[18]=$(sed -n "s/.*\"tag\":\"\(.*\) ${NODE_TAG[7]}.*/\1/p" <<< "$JSON") && PORT_VLESS_WS=$(sed -n 's/.*"listen_port":\([0-9]\+\),/\1/gp' <<< "$JSON") && UUID[18]=$(awk -F '"' '/"uuid"/{print $4}' <<< "$JSON") && VLESS_WS_PATH=$(sed -n 's#.*"path":"/\(.*\)",#\1#p' <<< "$JSON") && WS_SERVER_IP[18]=$(awk  -F '"' '/"WS_SERVER_IP_SHOW"/{print $4}' <<< "$JSON") && VLESS_HOST_DOMAIN=$(awk -F '"' '/"server_name"/{print $4}' <<< "$JSON") && CDN[18]=$(awk  -F '"' '/"CDN"/{print $4}' <<< "$JSON")

  # 获取 H2 + Reality key-value
  [ -s $WORK_DIR_SUB/conf/*_${NODE_TAG[8]}_inbounds.json ] && local JSON=$(cat $WORK_DIR_SUB/conf/*_${NODE_TAG[8]}_inbounds.json) && NODE_NAME[19]=$(sed -n "s/.*\"tag\":\"\(.*\) ${NODE_TAG[8]}.*/\1/p" <<< "$JSON") && PORT_H2_REALITY=$(sed -n 's/.*"listen_port":\([0-9]\+\),/\1/gp' <<< "$JSON") && UUID[19]=$(awk -F '"' '/"uuid"/{print $4}' <<< "$JSON") && TLS_SERVER[19]=$(awk -F '"' '/"server"/{print $4}' <<< "$JSON") && REALITY_PRIVATE[19]=$(awk -F '"' '/"private_key"/{print $4}' <<< "$JSON") && REALITY_PUBLIC[19]=$(awk -F '"' '/"public_key"/{print $4}' <<< "$JSON")

  # 获取 gRPC + Reality key-value
  [ -s $WORK_DIR_SUB/conf/*_${NODE_TAG[9]}_inbounds.json ] && local JSON=$(cat $WORK_DIR_SUB/conf/*_${NODE_TAG[9]}_inbounds.json) && NODE_NAME[20]=$(sed -n "s/.*\"tag\":\"\(.*\) ${NODE_TAG[9]}.*/\1/p" <<< "$JSON") && PORT_GRPC_REALITY=$(sed -n 's/.*"listen_port":\([0-9]\+\),/\1/gp' <<< "$JSON") && UUID[20]=$(awk -F '"' '/"uuid"/{print $4}' <<< "$JSON") && TLS_SERVER[20]=$(awk -F '"' '/"server"/{print $4}' <<< "$JSON") && REALITY_PRIVATE[20]=$(awk -F '"' '/"private_key"/{print $4}' <<< "$JSON") && REALITY_PUBLIC[20]=$(awk -F '"' '/"public_key"/{print $4}' <<< "$JSON")
}

install_sing_box() {
  sing_box_variables
  [ ! -d /etc/systemd/system ] && mkdir -p /etc/systemd/system
  [ ! -d $WORK_DIR_SUB/logs ] && mkdir -p $WORK_DIR_SUB/logs
  ssl_certificate
  [ "$SYSTEM" = 'CentOS' ] && check_firewall_configuration
  listchoice "\n 下载 Sing-box 中，请稍等 ... " && wait
  sing_box_json
  echo "${L^^}" > $WORK_DIR_SUB/language
  cp $TEMP_DIR/sing-box $TEMP_DIR/jq $WORK_DIR_SUB

  # 生成 sing-box systemd 配置文件
  sing_box_systemd

  # 如果 Alpine 系统，放到开机自启动
  if [ "$SYSTEM" = 'Alpine' ]; then
    cat > /etc/local.d/sing-box.start << EOF
#!/usr/bin/env bash

systemctl start sing-box
EOF
    chmod +x /etc/local.d/sing-box.start
    rc-update add local >/dev/null 2>&1
  fi

  # 等待所有后台进程完成后,再次检测状态，运行 Sing-box
  check_install
  sleep 1
  check_sing_box_status
}

export_list() {
  IS_INSTALL=$1

  check_install

  [ "$IS_INSTALL" != 'install' ] && fetch_nodes_value

  # IPv6 时的 IP 处理
  if [[ "$SERVER_IP" =~ : ]]; then
    SERVER_IP_1="[$SERVER_IP]"
    SERVER_IP_2="[[$SERVER_IP]]"
  else
    SERVER_IP_1="$SERVER_IP"
    SERVER_IP_2="$SERVER_IP"
  fi

  # 生成各订阅文件
  # 生成 Clash proxy providers 订阅文件
  local CLASH_SUBSCRIBE='proxies:'

  [ -n "$PORT_XTLS_REALITY" ] && local CLASH_XTLS_REALITY="- {name: \"${NODE_NAME[11]} ${NODE_TAG[0]}\", type: vless, server: ${SERVER_IP}, port: ${PORT_XTLS_REALITY}, uuid: ${UUID[11]}, network: tcp, udp: true, tls: true, servername: ${TLS_SERVER[11]}, client-fingerprint: chrome, reality-opts: {public-key: ${REALITY_PUBLIC[11]}, short-id: \"\"}, smux: { enabled: true, protocol: 'h2mux', padding: true, max-connections: '8', min-streams: '16', statistic: true, only-tcp: false } }" &&
  local CLASH_SUBSCRIBE+="
  $CLASH_XTLS_REALITY
"
  [ -n "$PORT_HYSTERIA2" ] && local CLASH_HYSTERIA2="- {name: \"${NODE_NAME[12]} ${NODE_TAG[1]}\", type: hysteria2, server: ${SERVER_IP}, port: ${PORT_HYSTERIA2}, up: \"200 Mbps\", down: \"1000 Mbps\", password: ${UUID[12]}, skip-cert-verify: true}" &&
  local CLASH_SUBSCRIBE+="
  - {name: \"${NODE_NAME[12]} ${NODE_TAG[1]}\", type: hysteria2, server: ${SERVER_IP}, port: ${PORT_HYSTERIA2}, up: \"200 Mbps\", down: \"1000 Mbps\", password: ${UUID[12]}, skip-cert-verify: true}
"
  [ -n "$PORT_TUIC" ] && local CLASH_TUIC="- {name: \"${NODE_NAME[13]} ${NODE_TAG[2]}\", type: tuic, server: ${SERVER_IP}, port: ${PORT_TUIC}, uuid: ${UUID[13]}, password: ${TUIC_PASSWORD}, alpn: [h3], disable-sni: true, reduce-rtt: true, request-timeout: 8000, udp-relay-mode: native, congestion-controller: $TUIC_CONGESTION_CONTROL, skip-cert-verify: true}" &&
  local CLASH_SUBSCRIBE+="
  $CLASH_TUIC
"
  [ -n "$PORT_SHADOWTLS" ] && local CLASH_SHADOWTLS="- {name: \"${NODE_NAME[14]} ${NODE_TAG[3]}\", type: ss, server: ${SERVER_IP}, port: ${PORT_SHADOWTLS}, cipher: $SHADOWTLS_METHOD, password: $SHADOWTLS_PASSWORD, plugin: shadow-tls, client-fingerprint: chrome, plugin-opts: {host: ${TLS_SERVER[14]}, password: \"${UUID[14]}\", version: 3}, smux: { enabled: true, protocol: 'h2mux', padding: true, max-connections: '8', min-streams: '16', statistic: true, only-tcp: false } }" &&
  local CLASH_SUBSCRIBE+="
  $CLASH_SHADOWTLS
"

  [ -n "$PORT_SHADOWSOCKS" ] && local CLASH_SHADOWSOCKS="- {name: \"${NODE_NAME[15]} ${NODE_TAG[4]}\", type: ss, server: ${SERVER_IP}, port: $PORT_SHADOWSOCKS, cipher: ${SHADOWSOCKS_METHOD}, password: ${UUID[15]}, smux: { enabled: true, protocol: 'h2mux', padding: true, max-connections: '8', min-streams: '16', statistic: true, only-tcp: false } }" &&
  local CLASH_SUBSCRIBE+="
  $CLASH_SHADOWSOCKS
"
  [ -n "$PORT_TROJAN" ] && local CLASH_TROJAN="- {name: \"${NODE_NAME[16]} ${NODE_TAG[5]}\", type: trojan, server: ${SERVER_IP}, port: $PORT_TROJAN, password: $TROJAN_PASSWORD, client-fingerprint: random, skip-cert-verify: true, smux: { enabled: true, protocol: 'h2mux', padding: true, max-connections: '8', min-streams: '16', statistic: true, only-tcp: false } }" &&
  local CLASH_SUBSCRIBE+="
  $CLASH_TROJAN
"
  [ -n "$PORT_VMESS_WS" ] && local CLASH_VMESS_WS="- {name: \"${NODE_NAME[17]} ${NODE_TAG[6]}\", type: vmess, server: ${CDN[17]}, port: 80, uuid: ${UUID[17]}, udp: true, tls: false, alterId: 0, cipher: none, skip-cert-verify: true, network: ws, ws-opts: { path: \"/$VMESS_WS_PATH\", headers: {Host: $VMESS_HOST_DOMAIN} }, smux: { enabled: true, protocol: 'h2mux', padding: true, max-connections: '8', min-streams: '16', statistic: true, only-tcp: false } }" &&
  local WS_SERVER_IP_SHOW=${WS_SERVER_IP[17]} && local TYPE_HOST_DOMAIN=$VMESS_HOST_DOMAIN && local TYPE_PORT_WS=$PORT_VMESS_WS &&
  local CLASH_SUBSCRIBE+="
  $CLASH_VMESS_WS

  # 请在 Cloudflare 绑定 \[\${WS_SERVER_IP_SHOW}] 的域名为 \[\${TYPE_HOST_DOMAIN}], 并设置 origin rule 为 \[\${TYPE_PORT_WS}]
"
  [ -n "$PORT_VLESS_WS" ] && local CLASH_VLESS_WS="- {name: \"${NODE_NAME[18]} ${NODE_TAG[7]}\", type: vless, server: ${CDN[18]}, port: 443, uuid: ${UUID[18]}, udp: true, tls: true, servername: $VLESS_HOST_DOMAIN, network: ws, skip-cert-verify: true, ws-opts: { path: \"/$VLESS_WS_PATH\", headers: {Host: $VLESS_HOST_DOMAIN}, max-early-data: 2048, early-data-header-name: Sec-WebSocket-Protocol }, smux: { enabled: true, protocol: 'h2mux', padding: true, max-connections: '8', min-streams: '16', statistic: true, only-tcp: false } }" &&
  local WS_SERVER_IP_SHOW=${WS_SERVER_IP[18]} && local TYPE_HOST_DOMAIN=$VLESS_HOST_DOMAIN && local TYPE_PORT_WS=$PORT_VLESS_WS &&
  local CLASH_SUBSCRIBE+="
  $CLASH_VLESS_WS

  # 请在 Cloudflare 绑定 \[\${WS_SERVER_IP_SHOW}] 的域名为 \[\${TYPE_HOST_DOMAIN}], 并设置 origin rule 为 \[\${TYPE_PORT_WS}]
"
  # Clash 的 H2 传输层未实现多路复用功能，在 Clash.Meta 中更建议使用 gRPC 协议，故不输出相关配置。 https://wiki.metacubex.one/config/proxies/vless/
  [ -n "$PORT_H2_REALITY" ]

  [ -n "$PORT_GRPC_REALITY" ] && local CLASH_GRPC_REALITY="- {name: \"${NODE_NAME[20]} ${NODE_TAG[9]}\", type: vless, server: ${SERVER_IP}, port: ${PORT_GRPC_REALITY}, uuid: ${UUID[20]}, network: grpc, tls: true, udp: true, flow:, client-fingerprint: chrome, servername: ${TLS_SERVER[20]}, grpc-opts: {  grpc-service-name: \"grpc\" }, reality-opts: { public-key: ${REALITY_PUBLIC[20]}, short-id: \"\" }, smux: { enabled: true, protocol: 'h2mux', padding: true, max-connections: '8', min-streams: '16', statistic: true, only-tcp: false } }" &&
  local CLASH_SUBSCRIBE+="
  $CLASH_GRPC_REALITY
"
  echo -n "${CLASH_SUBSCRIBE}" | sed -E '/^[ ]*#|^--/d' | sed '/^$/d' > $WORK_DIR_SUB/subscribe/proxies

  # 生成 clash 订阅配置文件
  # 模板1: 使用 proxy providers
  wget --no-check-certificate -qO- --tries=3 --timeout=2 ${SUBSCRIBE_TEMPLATE}/clash | sed "s#NODE_NAME#${NODE_NAME_CONFIRM}#g; s#PROXY_PROVIDERS_URL#http://${SERVER_IP_1}:${PORT_NGINX}/${UUID_CONFIRM}/proxies#" > $WORK_DIR_SUB/subscribe/clash

  # 模板2: 不使用 proxy providers
  CLASH2_PORT=("$PORT_XTLS_REALITY" "$PORT_HYSTERIA2" "$PORT_TUIC" "$PORT_SHADOWTLS" "$PORT_SHADOWSOCKS" "$PORT_TROJAN" "$PORT_VMESS_WS" "$PORT_VLESS_WS" "$PORT_GRPC_REALITY")
  CLASH2_PROXY_INSERT=("$CLASH_XTLS_REALITY" "$CLASH_HYSTERIA2" "$CLASH_TUIC" "$CLASH_SHADOWTLS" "$CLASH_SHADOWSOCKS" "$CLASH_TROJAN" "$CLASH_VMESS_WS" "$CLASH_VLESS_WS" "$CLASH_GRPC_REALITY")
  CLASH2_PROXY_GROUPS_INSERT=("- ${NODE_NAME[11]} ${NODE_TAG[0]}" "- ${NODE_NAME[12]} ${NODE_TAG[1]}" "- ${NODE_NAME[13]} ${NODE_TAG[2]}" "- ${NODE_NAME[14]} ${NODE_TAG[3]}" "- ${NODE_NAME[15]} ${NODE_TAG[4]}" "- ${NODE_NAME[16]} ${NODE_TAG[5]}" "- ${NODE_NAME[17]} ${NODE_TAG[6]}" "- ${NODE_NAME[18]} ${NODE_TAG[7]}" "- ${NODE_NAME[20]} ${NODE_TAG[9]}")

  CLASH2_YAML=$(wget --no-check-certificate -qO- --tries=3 --timeout=2 ${SUBSCRIBE_TEMPLATE}/clash2)
  for x in ${!CLASH2_PORT[@]}; do
    [[ ${CLASH2_PORT[x]} =~ [0-9]+ ]] && CLASH2_YAML=$(sed "/proxy-groups:/i\  ${CLASH2_PROXY_INSERT[x]}" <<< "$CLASH2_YAML" >/dev/null 2>&1) && CLASH2_YAML=$(sed -E "/- name: (♻️ 自动选择|📲 电报消息|💬 OpenAi|📹 油管视频|🎥 奈飞视频|📺 巴哈姆特|📺 哔哩哔哩|🌍 国外媒体|🌏 国内媒体|📢 谷歌FCM|Ⓜ️ 微软Bing|Ⓜ️ 微软云盘|Ⓜ️ 微软服务|🍎 苹果服务|🎮 游戏平台|🎶 网易音乐|🎯 全球直连)|^rules:$/i\      ${CLASH2_PROXY_GROUPS_INSERT[x]}" <<< "$CLASH2_YAML" >/dev/null 2>&1)
  done
  echo "$CLASH2_YAML" > $WORK_DIR_SUB/subscribe/clash2

  # 生成 ShadowRocket 订阅配置文件
  [ -n "$PORT_XTLS_REALITY" ] && local SHADOWROCKET_SUBSCRIBE+="
vless://$(echo -n "auto:${UUID[11]}@${SERVER_IP_2}:${PORT_XTLS_REALITY}" | base64 -w0)?remarks=${NODE_NAME[11]} ${NODE_TAG[0]}&obfs=none&tls=1&peer=${TLS_SERVER[11]}&mux=1&pbk=${REALITY_PUBLIC[11]}
"
  [ -n "$PORT_HYSTERIA2" ] && local SHADOWROCKET_SUBSCRIBE+="
hysteria2://${UUID[12]}@${SERVER_IP_2}:${PORT_HYSTERIA2}?insecure=1&obfs=none#${NODE_NAME[12]}%20${NODE_TAG[1]}
"
  [ -n "$PORT_TUIC" ] && local SHADOWROCKET_SUBSCRIBE+="
tuic://${TUIC_PASSWORD}:${UUID[13]}@${SERVER_IP_2}:${PORT_TUIC}?congestion_control=$TUIC_CONGESTION_CONTROL&udp_relay_mode=native&alpn=h3&allow_insecure=1#${NODE_NAME[13]}%20${NODE_TAG[2]}
"
  [ -n "$PORT_SHADOWTLS" ] && local SHADOWROCKET_SUBSCRIBE+="
ss://$(echo -n "$SHADOWTLS_METHOD:$SHADOWTLS_PASSWORD@${SERVER_IP_2}:${PORT_SHADOWTLS}" | base64 -w0)?shadow-tls=$(echo -n "{\"version\":\"3\",\"host\":\"${TLS_SERVER[14]}\",\"password\":\"${UUID[14]}\"}" | base64 -w0)#${NODE_NAME[14]}%20${NODE_TAG[3]}
"
  [ -n "$PORT_SHADOWSOCKS" ] && local SHADOWROCKET_SUBSCRIBE+="
ss://$(echo -n "${SHADOWSOCKS_METHOD}:${UUID[15]}@${SERVER_IP_2}:$PORT_SHADOWSOCKS" | base64 -w0)#${NODE_NAME[15]}%20${NODE_TAG[4]}
"
  [ -n "$PORT_TROJAN" ] && local SHADOWROCKET_SUBSCRIBE+="
trojan://$TROJAN_PASSWORD@${SERVER_IP_1}:$PORT_TROJAN?allowInsecure=1#${NODE_NAME[16]}%20${NODE_TAG[5]}
"
  [ -n "$PORT_VMESS_WS" ] && WS_SERVER_IP_SHOW=${WS_SERVER_IP[17]} && TYPE_HOST_DOMAIN=$VMESS_HOST_DOMAIN && TYPE_PORT_WS=$PORT_VMESS_WS && local SHADOWROCKET_SUBSCRIBE+="
----------------------------
vmess://$(echo -n "none:${UUID[17]}@${CDN[17]}:80" | base64 -w0)?remarks=${NODE_NAME[17]}%20${NODE_TAG[6]}&obfsParam=$VMESS_HOST_DOMAIN&path=/$VMESS_WS_PATH&obfs=websocket&alterId=0

# 请在 Cloudflare 绑定 \[\${WS_SERVER_IP_SHOW}] 的域名为 \[\${TYPE_HOST_DOMAIN}], 并设置 origin rule 为 \[\${TYPE_PORT_WS}]
"
  [ -n "$PORT_VLESS_WS" ] && WS_SERVER_IP_SHOW=${WS_SERVER_IP[18]} && TYPE_HOST_DOMAIN=$VLESS_HOST_DOMAIN && TYPE_PORT_WS=$PORT_VLESS_WS && local SHADOWROCKET_SUBSCRIBE+="
----------------------------
vless://$(echo -n "auto:${UUID[18]}@${CDN[18]}:443" | base64 -w0)?remarks=${NODE_NAME[18]}%20${NODE_TAG[7]}&obfsParam=$VLESS_HOST_DOMAIN&path=/$VLESS_WS_PATH?ed=2048&obfs=websocket&tls=1&peer=$VLESS_HOST_DOMAIN&allowInsecure=1

# 请在 Cloudflare 绑定 \[\${WS_SERVER_IP_SHOW}] 的域名为 \[\${TYPE_HOST_DOMAIN}], 并设置 origin rule 为 \[\${TYPE_PORT_WS}]
"
  [ -n "$PORT_H2_REALITY" ] && local SHADOWROCKET_SUBSCRIBE+="
----------------------------
vless://$(echo -n auto:${UUID[19]}@${SERVER_IP_2}:${PORT_H2_REALITY} | base64 -w0)?remarks=${NODE_NAME[19]}%20${NODE_TAG[8]}&path=/&obfs=h2&tls=1&peer=${TLS_SERVER[19]}&alpn=h2&mux=1&pbk=${REALITY_PUBLIC[19]}
"
  [ -n "$PORT_GRPC_REALITY" ] && local SHADOWROCKET_SUBSCRIBE+="
vless://$(echo -n "auto:${UUID[20]}@${SERVER_IP_2}:${PORT_GRPC_REALITY}" | base64 -w0)?remarks=${NODE_NAME[20]}%20${NODE_TAG[9]}&path=grpc&obfs=grpc&tls=1&peer=${TLS_SERVER[20]}&pbk=${REALITY_PUBLIC[20]}
"
  echo -n "$SHADOWROCKET_SUBSCRIBE" | sed -E '/^[ ]*#|^--/d' | sed '/^$/d' | base64 -w0 > $WORK_DIR_SUB/subscribe/shadowrocket

  # 生成 V2rayN 订阅文件
  [ -n "$PORT_XTLS_REALITY" ] && local V2RAYN_SUBSCRIBE+="
----------------------------
vless://${UUID[11]}@${SERVER_IP_1}:${PORT_XTLS_REALITY}?encryption=none&security=reality&sni=${TLS_SERVER[11]}&fp=chrome&pbk=${REALITY_PUBLIC[11]}&type=tcp&headerType=none#${NODE_NAME[11]// /%20}"

  [ -n "$PORT_HYSTERIA2" ] && local V2RAYN_SUBSCRIBE+="
----------------------------
hysteria2://${UUID[12]}@${SERVER_IP_1}:${PORT_HYSTERIA2}/?alpn=h3&insecure=1#${NODE_NAME[12]// /%20}"

  [ -n "$PORT_TUIC" ] && local V2RAYN_SUBSCRIBE+="
----------------------------
tuic://${UUID[13]}:${TUIC_PASSWORD}@${SERVER_IP_1}:${PORT_TUIC}?alpn=h3&congestion_control=$TUIC_CONGESTION_CONTROL#${NODE_NAME[13]// /%20}

# 请把 tls 里的 inSecure 设置为 true"

  [ -n "$PORT_SHADOWTLS" ] && local V2RAYN_SUBSCRIBE+="
----------------------------
# ShadowTLS 配置文件内容，需要更新 sing_box 内核

{
  \"log\":{
      \"level\":\"warn\"
  },
  \"inbounds\":[
      {
          \"domain_strategy\":\"\",
          \"listen\":\"127.0.0.1\",
          \"listen_port\":${PORT_SHADOWTLS},
          \"sniff\":true,
          \"sniff_override_destination\":false,
          \"tag\": \"ShadowTLS\",
          \"type\":\"mixed\"
      }
  ],
  \"outbounds\":[
      {
          \"detour\":\"shadowtls-out\",
          \"domain_strategy\":\"\",
          \"method\":\"$SHADOWTLS_METHOD\",
          \"password\":\"$SHADOWTLS_PASSWORD\",
          \"type\":\"shadowsocks\",
          \"udp_over_tcp\": false,
          \"multiplex\": {
            \"enabled\": true,
            \"protocol\": \"h2mux\",
            \"max_connections\": 8,
            \"min_streams\": 16,
            \"padding\": true
          }
      },
      {
          \"domain_strategy\":\"\",
          \"password\":\"${UUID[14]}\",
          \"server\":\"${SERVER_IP}\",
          \"server_port\":${PORT_SHADOWTLS},
          \"tag\": \"shadowtls-out\",
          \"tls\":{
              \"enabled\":true,
              \"server_name\":\"${TLS_SERVER[14]}\",
              \"utls\": {
                \"enabled\": true,
                \"fingerprint\": \"chrome\"
              }
          },
          \"type\":\"shadowtls\",
          \"version\":3
      }
  ]
}"
  [ -n "$PORT_SHADOWSOCKS" ] && local V2RAYN_SUBSCRIBE+="
----------------------------
ss://$(echo -n "${SHADOWSOCKS_METHOD}:${UUID[15]}@${SERVER_IP_1}:$PORT_SHADOWSOCKS" | base64 -w0)#${NODE_NAME[15]// /%20}"

  [ -n "$PORT_TROJAN" ] && local V2RAYN_SUBSCRIBE+="
----------------------------
trojan://$TROJAN_PASSWORD@${SERVER_IP_1}:$PORT_TROJAN?security=tls&type=tcp&headerType=none#${NODE_NAME[16]// /%20}

# 请把 tls 里的 inSecure 设置为 true"

  [ -n "$PORT_VMESS_WS" ] && WS_SERVER_IP_SHOW=${WS_SERVER_IP[17]} && TYPE_HOST_DOMAIN=$VMESS_HOST_DOMAIN && TYPE_PORT_WS=$PORT_VMESS_WS && local V2RAYN_SUBSCRIBE+="
----------------------------
vmess://$(echo -n "{ \"v\": \"2\", \"ps\": \"${NODE_NAME[17]} ${NODE_TAG[6]}\", \"add\": \"${CDN[18]}\", \"port\": \"80\", \"id\": \"${UUID[18]}\", \"aid\": \"0\", \"scy\": \"none\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"$VMESS_HOST_DOMAIN\", \"path\": \"/$VMESS_WS_PATH\", \"tls\": \"\", \"sni\": \"\", \"alpn\": \"\" }" | base64 -w0)

# 请在 Cloudflare 绑定 \[\${WS_SERVER_IP_SHOW}] 的域名为 \[\${TYPE_HOST_DOMAIN}], 并设置 origin rule 为 \[\${TYPE_PORT_WS}]"

  [ -n "$PORT_VLESS_WS" ] && WS_SERVER_IP_SHOW=${WS_SERVER_IP[18]} && TYPE_HOST_DOMAIN=$VLESS_HOST_DOMAIN && TYPE_PORT_WS=$PORT_VLESS_WS && local V2RAYN_SUBSCRIBE+="
----------------------------
vless://${UUID[18]}@${CDN[18]}:443?encryption=none&security=tls&sni=$VLESS_HOST_DOMAIN&type=ws&host=$VLESS_HOST_DOMAIN&path=%2F$VLESS_WS_PATH%3Fed%3D2048#${NODE_NAME[18]// /%20}%20${NODE_TAG[7]}

# 请在 Cloudflare 绑定 \[\${WS_SERVER_IP_SHOW}] 的域名为 \[\${TYPE_HOST_DOMAIN}], 并设置 origin rule 为 \[\${TYPE_PORT_WS}]"

  [ -n "$PORT_H2_REALITY" ] && local V2RAYN_SUBSCRIBE+="
----------------------------
vless://${UUID[19]}@${SERVER_IP_1}:${PORT_H2_REALITY}?encryption=none&security=reality&sni=${TLS_SERVER[19]}&fp=chrome&pbk=${REALITY_PUBLIC[19]}&type=http#${NODE_NAME[19]// /%20}"

  [ -n "$PORT_GRPC_REALITY" ] && local V2RAYN_SUBSCRIBE+="
----------------------------
vless://${UUID[20]}@${SERVER_IP_1}:${PORT_GRPC_REALITY}?encryption=none&security=reality&sni=${TLS_SERVER[20]}&fp=chrome&pbk=${REALITY_PUBLIC[20]}&type=grpc&serviceName=grpc&mode=gun#${NODE_NAME[20]// /%20}"

  echo -n "$V2RAYN_SUBSCRIBE" | sed -E '/^[ ]*#|^[ ]+|^--|^\{|^\}/d' | sed '/^$/d' | base64 -w0 > $WORK_DIR_SUB/subscribe/V2rayN
  echo -e "$(echo -n "$V2RAYN_SUBSCRIBE" | sed -E '/^[ ]*#|^[ ]+|^--|^\{|^\}/d' | sed '/^$/d') \n" >> ~/Proxy.txt

  # 生成 NekoBox 订阅文件
  [ -n "$PORT_XTLS_REALITY" ] && local NEKOBOX_SUBSCRIBE+="
----------------------------
vless://${UUID[11]}@${SERVER_IP_1}:${PORT_XTLS_REALITY}?security=reality&sni=${TLS_SERVER[11]}&fp=chrome&pbk=${REALITY_PUBLIC[11]}&type=tcp&encryption=none#${NODE_NAME[11]}%20${NODE_TAG[0]}"

  [ -n "$PORT_HYSTERIA2" ] && local NEKOBOX_SUBSCRIBE+="
----------------------------
hy2://${UUID[12]}@${SERVER_IP_1}:${PORT_HYSTERIA2}?insecure=1#${NODE_NAME[12]} ${NODE_TAG[1]}"

  [ -n "$PORT_TUIC" ] && local NEKOBOX_SUBSCRIBE+="
----------------------------
tuic://${TUIC_PASSWORD}:${UUID[13]}@${SERVER_IP_1}:${PORT_TUIC}?congestion_control=$TUIC_CONGESTION_CONTROL&alpn=h3&udp_relay_mode=native&allow_insecure=1&disable_sni=1#${NODE_NAME[13]} ${NODE_TAG[2]}"

  [ -n "$PORT_SHADOWTLS" ] && local NEKOBOX_SUBSCRIBE+="
----------------------------
nekoray://custom#$(echo -n "{\"_v\":0,\"addr\":\"127.0.0.1\",\"cmd\":[\"\"],\"core\":\"internal\",\"cs\":\"{\n    \\\"password\\\": \\\"${UUID[14]}\\\",\n    \\\"server\\\": \\\"${SERVER_IP_1}\\\",\n    \\\"server_port\\\": ${PORT_SHADOWTLS},\n    \\\"tag\\\": \\\"shadowtls-out\\\",\n    \\\"tls\\\": {\n        \\\"enabled\\\": true,\n        \\\"server_name\\\": \\\"${TLS_SERVER[14]}\\\"\n    },\n    \\\"type\\\": \\\"shadowtls\\\",\n    \\\"version\\\": 3\n}\n\",\"mapping_port\":0,\"name\":\"1-tls-not-use\",\"port\":1080,\"socks_port\":0}" | base64 -w0)

nekoray://shadowsocks#$(echo -n "{\"_v\":0,\"method\":\"$SHADOWTLS_METHOD\",\"name\":\"2-ss-not-use\",\"pass\":\"$SHADOWTLS_PASSWORD\",\"port\":0,\"stream\":{\"ed_len\":0,\"insecure\":false,\"mux_s\":0,\"net\":\"tcp\"},\"uot\":0}" | base64 -w0)"

  [ -n "$PORT_SHADOWSOCKS" ] && local NEKOBOX_SUBSCRIBE+="
----------------------------
ss://$(echo -n "${SHADOWSOCKS_METHOD}:${UUID[15]}" | base64 -w0)@${SERVER_IP_1}:$PORT_SHADOWSOCKS#${NODE_NAME[15]} ${NODE_TAG[4]}"

  [ -n "$PORT_TROJAN" ] && local NEKOBOX_SUBSCRIBE+="
----------------------------
trojan://$TROJAN_PASSWORD@${SERVER_IP_1}:$PORT_TROJAN?security=tls&allowInsecure=1&fp=random&type=tcp#${NODE_NAME[16]} ${NODE_TAG[5]}"

  [ -n "$PORT_VMESS_WS" ] && WS_SERVER_IP_SHOW=${WS_SERVER_IP[17]} && TYPE_HOST_DOMAIN=$VMESS_HOST_DOMAIN && TYPE_PORT_WS=$PORT_VMESS_WS && local NEKOBOX_SUBSCRIBE+="
----------------------------
vmess://$(echo -n "{\"add\":\"${CDN[17]}\",\"aid\":\"0\",\"host\":\"$VMESS_HOST_DOMAIN\",\"id\":\"${UUID[17]}\",\"net\":\"ws\",\"path\":\"/$VMESS_WS_PATH\",\"port\":\"80\",\"ps\":\"${NODE_NAME[17]} ${NODE_TAG[6]}\",\"scy\":\"none\",\"sni\":\"\",\"tls\":\"\",\"type\":\"\",\"v\":\"2\"}" | base64 -w0)

# 请在 Cloudflare 绑定 \[\${WS_SERVER_IP_SHOW}] 的域名为 \[\${TYPE_HOST_DOMAIN}], 并设置 origin rule 为 \[\${TYPE_PORT_WS}]"

  [ -n "$PORT_VLESS_WS" ] && WS_SERVER_IP_SHOW=${WS_SERVER_IP[18]} && TYPE_HOST_DOMAIN=$VLESS_HOST_DOMAIN && TYPE_PORT_WS=$PORT_VLESS_WS && local NEKOBOX_SUBSCRIBE+="
----------------------------
vless://${UUID[18]}@${CDN[18]}:443?security=tls&sni=$VLESS_HOST_DOMAIN&type=ws&path=/$VLESS_WS_PATH?ed%3D2048&host=$VLESS_HOST_DOMAIN&encryption=none#${NODE_NAME[18]}%20${NODE_TAG[7]}

# 请在 Cloudflare 绑定 \[\${WS_SERVER_IP_SHOW}] 的域名为 \[\${TYPE_HOST_DOMAIN}], 并设置 origin rule 为 \[\${TYPE_PORT_WS}]"

  [ -n "$PORT_H2_REALITY" ] && local NEKOBOX_SUBSCRIBE+="
----------------------------
vless://${UUID[19]}@${SERVER_IP_1}:${PORT_H2_REALITY}?security=reality&sni=${TLS_SERVER[19]}&alpn=h2&fp=chrome&pbk=${REALITY_PUBLIC[19]}&type=http&encryption=none#${NODE_NAME[19]}%20${NODE_TAG[8]}"

  [ -n "$PORT_GRPC_REALITY" ] && local NEKOBOX_SUBSCRIBE+="
----------------------------
vless://${UUID[20]}@${SERVER_IP_1}:${PORT_GRPC_REALITY}?security=reality&sni=${TLS_SERVER[20]}&fp=chrome&pbk=${REALITY_PUBLIC[20]}&type=grpc&serviceName=grpc&encryption=none#${NODE_NAME[20]}%20${NODE_TAG[9]}"

  echo -n "$NEKOBOX_SUBSCRIBE" | sed -E '/^[ ]*#|^--/d' | sed '/^$/d' | base64 -w0 > $WORK_DIR_SUB/subscribe/neko

  # 生成 Sing-box 订阅文件
  [ -n "$PORT_XTLS_REALITY" ] &&
  local INBOUND_REPLACE+=" { \"type\": \"vless\", \"tag\": \"${NODE_NAME[11]} ${NODE_TAG[0]}\", \"server\":\"${SERVER_IP}\", \"server_port\":${PORT_XTLS_REALITY}, \"uuid\":\"${UUID[11]}\", \"flow\":\"\", \"packet_encoding\":\"xudp\", \"tls\":{ \"enabled\":true, \"server_name\":\"${TLS_SERVER[11]}\", \"utls\":{ \"enabled\":true, \"fingerprint\":\"chrome\" }, \"reality\":{ \"enabled\":true, \"public_key\":\"${REALITY_PUBLIC[11]}\", \"short_id\":\"\" } }, \"multiplex\": { \"enabled\": true, \"protocol\": \"h2mux\", \"max_connections\": 8, \"min_streams\": 16, \"padding\": true, \"brutal\":{ \"enabled\":true, \"up_mbps\":1000, \"down_mbps\":1000 } } }," &&
  local NODE_REPLACE+="\"${NODE_NAME[11]} ${NODE_TAG[0]}\","

  [ -n "$PORT_HYSTERIA2" ] &&
  local INBOUND_REPLACE+=" { \"type\": \"hysteria2\", \"tag\": \"${NODE_NAME[12]} ${NODE_TAG[1]}\", \"server\": \"${SERVER_IP}\", \"server_port\": ${PORT_HYSTERIA2}, \"up_mbps\": 200, \"down_mbps\": 1000, \"password\": \"${UUID[12]}\", \"tls\": { \"enabled\": true, \"insecure\": true, \"server_name\": \"\", \"alpn\": [ \"h3\" ] } }," &&
  local NODE_REPLACE+="\"${NODE_NAME[12]} ${NODE_TAG[1]}\","

  [ -n "$PORT_TUIC" ] &&
  local TUIC_INBOUND=" { \"type\": \"tuic\", \"tag\": \"${NODE_NAME[13]} ${NODE_TAG[2]}\", \"server\": \"${SERVER_IP}\", \"server_port\": ${PORT_TUIC}, \"uuid\": \"${UUID[13]}\", \"password\": \"${TUIC_PASSWORD}\", \"congestion_control\": \"$TUIC_CONGESTION_CONTROL\", \"udp_relay_mode\": \"native\", \"zero_rtt_handshake\": false, \"heartbeat\": \"10s\", \"tls\": { \"enabled\": true, \"insecure\": true, \"server_name\": \"\", \"alpn\": [ \"h3\" ] } }," &&
  local INBOUND_REPLACE+="${TUIC_INBOUND}" &&
  local NODE_REPLACE+="\"${NODE_NAME[13]} ${NODE_TAG[2]}\"," &&
  local INBOUND_INSERT+="${TUIC_INBOUND}" &&
  local NODE_INSERT+=", \"${NODE_NAME[13]} ${NODE_TAG[2]}\""

  [ -n "$PORT_SHADOWTLS" ] &&
  local SHADOWTLS_INBOUND=" { \"type\": \"shadowsocks\", \"tag\": \"${NODE_NAME[14]} ${NODE_TAG[3]}\", \"method\": \"$SHADOWTLS_METHOD\", \"password\": \"$SHADOWTLS_PASSWORD\", \"detour\": \"shadowtls-out\", \"udp_over_tcp\": false, \"multiplex\": { \"enabled\": true, \"protocol\": \"h2mux\", \"max_connections\": 8, \"min_streams\": 16, \"padding\": true, \"brutal\":{ \"enabled\":true, \"up_mbps\":1000, \"down_mbps\":1000 } } }, { \"type\": \"shadowtls\", \"tag\": \"shadowtls-out\", \"server\": \"${SERVER_IP}\", \"server_port\": ${PORT_SHADOWTLS}, \"version\": 3, \"password\": \"${UUID[14]}\", \"tls\": { \"enabled\": true, \"server_name\": \"${TLS_SERVER[14]}\", \"utls\": { \"enabled\": true, \"fingerprint\": \"chrome\" } } }," &&
  local INBOUND_REPLACE+="${SHADOWTLS_INBOUND}" &&
  local NODE_REPLACE+="\"${NODE_NAME[14]} ${NODE_TAG[3]}\"," &&
  local INBOUND_INSERT+="${SHADOWTLS_INBOUND}" &&
  local NODE_INSERT+=", \"${NODE_NAME[14]} ${NODE_TAG[3]}\""

  [ -n "$PORT_SHADOWSOCKS" ] &&
  local INBOUND_REPLACE+=" { \"type\": \"shadowsocks\", \"tag\": \"${NODE_NAME[15]} ${NODE_TAG[4]}\", \"server\": \"${SERVER_IP}\", \"server_port\": $PORT_SHADOWSOCKS, \"method\": \"${SHADOWSOCKS_METHOD}\", \"password\": \"${UUID[15]}\", \"multiplex\": { \"enabled\": true, \"protocol\": \"h2mux\", \"max_connections\": 8, \"min_streams\": 16, \"padding\": true, \"brutal\":{ \"enabled\":true, \"up_mbps\":1000, \"down_mbps\":1000 } } }," &&
  local NODE_REPLACE+="\"${NODE_NAME[15]} ${NODE_TAG[4]}\","

  [ -n "$PORT_TROJAN" ] &&
  local INBOUND_REPLACE+=" { \"type\": \"trojan\", \"tag\": \"${NODE_NAME[16]} ${NODE_TAG[5]}\", \"server\": \"${SERVER_IP}\", \"server_port\": $PORT_TROJAN, \"password\": \"$TROJAN_PASSWORD\", \"tls\": { \"enabled\":true, \"insecure\": true, \"server_name\":\"\", \"utls\": { \"enabled\":true, \"fingerprint\":\"chrome\" } }, \"multiplex\": { \"enabled\":true, \"protocol\":\"h2mux\", \"max_connections\": 8, \"min_streams\": 16, \"padding\": true, \"brutal\":{ \"enabled\":true, \"up_mbps\":1000, \"down_mbps\":1000 } } }," &&
  local NODE_REPLACE+="\"${NODE_NAME[16]} ${NODE_TAG[5]}\","

  [ -n "$PORT_VMESS_WS" ] &&
  local WS_SERVER_IP_SHOW=${WS_SERVER_IP[17]} &&
  local TYPE_HOST_DOMAIN=$VMESS_HOST_DOMAIN &&
  local TYPE_PORT_WS=$PORT_VMESS_WS &&
  local PROMPT+="
  # 请在 Cloudflare 绑定 \[\${WS_SERVER_IP_SHOW}] 的域名为 \[\${TYPE_HOST_DOMAIN}], 并设置 origin rule 为 \[\${TYPE_PORT_WS}]" &&
  local INBOUND_REPLACE+=" { \"type\": \"vmess\", \"tag\": \"${NODE_NAME[17]} ${NODE_TAG[6]}\", \"server\":\"${CDN[17]}\", \"server_port\":80, \"uuid\":\"${UUID[17]}\", \"transport\": { \"type\":\"ws\", \"path\":\"/$VMESS_WS_PATH\", \"headers\": { \"Host\": \"$VMESS_HOST_DOMAIN\" } }, \"multiplex\": { \"enabled\":true, \"protocol\":\"h2mux\", \"max_streams\":16, \"padding\": true, \"brutal\":{ \"enabled\":true, \"up_mbps\":1000, \"down_mbps\":1000 } } }," && local NODE_REPLACE+="\"${NODE_NAME[17]} ${NODE_TAG[6]}\","

  [ -n "$PORT_VLESS_WS" ] &&
  local WS_SERVER_IP_SHOW=${WS_SERVER_IP[18]} &&
  local TYPE_HOST_DOMAIN=$VLESS_HOST_DOMAIN &&
  local TYPE_PORT_WS=$PORT_VLESS_WS &&
  local PROMPT+="
  # 请在 Cloudflare 绑定 \[\${WS_SERVER_IP_SHOW}] 的域名为 \[\${TYPE_HOST_DOMAIN}], 并设置 origin rule 为 \[\${TYPE_PORT_WS}]" &&
  local INBOUND_REPLACE+=" { \"type\": \"vless\", \"tag\": \"${NODE_NAME[18]} ${NODE_TAG[7]}\", \"server\":\"${CDN[18]}\", \"server_port\":443, \"uuid\":\"${UUID[18]}\", \"tls\": { \"enabled\":true, \"server_name\":\"$VLESS_HOST_DOMAIN\", \"utls\": { \"enabled\":true, \"fingerprint\":\"chrome\" } }, \"transport\": { \"type\":\"ws\", \"path\":\"/$VLESS_WS_PATH\", \"headers\": { \"Host\": \"$VLESS_HOST_DOMAIN\" }, \"max_early_data\":2048, \"early_data_header_name\":\"Sec-WebSocket-Protocol\" }, \"multiplex\": { \"enabled\":true, \"protocol\":\"h2mux\", \"max_streams\":16, \"padding\": true, \"brutal\":{ \"enabled\":true, \"up_mbps\":1000, \"down_mbps\":1000 } } }," &&
  local NODE_REPLACE+="\"${NODE_NAME[18]} ${NODE_TAG[7]}\","

  [ -n "$PORT_H2_REALITY" ] &&
  local REALITY_H2_INBOUND=" { \"type\": \"vless\", \"tag\": \"${NODE_NAME[19]} ${NODE_TAG[8]}\", \"server\": \"${SERVER_IP}\", \"server_port\": ${PORT_H2_REALITY}, \"uuid\":\"${UUID[19]}\", \"tls\": { \"enabled\":true, \"server_name\":\"${TLS_SERVER[19]}\", \"utls\": { \"enabled\":true, \"fingerprint\":\"chrome\" }, \"reality\":{ \"enabled\":true, \"public_key\":\"${REALITY_PUBLIC[19]}\", \"short_id\":\"\" } }, \"packet_encoding\": \"xudp\", \"transport\": { \"type\": \"http\" } }," &&
  local REALITY_H2_NODE="\"${NODE_NAME[19]} ${NODE_TAG[8]}\"" &&
  local NODE_REPLACE+="${REALITY_H2_NODE}," &&
  local INBOUND_REPLACE+=" ${REALITY_H2_INBOUND}" &&
  local INBOUND_INSERT+=" ${REALITY_H2_INBOUND}" &&
  local NODE_INSERT+=", ${REALITY_H2_NODE}"

  [ -n "$PORT_GRPC_REALITY" ] &&
  local INBOUND_REPLACE+=" { \"type\": \"vless\", \"tag\": \"${NODE_NAME[20]} ${NODE_TAG[9]}\", \"server\": \"${SERVER_IP}\", \"server_port\": ${PORT_GRPC_REALITY}, \"uuid\":\"${UUID[20]}\", \"tls\": { \"enabled\":true, \"server_name\":\"${TLS_SERVER[20]}\", \"utls\": { \"enabled\":true, \"fingerprint\":\"chrome\" }, \"reality\":{ \"enabled\":true, \"public_key\":\"${REALITY_PUBLIC[20]}\", \"short_id\":\"\" } }, \"packet_encoding\": \"xudp\", \"transport\": { \"type\": \"grpc\", \"service_name\": \"grpc\" } }," &&
  local NODE_REPLACE+="\"${NODE_NAME[20]} ${NODE_TAG[9]}\","

  # 模板1
  local SING_BOX_JSON1=$(wget --no-check-certificate -qO- --tries=3 --timeout=2 ${SUBSCRIBE_TEMPLATE}/sing-box1)
  echo $SING_BOX_JSON1 | sed 's#, {[^}]\+"tun-in"[^}]\+}##' | sed "s#\"<INBOUND_REPLACE>\",#$INBOUND_REPLACE#; s#\"<NODE_REPLACE>\"#${NODE_REPLACE%,}#g" | $WORK_DIR_SUB/jq > $WORK_DIR_SUB/subscribe/sing-box-pc
  echo $SING_BOX_JSON1 | sed 's# {[^}]\+"mixed"[^}]\+},##; s#, "auto_detect_interface": true##' | sed "s#\"<INBOUND_REPLACE>\",#$INBOUND_REPLACE#; s#\"<NODE_REPLACE>\"#${NODE_REPLACE%,}#g" | $WORK_DIR_SUB/jq > $WORK_DIR_SUB/subscribe/sing-box-phone

  # 模板2
  local SING_BOX_JSON2=$(wget --no-check-certificate -qO- --tries=3 --timeout=2 ${SUBSCRIBE_TEMPLATE}/sing-box2)
  echo $SING_BOX_JSON2 | sed "s#\"<INBOUND_REPLACE>\",#$INBOUND_REPLACE#; s#\"<NODE_REPLACE>\"#${NODE_REPLACE%,}#g" | $WORK_DIR_SUB/jq > $WORK_DIR_SUB/subscribe/sing-box2



  # 生成配置文件
  EXPORT_LIST_FILE="*******************************************
┌────────────────┐
│                │
│     $(warning "V2rayN")     │
│                │
└────────────────┘
$(info "${V2RAYN_SUBSCRIBE}")

*******************************************
┌────────────────┐
│                │
│  $(warning "ShadowRocket")  │
│                │
└────────────────┘
----------------------------
$(listchoice "${SHADOWROCKET_SUBSCRIBE}")

*******************************************
┌────────────────┐
│                │
│   $(warning "Clash Meta")   │
│                │
└────────────────┘
----------------------------

$(info "$(sed '1d' <<< "${CLASH_SUBSCRIBE}")")

*******************************************
┌────────────────┐
│                │
│    $(warning "NekoBox")     │
│                │
└────────────────┘
$(listchoice "${NEKOBOX_SUBSCRIBE}")

*******************************************
┌────────────────┐
│                │
│    $(warning "Sing-box")    │
│                │
└────────────────┘
----------------------------

$(info "$(echo "{ \"outbounds\":[ ${INBOUND_REPLACE%,} ] }" | $WORK_DIR_SUB/jq)

${PROMPT}

各客户端配置文件路径: $WORK_DIR_SUB/subscribe/\n 完整模板可参照:\n https://github.com/chika0801/sing-box-examples/tree/main/Tun")
"

  # 生成并显示节点信息
  echo "$EXPORT_LIST_FILE" > $WORK_DIR_SUB/list
  cat $WORK_DIR_SUB/list

}

# 更换各协议的监听端口
change_start_port() {
  OLD_PORTS=$(awk -F ':|,' '/listen_port/{print $2}' $WORK_DIR_SUB/conf/*)
  OLD_START_PORT=$(awk 'NR == 1 { min = $0 } { if ($0 < min) min = $0; count++ } END {print min}' <<< "$OLD_PORTS")
  OLD_CONSECUTIVE_PORTS=$(awk 'END { print NR }' <<< "$OLD_PORTS")
  enter_start_port $OLD_CONSECUTIVE_PORTS
  cmd_systemctl disable sing-box
  for ((a=0; a<$OLD_CONSECUTIVE_PORTS; a++)) do
    [ -s $WORK_DIR_SUB/conf/${CONF_FILES[a]} ] && sed -i "s/\(.*listen_port.*:\)$((OLD_START_PORT+a))/\1$((START_PORT+a))/" $WORK_DIR_SUB/conf/*
  done
  systemctl enable sing-box
  sleep 2
  export_list
  [ "$(systemctl is-active sing-box)" = 'active' ] && info " Sing-box 更换监听端口 成功 " || error " Sing-box 更换监听端口 失败 "
}

# 增加或删除协议
change_protocols() {
  check_install
  [ "$STATUS" = "未安装" ] && error "\n Sing-box 未安装 "

  # 查找已安装的协议，并遍历其在所有协议列表中的名称，获取协议名后存放在 EXISTED_PROTOCOLS; 没有的协议存放在 NOT_EXISTED_PROTOCOLS
  INSTALLED_PROTOCOLS_LIST=$(awk -F '"' '/"tag":/{print $4}' $WORK_DIR_SUB/conf/*_inbounds.json | grep -v 'shadowtls-in' | awk '{print $NF}')
  for f in ${!NODE_TAG[@]}; do [[ $INSTALLED_PROTOCOLS_LIST =~ "${NODE_TAG[f]}" ]] && EXISTED_PROTOCOLS+=("${PROTOCOL_LIST[f]}") || NOT_EXISTED_PROTOCOLS+=("${PROTOCOL_LIST[f]}"); done

  # 列出已安装协议
  listchoice "\n (1/3) 已安装的协议 (${#EXISTED_PROTOCOLS[@]})"
  for h in "${!EXISTED_PROTOCOLS[@]}"; do
    listchoice " $(asc $[h+97]). ${EXISTED_PROTOCOLS[h]} "
  done

  # 从已安装的协议中选择需要删除的协议名，并存放在 REMOVE_PROTOCOLS，把保存的协议的协议存放在 KEEP_PROTOCOLS
  reading "\n 请选择需要删除的协议（可以多选）: " REMOVE_SELECT
  # 统一为小写，去掉重复选项，处理不在可选列表里的选项，把特殊符号处理
  REMOVE_SELECT=$(sed "s/[^a-$(asc $[${#EXISTED_PROTOCOLS[@]} + 96])]//g" <<< "${REMOVE_SELECT,,}" | awk 'BEGIN{RS=""; FS=""}{delete seen; output=""; for(i=1; i<=NF; i++){ if(!seen[$i]++){ output=output $i } } print output}')

  for ((j=0; j<${#REMOVE_SELECT}; j++)); do
    REMOVE_PROTOCOLS+=("${EXISTED_PROTOCOLS[$[$(asc "$(awk "NR==$[j+1] {print}" <<< "$(grep -o . <<< "$REMOVE_SELECT")")") - 97]]}")
  done

  for k in "${EXISTED_PROTOCOLS[@]}"; do
    [[ ! "${REMOVE_PROTOCOLS[@]}" =~ "$k" ]] && KEEP_PROTOCOLS+=("$k")
  done

  # 如有未安装的协议，列表显示并选择安装，把增加的协议存在放在 ADD_PROTOCOLS
  if [ "${#NOT_EXISTED_PROTOCOLS[@]}" -gt 0 ]; then
    listchoice "\n (2/3) 未安装的协议 (${#NOT_EXISTED_PROTOCOLS[@]}) "
    for i in "${!NOT_EXISTED_PROTOCOLS[@]}"; do
      listchoice " $(asc $[i+97]). ${NOT_EXISTED_PROTOCOLS[i]} "
    done
    reading "\n 请选择需要增加的协议（可以多选）: " ADD_SELECT
    # 统一为小写，去掉重复选项，处理不在可选列表里的选项，把特殊符号处理
    ADD_SELECT=$(sed "s/[^a-$(asc $[${#NOT_EXISTED_PROTOCOLS[@]} + 96])]//g" <<< "${ADD_SELECT,,}" | awk 'BEGIN{RS=""; FS=""}{delete seen; output=""; for(i=1; i<=NF; i++){ if(!seen[$i]++){ output=output $i } } print output}')

    for ((l=0; l<${#ADD_SELECT}; l++)); do
      ADD_PROTOCOLS+=("${NOT_EXISTED_PROTOCOLS[$[$(asc "$(awk "NR==$[l+1] {print}" <<< "$(grep -o . <<< "$ADD_SELECT")")") - 97]]}")
    done
  fi

  # 重新安装 = 保留 + 新增，如数量为 0 ，则触发卸载
  REINSTALL_PROTOCOLS=("${KEEP_PROTOCOLS[@]}" "${ADD_PROTOCOLS[@]}")
  [ "${#REINSTALL_PROTOCOLS[@]}" = 0 ] && error "\n 没有协议剩下，如确定请重新执行卸载所有 "

  # 显示重新安装的协议列表，并确认是否正确
  listchoice "\n (3/3) 确认重装的所有协议 (${#REINSTALL_PROTOCOLS[@]}) "
  [ "${#KEEP_PROTOCOLS[@]}" -gt 0 ] && listchoice "\n 保留协议 (${#KEEP_PROTOCOLS[@]}) "
  for r in "${!KEEP_PROTOCOLS[@]}"; do
    listchoice " $[r+1]. ${KEEP_PROTOCOLS[r]} "
  done

  [ "${#ADD_PROTOCOLS[@]}" -gt 0 ] && listchoice "\n 新增协议 (${#ADD_PROTOCOLS[@]}) "
  for r in "${!ADD_PROTOCOLS[@]}"; do
    listchoice " $[r+1]. ${ADD_PROTOCOLS[r]} "
  done

  reading "\n 如有错误请按 [n]，其他键继续: " CONFIRM
  [ "${CONFIRM,,}" = 'n' ] && exit 0

  # 把确认安装的协议遍历所有协议列表的数组，找出其下标并变为英文小写的形式
  for m in "${!REINSTALL_PROTOCOLS[@]}"; do
    for n in "${!PROTOCOL_LIST[@]}"; do
      if [ "${REINSTALL_PROTOCOLS[m]}" = "${PROTOCOL_LIST[n]}" ]; then
        INSTALL_PROTOCOLS+=($(asc $[n+98]))
      fi
    done
  done

  cmd_systemctl disable sing-box

  # 获取各节点信息
  fetch_nodes_value

  # 用于新节点的配置信息
  UUID_CONFIRM=$(awk '{print $1}' <<< "${UUID[@]} $TROJAN_PASSWORD")
  for v in "${NODE_NAME[@]}"; do
    [ -n "$v" ] && NODE_NAME_CONFIRM="$v" && break
  done
  [ "${#WS_SERVER_IP[@]}" -gt 0 ] && WS_SERVER_IP_SHOW=$(awk '{print $1}' <<< "${WS_SERVER_IP[@]}") && CDN=$(awk '{print $1}' <<< "${CDN[@]}")

  # 寻找待删除协议的 inbound 文件名
  for o in "${REMOVE_PROTOCOLS[@]}"; do
    for ((s=0; s<${#PROTOCOL_LIST[@]}; s++)); do
      [ "$o" = "${PROTOCOL_LIST[s]}" ] && REMOVE_FILE+=("${NODE_TAG[s]}_inbounds.json")
    done
  done

  # 删除不需要的协议配置文件
  [ "${#REMOVE_FILE[@]}" -gt 0 ] && for t in "${REMOVE_FILE[@]}"; do
    rm -f $WORK_DIR_SUB/conf/*${t}
  done

  # 寻找已存在协议中原有的端口号
  for p in "${KEEP_PROTOCOLS[@]}"; do
    for ((u=0; u<${#PROTOCOL_LIST[@]}; u++)); do
      [ "$p" = "${PROTOCOL_LIST[u]}" ] && KEEP_PORTS+=("$(awk -F '[:,]' '/listen_port/{print $2}' $WORK_DIR_SUB/conf/*${NODE_TAG[u]}_inbounds.json)")
    done
  done

  # 根据全部协议，找到空余的端口号
  for q in "${!REINSTALL_PROTOCOLS[@]}"; do
    [[ ! ${KEEP_PORTS[@]} =~ $[START_PORT + q] ]] && ADD_PORTS+=($[START_PORT + q])
  done

  # 所有协议的端口号
  REINSTALL_PORTS=(${KEEP_PORTS[@]} ${ADD_PORTS[@]})

  CHECK_PROTOCOLS=b
  # 获取原始 Reality 配置信息
  if [[ "${INSTALL_PROTOCOLS[@]}" =~ "$CHECK_PROTOCOLS" ]]; then
    POSITION=$(awk -v target=$CHECK_PROTOCOLS '{ for(i=1; i<=NF; i++) if($i == target) { print i-1; break } }' <<< "${INSTALL_PROTOCOLS[*]}")
    PORT_XTLS_REALITY=${REINSTALL_PORTS[POSITION]}
  fi

  # 获取原始 Hysteria2 配置信息
  CHECK_PROTOCOLS=$(asc "$CHECK_PROTOCOLS" ++)
  if [[ "${INSTALL_PROTOCOLS[@]}" =~ "$CHECK_PROTOCOLS" ]]; then
    POSITION=$(awk -v target=$CHECK_PROTOCOLS '{ for(i=1; i<=NF; i++) if($i == target) { print i-1; break } }' <<< "${INSTALL_PROTOCOLS[*]}")
    PORT_HYSTERIA2=${REINSTALL_PORTS[POSITION]}
  fi

  # 获取原始 Tuic V5 配置信息
  CHECK_PROTOCOLS=$(asc "$CHECK_PROTOCOLS" ++)
  if [[ "${INSTALL_PROTOCOLS[@]}" =~ "$CHECK_PROTOCOLS" ]]; then
    POSITION=$(awk -v target=$CHECK_PROTOCOLS '{ for(i=1; i<=NF; i++) if($i == target) { print i-1; break } }' <<< "${INSTALL_PROTOCOLS[*]}")
    PORT_TUIC=${REINSTALL_PORTS[POSITION]}
  fi

  # 获取原始 ShadowTLS 配置信息
  CHECK_PROTOCOLS=$(asc "$CHECK_PROTOCOLS" ++)
  if [[ "${INSTALL_PROTOCOLS[@]}" =~ "$CHECK_PROTOCOLS" ]]; then
    POSITION=$(awk -v target=$CHECK_PROTOCOLS '{ for(i=1; i<=NF; i++) if($i == target) { print i-1; break } }' <<< "${INSTALL_PROTOCOLS[*]}")
    PORT_SHADOWTLS=${REINSTALL_PORTS[POSITION]}
  fi

  # 获取原始 Shadowsocks 配置信息
  CHECK_PROTOCOLS=$(asc "$CHECK_PROTOCOLS" ++)
  if [[ "${INSTALL_PROTOCOLS[@]}" =~ "$CHECK_PROTOCOLS" ]]; then
    POSITION=$(awk -v target=$CHECK_PROTOCOLS '{ for(i=1; i<=NF; i++) if($i == target) { print i-1; break } }' <<< "${INSTALL_PROTOCOLS[*]}")
    PORT_SHADOWSOCKS=${REINSTALL_PORTS[POSITION]}
  fi

  # 获取原始 Trojan 配置信息
  CHECK_PROTOCOLS=$(asc "$CHECK_PROTOCOLS" ++)
  if [[ "${INSTALL_PROTOCOLS[@]}" =~ "$CHECK_PROTOCOLS" ]]; then
    POSITION=$(awk -v target=$CHECK_PROTOCOLS '{ for(i=1; i<=NF; i++) if($i == target) { print i-1; break } }' <<< "${INSTALL_PROTOCOLS[*]}")
    PORT_TROJAN=${REINSTALL_PORTS[POSITION]}
  fi

  # 获取原始 vmess + ws 配置信息
  CHECK_PROTOCOLS=$(asc "$CHECK_PROTOCOLS" ++)
  if [[ "${INSTALL_PROTOCOLS[@]}" =~ "$CHECK_PROTOCOLS" ]]; then
    local DOMAIN_ERROR_TIME=5
    until [ -n "$VMESS_HOST_DOMAIN" ]; do
      (( DOMAIN_ERROR_TIME-- )) || true
      [ "$DOMAIN_ERROR_TIME" != 0 ] && TYPE=VMESS && reading "\n 请输入 $TYPE 域名: " VMESS_HOST_DOMAIN || error "\n 输入错误达5次,脚本退出 \n"
    done
    POSITION=$(awk -v target=$CHECK_PROTOCOLS '{ for(i=1; i<=NF; i++) if($i == target) { print i-1; break } }' <<< "${INSTALL_PROTOCOLS[*]}")
    PORT_VMESS_WS=${REINSTALL_PORTS[POSITION]}
  fi

  # 获取原始 vless + ws + tls 配置信息
  CHECK_PROTOCOLS=$(asc "$CHECK_PROTOCOLS" ++)
  if [[ "${INSTALL_PROTOCOLS[@]}" =~ "$CHECK_PROTOCOLS" ]]; then
    local DOMAIN_ERROR_TIME=5
    until [ -n "$VLESS_HOST_DOMAIN" ]; do
      (( DOMAIN_ERROR_TIME-- )) || true
      [ "$DOMAIN_ERROR_TIME" != 0 ] && TYPE=VLESS && reading "\n 请输入 $TYPE 域名: " VLESS_HOST_DOMAIN || error "\n 输入错误达5次,脚本退出 \n"
    done
    POSITION=$(awk -v target=$CHECK_PROTOCOLS '{ for(i=1; i<=NF; i++) if($i == target) { print i-1; break } }' <<< "${INSTALL_PROTOCOLS[*]}")
    PORT_VLESS_WS=${REINSTALL_PORTS[POSITION]}
  fi

  # 获取原始 H2 + Reality 配置信息
  CHECK_PROTOCOLS=$(asc "$CHECK_PROTOCOLS" ++)
  if [[ "${INSTALL_PROTOCOLS[@]}" =~ "$CHECK_PROTOCOLS" ]]; then
    POSITION=$(awk -v target=$CHECK_PROTOCOLS '{ for(i=1; i<=NF; i++) if($i == target) { print i-1; break } }' <<< "${INSTALL_PROTOCOLS[*]}")
    PORT_H2_REALITY=${REINSTALL_PORTS[POSITION]}
  fi

  # 获取原始 gRPC + Reality 配置信息
  CHECK_PROTOCOLS=$(asc "$CHECK_PROTOCOLS" ++)
  if [[ "${INSTALL_PROTOCOLS[@]}" =~ "$CHECK_PROTOCOLS" ]]; then
    POSITION=$(awk -v target=$CHECK_PROTOCOLS '{ for(i=1; i<=NF; i++) if($i == target) { print i-1; break } }' <<< "${INSTALL_PROTOCOLS[*]}")
    PORT_GRPC_REALITY=${REINSTALL_PORTS[POSITION]}
  fi

  # 生成各协议的 json 文件
  sing_box_json change

  # 运行 sing-box
  systemctl start sing-box

  # 再次检测状态，运行 Sing-box
  check_install

  check_sing_box_status

  export_list
}

# 卸载 Sing-box 全家桶
uninstall() {
  cmd_systemctl disable sing-box 2>/dev/null
  sleep 1
  rm -rf $WORK_DIR_SUB $TEMP_DIR /etc/systemd/system/sing-box.service
  info "\n Sing-box 已彻底卸载 \n"

  # 如果 Alpine 系统，删除开机自启动和python3版systemd
  if [ "$SYSTEM" = 'Alpine' ]; then
    rm -f /etc/local.d/sing-box.start
    rc-update add local >/dev/null 2>&1
    ! ls /etc/systemd/system/*.service >/dev/null 2>&1 && rm -f /bin/systemctl
  fi
  exit 0
}

# Sing-box 的最新版本
version() {
  local VERSION_LATEST=$(wget --no-check-certificate -qO- "https://api.github.com/repos/SagerNet/sing-box/releases" | awk -F '["v-]' '/tag_name/{print $5}' | sort -r | sed -n '1p')
  local ONLINE=$(wget --no-check-certificate -qO- "https://api.github.com/repos/SagerNet/sing-box/releases" | awk -F '["v]' -v var="tag_name.*$VERSION_LATEST" '$0 ~ var {print $5; exit}')
  local LOCAL=$($WORK_DIR_SUB/sing-box version | awk '/version/{print $NF}')
  info "\n Sing-box 本地版本: $LOCAL\t 最新版本: $ONLINE "
  [[ -n "$ONLINE" && "$ONLINE" != "$LOCAL" ]] && reading "\n 升级请按 [y]，默认不升级: " UPDATE || info " 不需要升级 "

  if [ "${UPDATE,,}" = 'y' ]; then
    check_system_info
    wget --no-check-certificate --continue https://github.com/SagerNet/sing-box/releases/download/v$ONLINE/sing-box-$ONLINE-linux-$SING_BOX_ARCH.tar.gz -qO- | tar xz -C $TEMP_DIR sing-box-$ONLINE-linux-$SING_BOX_ARCH/sing-box

    if [ -s $TEMP_DIR/sing-box-$ONLINE-linux-$SING_BOX_ARCH/sing-box ]; then
      cmd_systemctl disable sing-box
      chmod +x $TEMP_DIR/sing-box-$ONLINE-linux-$SING_BOX_ARCH/sing-box && mv $TEMP_DIR/sing-box-$ONLINE-linux-$SING_BOX_ARCH/sing-box $WORK_DIR_SUB/sing-box
      systemctl enable sing-box && sleep 2 && [ "$(systemctl is-active sing-box)" = 'active' ] && info " Sing-box 开启 成功" || error "Sing-box 开启 失败 "
    else
      local error "\n 下载最新版本 Sing-box 失败，脚本退出 "
    fi
  fi
}

echo_system_status()
{
  echo -e "==================================================\n"
  info " 脚本版本: $VERSION\n 系统信息:\n\t 当前操作系统: $SYS\n\t 内核: $(uname -r)\n\t 处理器架构: $SING_BOX_ARCH\n\t 虚拟化: $VIRT "
  info "\t IPv4: $WAN4 $COUNTRY4  $ASNORG4 "
  info "\t Sing-box: $STATUS\t $SING_BOX_VERSION "
  [ -n "$PID" ] && info "\t 进程ID: $PID "
  [ -n "$RUNTIME" ] && info "\t 运行时长: $RUNTIME "
  [ -n "$MEMORY_USAGE" ] && info "\t 内存占用: $MEMORY_USAGE MB"
  [ -n "$NOW_START_PORT" ] && info "\t 使用端口: ${NOW_START_PORT} - $((NOW_START_PORT+NOW_CONSECUTIVE_PORTS-1)) "
  echo -e "\n==================================================\n"
}
# 判断当前 Sing-box 的运行状态，并对应的给菜单和动作赋值
menu_setting() {
  if [[ "$STATUS" =~ "关闭"|"开启" ]]; then
    # 查进程号，sing-box 运行时长和内存占用
    if [ "$STATUS" = "开启" ]; then
      if [ "$SYSTEM" = 'Alpine' ]; then
        PID=$(pidof sing-box | sed -n 1p)
      else
        SYSTEMCTL_STATUS=$(systemctl status sing-box)
        PID=$(awk '/PID/{print $3}' <<< "$SYSTEMCTL_STATUS")
        RUNTIME=$(awk '/Active:/{for (i=5;i<=NF;i++)printf("%s ", $i);print ""}' <<< "$SYSTEMCTL_STATUS")
      fi
      MEMORY_USAGE="$(awk '/VmRSS/{printf "%.1f\n", $2/1024}' /proc/$PID/status)"
    fi

    NOW_PORTS=$(awk -F ':|,' '/listen_port/{print $2}' $WORK_DIR_SUB/conf/*)
    NOW_START_PORT=$(awk 'NR == 1 { min = $0 } { if ($0 < min) min = $0; count++ } END {print min}' <<< "$NOW_PORTS")
    NOW_CONSECUTIVE_PORTS=$(awk 'END { print NR }' <<< "$NOW_PORTS")
    [ -s $WORK_DIR_SUB/sing-box ] && SING_BOX_VERSION="version: $($WORK_DIR_SUB/sing-box version | awk '/version/{print $NF}')"
    [ -s $WORK_DIR_SUB/conf/02_route.json ] && { grep -q 'direct' $WORK_DIR_SUB/conf/02_route.json && RETURN_STATUS="关闭" || RETURN_STATUS="开启"; }
    OPTION[1]="1.  查看节点信息"
    [ "$STATUS" = "开启" ] && OPTION[2]="2.  关闭 Sing-box " || OPTION[2]="2.  开启 Sing-box "
    OPTION[3]="3.  更换监听端口"
    OPTION[4]="4.  同步 Sing-box 至最新版本"
    OPTION[5]="5.  升级内核、安装BBR、DD脚本"
    OPTION[6]="6.  增加 / 删除协议"
    OPTION[7]="7.  卸载"

    ACTION[1]() { export_list; exit 0; }
    [ "$STATUS" = "开启" ] && ACTION[2]() { cmd_systemctl disable sing-box; [[ "$(systemctl is-active sing-box)" =~ 'inactive'|'unknown' ]] && info " Sing-box 关闭 成功" || error " Sing-box 关闭 失败 "; } || ACTION[2]() { cmd_systemctl enable sing-box && [ "$(systemctl is-active sing-box)" = 'active' ] && info " Sing-box 开启 成功" || error " Sing-box 开启 失败 "; }
    ACTION[3]() { change_start_port; exit; }
    ACTION[4]() { version; exit; }
    ACTION[5]() { bash <(wget --no-check-certificate -qO- "https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcp.sh"); exit; }
    ACTION[6]() { change_protocols; exit; }
    ACTION[7]() { uninstall; exit; }

  else
    OPTION[1]="1.  安装 Sing-box 协议全家桶脚本"
    #OPTION[2]="2.  升级内核、安装BBR、DD脚本"

    ACTION[1]() { install_sing_box; export_list install; exit; }
    #ACTION[2]() { bash <(wget --no-check-certificate -qO- "https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcp.sh"); exit; }

  fi

  OPTION[0]="0.  退出"
  ACTION[0]() { exit; }
}

menu() {
  clear
  echo "  
==================================================
Sing-Box 管理脚本V1 $VERSION 
==================================================
"
  #只有一个选项，那就直接进吧
  if [[ "${#OPTION[*]}" == "2" ]]; then
      ACTION[1]
      exit
  fi

  for ((b=1;b<${#OPTION[*]};b++)); do listchoice " ${OPTION[b]} "; done
  listchoice " ${OPTION[0]} "
    echo "  
=================================================="
  reading "\n 请选择: " CHOOSE

  # 选项为0直接退出
  if [[ "${CHOOSE}" == "0" ]]; then
      exit
  elif grep -qE "^[0-9]{1,2}$" <<< "$CHOOSE" && [ "$CHOOSE" -lt "${#OPTION[*]}" ]; then   # 输入必须是数字且少于等于最大可选项
    check_system_ip
    ACTION[$CHOOSE]
  else
    warning " 请输入正确数字 [0-$((${#OPTION[*]}-1))] " && sleep 1 && menu
  fi
}

# 传参
if [[ ! $# == 0 && $1 == "install_ss2022" ]]; then
    flagInstallSS2022="Install"
    install_sing_box; export_list install; 
    exit 0
elif [[ ! $# == 0 && $1 == "uninstall_ss2022" ]]; then
    uninstall
    exit 0
fi

check_root
check_arch
check_system_info
check_dependencies
#check_system_ip
check_install

menu_setting
menu
