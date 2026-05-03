#!/bin/bash

# ==================== 颜色定义 ====================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'

# 避免 locale 警告
export LC_ALL=C

# ==================== 路径配置 ====================
CONFIG_FILE="/etc/sing-box/config.json"
INSTALL_DIR="/usr/local/bin"
CERT_DIR="/etc/sing-box/certs"
LINK_DIR="/etc/sing-box/links"
KEY_FILE="/etc/sing-box/keys.txt"

ALL_LINKS_FILE="${LINK_DIR}/all.txt"
REALITY_LINKS_FILE="${LINK_DIR}/reality.txt"
HYSTERIA2_LINKS_FILE="${LINK_DIR}/hysteria2.txt"
SOCKS5_LINKS_FILE="${LINK_DIR}/socks5.txt"
SHADOWTLS_LINKS_FILE="${LINK_DIR}/shadowtls.txt"
HTTPS_LINKS_FILE="${LINK_DIR}/https.txt"
ANYTLS_LINKS_FILE="${LINK_DIR}/anytls.txt"

SCRIPT_PATH=$(readlink -f "$0" 2>/dev/null || realpath "$0" 2>/dev/null || echo "$0")

# ==================== 全局变量 ====================
INBOUNDS_JSON=""                 # 所有入站 JSON 字符串
ALL_LINKS_TEXT=""                # 全部链接文本
SERVER_IP=""                     # 主 IPv4 地址
SERVER_IPV6=""                   # IPv6 地址
INBOUND_IP_MODE="ipv4"           # 入站监听地址族
OUTBOUND_IP_MODE="dual"          # 出站连接地址族
IP_CONFIG_FILE="/etc/sing-box/ip_config.conf"

RELAY_TAGS=()                    # 中转标签
RELAY_JSONS=()                   # 中转 JSON 配置
RELAY_DESCS=()                   # 中转描述
RELAY_FILE="/etc/sing-box/relays.conf"

INBOUND_TAGS=()                  # 节点标签
INBOUND_PORTS=()                 # 节点端口
INBOUND_PROTOS=()                # 节点协议
INBOUND_RELAY_TAGS=()            # 节点绑定的中转标签
INBOUND_SNIS=()                  # 节点 SNI

# 全局密钥（仅用于 Reality 公私钥等不变部分）
UUID=""
REALITY_PRIVATE=""
REALITY_PUBLIC=""
SHORT_ID=""
HY2_PASSWORD=""
SS_PASSWORD=""
SHADOWTLS_PASSWORD=""
ANYTLS_PASSWORD=""
SOCKS_USER=""
SOCKS_PASS=""

DEFAULT_SNI="time.is"
NEW_NODE_LINK=""           # 临时保存最新节点的分享链接
NEW_NODE_EXTRA_INFO=""     # 临时保存最新节点的额外信息（UUID/密码/端口等）

# ==================== 打印函数 ====================
print_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error()   { echo -e "${RED}[✗]${NC} $1"; }
show_banner()   { clear; echo ""; }

# ==================== 系统检测（兼容 Alpine） ====================
detect_system() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS="${ID}"
    elif [[ -f /etc/alpine-release ]]; then
        OS="alpine"
    else
        print_error "无法检测系统"; exit 1
    fi
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)  ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        *) print_error "不支持的架构: $ARCH"; exit 1 ;;
    esac
    print_success "系统: ${OS} (${ARCH})"
}

# ==================== 依赖安装 ====================
ensure_deps() {
    print_info "检查系统依赖..."
    if ! command -v jq &>/dev/null || ! command -v openssl &>/dev/null; then
        print_info "安装依赖包..."
        if command -v apt-get &>/dev/null; then
            apt-get update -qq && apt-get install -y curl wget jq openssl uuid-runtime >/dev/null 2>&1
        elif command -v apk &>/dev/null; then
            apk update && apk add curl wget jq openssl util-linux >/dev/null 2>&1
        else
            print_error "不支持的包管理器"; return 1
        fi
    fi
    print_success "依赖检查完成"
}

# ==================== sing-box 安装/更新（手动触发） ====================
install_or_update_singbox() {
    ensure_deps || { print_error "依赖安装失败"; return 1; }

    LATEST=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r '.tag_name' | sed 's/v//')
    [[ -z "$LATEST" ]] && LATEST="1.12.0"

    if command -v sing-box &>/dev/null; then
        CURRENT=$(sing-box version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "unknown")
        print_info "当前版本: ${CURRENT}，最新版本: ${LATEST}"
        if [[ "$CURRENT" == "$LATEST" ]]; then
            print_success "已是最新版本，无需更新"; return 0
        fi
        echo -e "${YELLOW}发现新版本！${NC}"
        echo -e "  ${GREEN}[1]${NC} 更新到最新版本"
        echo -e "  ${GREEN}[2]${NC} 不更新，继续使用当前版本"
        echo -e "  ${GREEN}[0]${NC} 返回"
        read -p "请选择 [0-2]: " ver_choice
        case $ver_choice in
            1) ;;
            2) print_info "跳过更新"; return 0 ;;
            0) return 0 ;;
            *) print_error "无效选择"; return 0 ;;
        esac
    else
        echo -e "${YELLOW}sing-box 未安装，准备下载安装...${NC}"
    fi

    print_info "下载 sing-box v${LATEST}..."
    wget -q --show-progress -O /tmp/sb.tar.gz \
        "https://github.com/SagerNet/sing-box/releases/download/v${LATEST}/sing-box-${LATEST}-linux-${ARCH}.tar.gz" || { print_error "下载失败"; return 1; }
    tar -xzf /tmp/sb.tar.gz -C /tmp || { print_error "解压失败"; rm -rf /tmp/sb.tar.gz /tmp/sing-box-*; return 1; }
    install -Dm755 /tmp/sing-box-${LATEST}-linux-${ARCH}/sing-box ${INSTALL_DIR}/sing-box
    rm -rf /tmp/sb.tar.gz /tmp/sing-box-*

    # 创建服务
    if command -v systemctl &>/dev/null; then
        cat > /etc/systemd/system/sing-box.service << 'EOFSVC'
[Unit]
Description=sing-box service
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity
Environment=ENABLE_DEPRECATED_LEGACY_DNS_SERVERS=true
[Install]
WantedBy=multi-user.target
EOFSVC
        systemctl daemon-reload
        systemctl enable sing-box >/dev/null 2>&1
    elif command -v rc-service &>/dev/null; then
        cat > /etc/init.d/sing-box << EOF
#!/sbin/openrc-run
name="sing-box"
command="/usr/local/bin/sing-box"
command_args="run -c /etc/sing-box/config.json"
command_background="yes"
pidfile="/run/sing-box.pid"
EOF
        chmod +x /etc/init.d/sing-box
        rc-update add sing-box default >/dev/null 2>&1
    fi
    print_success "sing-box ${LATEST} 安装/更新完成"
}

# ==================== 证书生成 ====================
gen_cert_for_sni() {
    local sni="$1"
    local node_cert_dir="${CERT_DIR}/${sni}"
    mkdir -p "${node_cert_dir}"
    openssl genrsa -out "${node_cert_dir}/private.key" 2048 2>/dev/null
    openssl req -new -x509 -days 36500 -key "${node_cert_dir}/private.key" \
        -out "${node_cert_dir}/cert.pem" -subj "/C=US/ST=California/L=Cupertino/O=Apple Inc./CN=${sni}" 2>/dev/null
    print_success "证书生成完成"
}

# ==================== 密钥管理 ====================
gen_keys() {
    print_info "生成密钥和 UUID..."
    if [[ -f "${KEY_FILE}" ]]; then
        source "${KEY_FILE}"
        print_success "密钥已加载"; return 0
    fi
    KEYS=$(${INSTALL_DIR}/sing-box generate reality-keypair 2>/dev/null)
    REALITY_PRIVATE=$(echo "$KEYS" | grep "PrivateKey" | awk '{print $2}')
    REALITY_PUBLIC=$(echo "$KEYS" | grep "PublicKey" | awk '{print $2}')
    UUID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen)
    SHORT_ID=$(openssl rand -hex 8)
    HY2_PASSWORD=$(openssl rand -hex 16)
    SS_PASSWORD=$(openssl rand -base64 16)
    SHADOWTLS_PASSWORD=$(openssl rand -hex 16)
    ANYTLS_PASSWORD=$(openssl rand -hex 16)
    SOCKS_USER="user_$(openssl rand -hex 4)"
    SOCKS_PASS=$(openssl rand -hex 16)
    save_keys_to_file
    print_success "密钥生成完成"
}

save_keys_to_file() {
    mkdir -p "$(dirname "${KEY_FILE}")"
    cat > "${KEY_FILE}" << EOF
UUID="${UUID}"
REALITY_PRIVATE="${REALITY_PRIVATE}"
REALITY_PUBLIC="${REALITY_PUBLIC}"
SHORT_ID="${SHORT_ID}"
HY2_PASSWORD="${HY2_PASSWORD}"
SS_PASSWORD="${SS_PASSWORD}"
SHADOWTLS_PASSWORD="${SHADOWTLS_PASSWORD}"
ANYTLS_PASSWORD="${ANYTLS_PASSWORD}"
SOCKS_USER="${SOCKS_USER}"
SOCKS_PASS="${SOCKS_PASS}"
EOF
    chmod 600 "${KEY_FILE}"
}
# ==================== 链接文件管理 ====================
save_links_to_files() {
    mkdir -p "${LINK_DIR}"
    echo -en "${ALL_LINKS_TEXT}"     > "${ALL_LINKS_FILE}"
    echo -en "${REALITY_LINKS}"      > "${REALITY_LINKS_FILE}"
    echo -en "${HYSTERIA2_LINKS}"    > "${HYSTERIA2_LINKS_FILE}"
    echo -en "${SOCKS5_LINKS}"       > "${SOCKS5_LINKS_FILE}"
    echo -en "${SHADOWTLS_LINKS}"    > "${SHADOWTLS_LINKS_FILE}"
    echo -en "${HTTPS_LINKS}"        > "${HTTPS_LINKS_FILE}"
    echo -en "${ANYTLS_LINKS}"       > "${ANYTLS_LINKS_FILE}"
    chmod 700 "${LINK_DIR}" 2>/dev/null || true
}

load_links_from_files() {
    mkdir -p "${LINK_DIR}"
    [[ -f "${ALL_LINKS_FILE}" ]]        && ALL_LINKS_TEXT=$(cat "${ALL_LINKS_FILE}")
    [[ -f "${REALITY_LINKS_FILE}" ]]    && REALITY_LINKS=$(cat "${REALITY_LINKS_FILE}")
    [[ -f "${HYSTERIA2_LINKS_FILE}" ]]  && HYSTERIA2_LINKS=$(cat "${HYSTERIA2_LINKS_FILE}")
    [[ -f "${SOCKS5_LINKS_FILE}" ]]     && SOCKS5_LINKS=$(cat "${SOCKS5_LINKS_FILE}")
    [[ -f "${SHADOWTLS_LINKS_FILE}" ]]  && SHADOWTLS_LINKS=$(cat "${SHADOWTLS_LINKS_FILE}")
    [[ -f "${HTTPS_LINKS_FILE}" ]]      && HTTPS_LINKS=$(cat "${HTTPS_LINKS_FILE}")
    [[ -f "${ANYTLS_LINKS_FILE}" ]]     && ANYTLS_LINKS=$(cat "${ANYTLS_LINKS_FILE}")
}

load_inbounds_from_config() {
    [[ ! -f "${CONFIG_FILE}" ]] && return 1
    command -v jq &>/dev/null || return 1
    INBOUND_TAGS=(); INBOUND_PORTS=(); INBOUND_PROTOS=(); INBOUND_SNIS=(); INBOUND_RELAY_TAGS=(); INBOUNDS_JSON=""
    local inbounds_count=$(jq '.inbounds | length' "${CONFIG_FILE}" 2>/dev/null || echo "0")
    [[ "$inbounds_count" -eq 0 ]] && return 1

    local inbound_list=""
    for ((i=0; i<inbounds_count; i++)); do
        local inbound=$(jq -c ".inbounds[${i}]" "${CONFIG_FILE}" 2>/dev/null)
        [[ -z "$inbound" ]] && continue
        [[ -z "$inbound_list" ]] && inbound_list="$inbound" || inbound_list="${inbound_list},${inbound}"
        local tag=$(echo "$inbound" | jq -r '.tag' 2>/dev/null)
        local port=$(echo "$inbound" | jq -r '.listen_port' 2>/dev/null)
        local type=$(echo "$inbound" | jq -r '.type' 2>/dev/null)
        [[ "$tag" == "shadowsocks-in-"* ]] && continue

        local proto="unknown"; local sni=""
        if [[ "$tag" == *"vless-in-"* ]]; then proto="Reality"; sni=$(echo "$inbound" | jq -r '.tls.server_name // ""' 2>/dev/null)
        elif [[ "$tag" == *"hy2-in-"* ]]; then proto="Hysteria2"; sni=$(echo "$inbound" | jq -r '.tls.server_name // ""' 2>/dev/null)
        elif [[ "$tag" == *"shadowtls-in-"* ]]; then proto="ShadowTLS v3"; sni=$(echo "$inbound" | jq -r '.handshake.server // ""' 2>/dev/null)
        elif [[ "$tag" == *"socks-in"* ]]; then proto="SOCKS5"
        elif [[ "$tag" == *"vless-tls-in-"* ]]; then proto="HTTPS"; sni=$(echo "$inbound" | jq -r '.tls.server_name // ""' 2>/dev/null)
        elif [[ "$tag" == *"anytls-in-"* ]]; then proto="AnyTLS"; sni=$(echo "$inbound" | jq -r '.tls.server_name // ""' 2>/dev/null)
        fi
        [[ -z "$sni" ]] && sni="${DEFAULT_SNI}"
        INBOUND_TAGS+=("$tag"); INBOUND_PORTS+=("$port"); INBOUND_PROTOS+=("$proto"); INBOUND_SNIS+=("$sni"); INBOUND_RELAY_TAGS+=("direct")
    done
    INBOUNDS_JSON="$inbound_list"

    # 恢复中转规则
    local route_rules=$(jq -c '.route.rules[]? // empty' "${CONFIG_FILE}" 2>/dev/null)
    [[ -n "$route_rules" ]] && while IFS= read -r rule; do
        local inbound_array=$(echo "$rule" | jq -r '.inbound[]? // empty' 2>/dev/null)
        local outbound=$(echo "$rule" | jq -r '.outbound // ""' 2>/dev/null)
        [[ -n "$outbound" && "$outbound" != "direct" ]] && while IFS= read -r inbound_tag; do
            for i in "${!INBOUND_TAGS[@]}"; do
                [[ "${INBOUND_TAGS[$i]}" == "$inbound_tag" ]] && INBOUND_RELAY_TAGS[$i]="$outbound" && break
            done
        done <<< "$inbound_array"
    done <<< "$route_rules"
    return 0
}

regenerate_links_from_config() {
    print_info "正在从配置文件重新生成链接..."
    ALL_LINKS_TEXT=""; REALITY_LINKS=""; HYSTERIA2_LINKS=""; SOCKS5_LINKS=""; SHADOWTLS_LINKS=""; HTTPS_LINKS=""; ANYTLS_LINKS=""
    [[ -f "${KEY_FILE}" ]] && source "${KEY_FILE}"
    [[ -z "${SERVER_IP}" ]] && get_ip
    [[ ! -f "${CONFIG_FILE}" ]] && { print_warning "配置文件不存在"; return 1; }
    local inbounds_count=$(jq '.inbounds | length' "${CONFIG_FILE}" 2>/dev/null || echo "0")
    for ((i=0; i<inbounds_count; i++)); do
        local inbound=$(jq -c ".inbounds[${i}]" "${CONFIG_FILE}" 2>/dev/null)
        local type=$(echo "$inbound" | jq -r '.type' 2>/dev/null)
        local port=$(echo "$inbound" | jq -r '.listen_port' 2>/dev/null)
        case "$type" in
            vless)
                if [[ "$(echo "$inbound" | jq -r '.tls.enabled // false')" == "true" ]]; then
                    if [[ "$(echo "$inbound" | jq -r '.tls.reality.enabled // false')" == "true" ]]; then
                        local uuid=$(echo "$inbound" | jq -r '.users[0].uuid // ""')
                        local sni=$(echo "$inbound" | jq -r '.tls.server_name // ""'); [[ -z "$sni" ]] && sni="${DEFAULT_SNI}"
                        local pbk=$(echo "$inbound" | jq -r '.tls.reality.public_key // ""'); [[ -z "$pbk" ]] && pbk="${REALITY_PUBLIC}"
                        local sid=$(echo "$inbound" | jq -r '.tls.reality.short_id[0] // ""'); [[ -z "$sid" ]] && sid="${SHORT_ID}"
                        local link="vless://${uuid}@${SERVER_IP}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=chrome&pbk=${pbk}&sid=${sid}&type=tcp#Reality-${SERVER_IP}"
                        local line="[Reality] ${SERVER_IP}:${port} (SNI: ${sni})\n${link}\n----------------------------------------\n\n"
                        ALL_LINKS_TEXT+="$line"; REALITY_LINKS+="$line"
                    else
                        local uuid=$(echo "$inbound" | jq -r '.users[0].uuid // ""')
                        local sni=$(echo "$inbound" | jq -r '.tls.server_name // ""'); [[ -z "$sni" ]] && sni="${DEFAULT_SNI}"
                        local link="vless://${uuid}@${SERVER_IP}:${port}?encryption=none&security=tls&sni=${sni}&type=tcp&allowInsecure=1#HTTPS-${SERVER_IP}"
                        local line="[HTTPS] ${SERVER_IP}:${port} (SNI: ${sni})\n${link}\n----------------------------------------\n\n"
                        ALL_LINKS_TEXT+="$line"; HTTPS_LINKS+="$line"
                    fi
                fi
                ;;
            hysteria2)
                local password=$(echo "$inbound" | jq -r '.users[0].password // ""')
                local sni=$(echo "$inbound" | jq -r '.tls.server_name // ""'); [[ -z "$sni" ]] && sni="${DEFAULT_SNI}"
                local link="hysteria2://${password}@${SERVER_IP}:${port}?insecure=1&sni=${sni}#Hysteria2-${SERVER_IP}"
                local line="[Hysteria2] ${SERVER_IP}:${port} (SNI: ${sni})\n${link}\n----------------------------------------\n\n"
                ALL_LINKS_TEXT+="$line"; HYSTERIA2_LINKS+="$line"
                ;;
            socks)
                local username=$(echo "$inbound" | jq -r '.users[0].username // ""')
                local password=$(echo "$inbound" | jq -r '.users[0].password // ""')
                local link
                [[ -n "$username" ]] && link="socks5://${username}:${password}@${SERVER_IP}:${port}#SOCKS5-${SERVER_IP}" || link="socks5://${SERVER_IP}:${port}#SOCKS5-${SERVER_IP}"
                local line="[SOCKS5] ${SERVER_IP}:${port}\n${link}\n----------------------------------------\n\n"
                ALL_LINKS_TEXT+="$line"; SOCKS5_LINKS+="$line"
                ;;
            shadowtls)
                local stls_pass=$(echo "$inbound" | jq -r '.users[0].password // ""')
                local sni=$(echo "$inbound" | jq -r '.handshake.server // ""'); [[ -z "$sni" ]] && sni="${DEFAULT_SNI}"
                local ss_inbound=$(jq -c ".inbounds[] | select(.tag == \"shadowsocks-in-${port}\")" "${CONFIG_FILE}" 2>/dev/null)
                local ss_pass=$(echo "$ss_inbound" | jq -r '.password // ""')
                local ss_method=$(echo "$ss_inbound" | jq -r '.method // "2022-blake3-aes-128-gcm"')
                local ss_userinfo=$(echo -n "${ss_method}:${ss_pass}" | base64 -w0 | sed 's/+/-/g; s/\//_/g; s/=//g')
                local plugin_json="{\"version\":\"3\",\"password\":\"${stls_pass}\",\"host\":\"${sni}\",\"port\":\"${port}\",\"address\":\"${SERVER_IP}\"}"
                local plugin_base64=$(echo -n "$plugin_json" | base64 -w0 | sed 's/+/-/g; s/\//_/g; s/=//g')
                local link="ss://${ss_userinfo}@${SERVER_IP}:${port}?shadow-tls=${plugin_base64}#ShadowTLS-${SERVER_IP}"
                local line="[ShadowTLS v3] ${SERVER_IP}:${port} (SNI: ${sni})\n${link}\n----------------------------------------\n\n"
                ALL_LINKS_TEXT+="$line"; SHADOWTLS_LINKS+="$line"
                ;;
            anytls)
                local password=$(echo "$inbound" | jq -r '.users[0].password // ""')
                local sni=$(echo "$inbound" | jq -r '.tls.server_name // ""'); [[ -z "$sni" ]] && sni="${DEFAULT_SNI}"
                local link="anytls://${password}@${SERVER_IP}:${port}?security=tls&fp=chrome&insecure=1&sni=${sni}&type=tcp#AnyTLS-${SERVER_IP}"
                local line="[AnyTLS] ${SERVER_IP}:${port} (SNI: ${sni})\n${link}\n----------------------------------------\n\n"
                ALL_LINKS_TEXT+="$line"; ANYTLS_LINKS+="$line"
                ;;
        esac
    done
    save_links_to_files
    print_success "链接重新生成完成"
}
# ==================== 网络工具 ====================
get_ip() {
    local ipv4=$(curl -s4m5 ifconfig.me || curl -s4m5 api.ipify.org || curl -s4m5 ip.sb)
    local ipv6=$(curl -s6m5 ifconfig.me || curl -s6m5 api6.ipify.org || curl -s6m5 ip.sb)
    [[ -n "$ipv4" ]] && echo -e "IPv4: ${ipv4}" || echo "无IPv4"
    [[ -n "$ipv6" ]] && echo -e "IPv6: ${ipv6}" || echo "无IPv6"
    if [[ -z "$ipv4" && -z "$ipv6" ]]; then print_error "无法获取IP"; exit 1; fi
    if [[ -n "$ipv4" ]]; then SERVER_IP="$ipv4"; SERVER_IPV6="$ipv6"
    else SERVER_IP="$ipv6"; INBOUND_IP_MODE="ipv6"; fi
    save_ip_config
}

check_port_in_use() { ss -tuln 2>/dev/null | grep -q ":${1} " && return 0 || return 1; }

read_port_with_check() {
    while true; do
        read -p "监听端口 [${1}]: " PORT; PORT=${PORT:-$1}
        [[ ! "$PORT" =~ ^[0-9]+$ || $PORT -lt 1 || $PORT -gt 65535 ]] && { print_error "端口无效"; continue; }
        check_port_in_use "$PORT" && { print_warning "端口占用"; continue; }
        break
    done
}

save_ip_config() {
    mkdir -p "$(dirname "${IP_CONFIG_FILE}")"
    cat > "${IP_CONFIG_FILE}" << EOF
SERVER_IP="${SERVER_IP}"
SERVER_IPV6="${SERVER_IPV6}"
INBOUND_IP_MODE="${INBOUND_IP_MODE}"
OUTBOUND_IP_MODE="${OUTBOUND_IP_MODE}"
EOF
}
load_ip_config() { [[ -f "${IP_CONFIG_FILE}" ]] && source "${IP_CONFIG_FILE}"; }

# ==================== 中转配置管理 ====================
save_relays_to_file() {
    mkdir -p "$(dirname "${RELAY_FILE}")"
    echo "# Sing-box 中转配置" > "${RELAY_FILE}"
    for i in "${!RELAY_TAGS[@]}"; do
        local b64=$(echo "${RELAY_JSONS[$i]}" | base64 -w0)
        echo "${RELAY_TAGS[$i]}|${RELAY_DESCS[$i]}|${b64}" >> "${RELAY_FILE}"
    done
}
load_relays_from_file() {
    RELAY_TAGS=(); RELAY_JSONS=(); RELAY_DESCS=()
    [[ ! -f "${RELAY_FILE}" ]] && return
    while IFS='|' read -r tag desc b64; do
        [[ "$tag" =~ ^# ]] && continue
        local json=$(echo "$b64" | base64 -d 2>/dev/null)
        [[ -n "$json" ]] && RELAY_TAGS+=("$tag") && RELAY_DESCS+=("$desc") && RELAY_JSONS+=("$json")
    done < "${RELAY_FILE}"
}

# ==================== 随机凭证生成 ====================
gen_random_uuid()      { uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid; }
gen_random_hex16()     { openssl rand -hex 16; }
gen_random_base64_16() { openssl rand -base64 16; }
gen_random_user()      { echo "user_$(openssl rand -hex 4)"; }

# ==================== 中转链接解析 ====================
parse_socks_link() {
    local link="$1"
    local data=$(echo "$link" | sed 's|socks5\?://||' | cut -d'#' -f1)
    local tag="relay-socks5-${#RELAY_TAGS[@]}"
    if [[ "$data" == *"@"* ]]; then
        local userpass=$(echo "$data" | cut -d'@' -f1)
        local username=$(echo "$userpass" | cut -d':' -f1)
        local password=$(echo "$userpass" | cut -d':' -f2-)
        local server_port=$(echo "$data" | cut -d'@' -f2)
        local server=$(echo "$server_port" | cut -d':' -f1)
        local port=$(echo "$server_port" | cut -d':' -f2)
        RELAY_TAGS+=("$tag")
        RELAY_JSONS+=("{\"type\":\"socks\",\"tag\":\"$tag\",\"server\":\"$server\",\"server_port\":$port,\"version\":\"5\",\"username\":\"$username\",\"password\":\"$password\"}")
        RELAY_DESCS+=("SOCKS5 $server:$port (认证)")
    else
        local server=$(echo "$data" | cut -d':' -f1)
        local port=$(echo "$data" | cut -d':' -f2)
        RELAY_TAGS+=("$tag")
        RELAY_JSONS+=("{\"type\":\"socks\",\"tag\":\"$tag\",\"server\":\"$server\",\"server_port\":$port,\"version\":\"5\"}")
        RELAY_DESCS+=("SOCKS5 $server:$port")
    fi
    save_relays_to_file
    print_success "已添加 SOCKS5 中转"
}

parse_http_link() {
    local link="$1"
    local proto=$(echo "$link" | cut -d':' -f1)
    local data=$(echo "$link" | sed 's|https\?://||')
    local tls="false"; [[ "$proto" == "https" ]] && tls="true"
    local tag="relay-http-${#RELAY_TAGS[@]}"
    if [[ "$data" == *"@"* ]]; then
        local userpass=$(echo "$data" | cut -d'@' -f1)
        local username=$(echo "$userpass" | cut -d':' -f1)
        local password=$(echo "$userpass" | cut -d':' -f2)
        local server_port=$(echo "$data" | cut -d'@' -f2 | cut -d'/' -f1)
        local server=$(echo "$server_port" | cut -d':' -f1)
        local port=$(echo "$server_port" | cut -d':' -f2)
        RELAY_TAGS+=("$tag")
        RELAY_JSONS+=("{\"type\":\"http\",\"tag\":\"$tag\",\"server\":\"$server\",\"server_port\":$port,\"username\":\"$username\",\"password\":\"$password\",\"tls\":{\"enabled\":$tls}}")
        RELAY_DESCS+=("HTTP(S) $server:$port (认证)")
    else
        local server=$(echo "$data" | cut -d':' -f1)
        local port=$(echo "$data" | cut -d':' -f2 | cut -d'/' -f1)
        RELAY_TAGS+=("$tag")
        RELAY_JSONS+=("{\"type\":\"http\",\"tag\":\"$tag\",\"server\":\"$server\",\"server_port\":$port,\"tls\":{\"enabled\":$tls}}")
        RELAY_DESCS+=("HTTP(S) $server:$port")
    fi
    save_relays_to_file
    print_success "已添加 HTTP(S) 中转"
}

parse_ss_link() {
    local link="$1"
    local data=$(echo "$link" | sed 's|ss://||' | cut -d'#' -f1)
    if [[ "$data" != *"@"* ]]; then print_error "SS 链接格式错误"; return 1; fi
    local userinfo=$(echo "$data" | cut -d'@' -f1)
    local server_port=$(echo "$data" | cut -d'@' -f2 | cut -d'?' -f1)
    local server=$(echo "$server_port" | cut -d':' -f1)
    local port=$(echo "$server_port" | cut -d':' -f2)
    local decoded=$(echo "$userinfo" | base64 -d 2>/dev/null)
    local method=$(echo "$decoded" | cut -d':' -f1)
    local password=$(echo "$decoded" | cut -d':' -f2-)
    local tag="relay-ss-${#RELAY_TAGS[@]}"
    RELAY_TAGS+=("$tag")
    RELAY_JSONS+=("{\"type\":\"shadowsocks\",\"tag\":\"$tag\",\"server\":\"$server\",\"server_port\":$port,\"method\":\"$method\",\"password\":\"$password\"}")
    RELAY_DESCS+=("Shadowsocks $server:$port")
    save_relays_to_file
    print_success "已添加 Shadowsocks 中转"
}

parse_vmess_link() {
    local link="$1"
    local base64_data=$(echo "$link" | sed 's|vmess://||')
    local json=$(echo "$base64_data" | base64 -d 2>/dev/null)
    [[ -z "$json" ]] && { print_error "VMess 解码失败"; return 1; }
    local server=$(echo "$json" | jq -r '.add // .address')
    local port=$(echo "$json" | jq -r '.port')
    local uuid=$(echo "$json" | jq -r '.id')
    local alterId=$(echo "$json" | jq -r '.aid // 0')
    local security=$(echo "$json" | jq -r '.scy // "auto"')
    local tag="relay-vmess-${#RELAY_TAGS[@]}"
    RELAY_TAGS+=("$tag")
    RELAY_JSONS+=("{\"type\":\"vmess\",\"tag\":\"$tag\",\"server\":\"$server\",\"server_port\":$port,\"uuid\":\"$uuid\",\"alter_id\":$alterId,\"security\":\"$security\"}")
    RELAY_DESCS+=("VMess $server:$port")
    save_relays_to_file
    print_success "已添加 VMess 中转"
}

parse_vless_link() {
    local link="$1"
    local data=$(echo "$link" | sed 's|vless://||')
    local uuid=$(echo "$data" | cut -d'@' -f1)
    local server_port_params=$(echo "$data" | cut -d'@' -f2)
    local server=$(echo "$server_port_params" | cut -d':' -f1)
    local port_params=$(echo "$server_port_params" | cut -d':' -f2)
    local port=$(echo "$port_params" | cut -d'?' -f1)
    local params=$(echo "$port_params" | grep -o '?.*' | sed 's|?||' | cut -d'#' -f1)
    local security="none"; local sni=""; local flow=""
    [[ "$params" =~ security=([^&]+) ]] && security="${BASH_REMATCH[1]}"
    [[ "$params" =~ sni=([^&]+) ]] && sni="${BASH_REMATCH[1]}"
    [[ "$params" =~ flow=([^&]+) ]] && flow="${BASH_REMATCH[1]}"
    local tls_config=""
    [[ "$security" == "tls" || "$security" == "reality" ]] && tls_config=",\"tls\":{\"enabled\":true,\"server_name\":\"$sni\"}"
    local flow_config=""; [[ -n "$flow" ]] && flow_config=",\"flow\":\"$flow\""
    local tag="relay-vless-${#RELAY_TAGS[@]}"
    RELAY_TAGS+=("$tag")
    RELAY_JSONS+=("{\"type\":\"vless\",\"tag\":\"$tag\",\"server\":\"$server\",\"server_port\":$port,\"uuid\":\"$uuid\"${flow_config}${tls_config}}")
    RELAY_DESCS+=("VLESS $server:$port")
    save_relays_to_file
    print_success "已添加 VLESS 中转"
}

parse_trojan_link() {
    local link="$1"
    local data=$(echo "$link" | sed 's|trojan://||')
    local password=$(echo "$data" | cut -d'@' -f1)
    local server_port_params=$(echo "$data" | cut -d'@' -f2)
    local server=$(echo "$server_port_params" | cut -d':' -f1)
    local port_params=$(echo "$server_port_params" | cut -d':' -f2)
    local port=$(echo "$port_params" | cut -d'?' -f1)
    local params=$(echo "$port_params" | grep -o '?.*' | sed 's|?||' | cut -d'#' -f1)
    local sni=""; [[ "$params" =~ sni=([^&]+) ]] && sni="${BASH_REMATCH[1]}"
    local tag="relay-trojan-${#RELAY_TAGS[@]}"
    RELAY_TAGS+=("$tag")
    RELAY_JSONS+=("{\"type\":\"trojan\",\"tag\":\"$tag\",\"server\":\"$server\",\"server_port\":$port,\"password\":\"$password\",\"tls\":{\"enabled\":true,\"server_name\":\"$sni\"}}")
    RELAY_DESCS+=("Trojan $server:$port")
    save_relays_to_file
    print_success "已添加 Trojan 中转"
}
# ==================== 节点添加（每个节点独立随机凭证） ====================
# Reality
setup_reality() {
    echo ""; read_port_with_check 443
    read -p "伪装域名 [${DEFAULT_SNI}]: " SNI; SNI=${SNI:-${DEFAULT_SNI}}
    local default_uuid=$(gen_random_uuid)
    echo -e "节点 UUID (回车使用随机):"
    read -p "UUID [${default_uuid}]: " use_uuid; use_uuid=${use_uuid:-$default_uuid}
    local inbound="{\"type\":\"vless\",\"tag\":\"vless-in-${PORT}\",\"listen\":\"::\",\"listen_port\":${PORT},\"users\":[{\"uuid\":\"${use_uuid}\",\"flow\":\"xtls-rprx-vision\"}],\"tls\":{\"enabled\":true,\"server_name\":\"${SNI}\",\"reality\":{\"enabled\":true,\"handshake\":{\"server\":\"${SNI}\",\"server_port\":443},\"private_key\":\"${REALITY_PRIVATE}\",\"short_id\":[\"${SHORT_ID}\"]}}}"
    [[ -z "$INBOUNDS_JSON" ]] && INBOUNDS_JSON="$inbound" || INBOUNDS_JSON="${INBOUNDS_JSON},${inbound}"
    LINK="vless://${use_uuid}@${SERVER_IP}:${PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=chrome&pbk=${REALITY_PUBLIC}&sid=${SHORT_ID}&type=tcp#Reality-${SERVER_IP}"
    local line="[Reality] ${SERVER_IP}:${PORT} (SNI: ${SNI})\n${LINK}\n----------------------------------------\n\n"
    ALL_LINKS_TEXT+="$line"; REALITY_LINKS+="$line"
    INBOUND_TAGS+=("vless-in-${PORT}"); INBOUND_PORTS+=("${PORT}"); INBOUND_PROTOS+=("Reality"); INBOUND_SNIS+=("${SNI}"); INBOUND_RELAY_TAGS+=("direct")
    print_success "Reality 添加完成"; save_links_to_files

    # 保存新节点信息，待服务启动成功后显示
    NEW_NODE_LINK="$LINK"
    NEW_NODE_EXTRA_INFO="UUID: ${use_uuid}  |  端口: ${PORT}\n伪装域名: ${SNI}"
}

# Hysteria2
setup_hysteria2() {
    echo ""; read_port_with_check 443
    read -p "伪装域名 [${DEFAULT_SNI}]: " HY2_SNI; HY2_SNI=${HY2_SNI:-${DEFAULT_SNI}}
    local default_pass=$(gen_random_hex16)
    echo -e "节点密码 (回车使用随机):"
    read -p "密码 [${default_pass}]: " use_pass; use_pass=${use_pass:-$default_pass}
    gen_cert_for_sni "${HY2_SNI}" || return 1
    local inbound="{\"type\":\"hysteria2\",\"tag\":\"hy2-in-${PORT}\",\"listen\":\"::\",\"listen_port\":${PORT},\"users\":[{\"password\":\"${use_pass}\"}],\"tls\":{\"enabled\":true,\"alpn\":[\"h3\"],\"server_name\":\"${HY2_SNI}\",\"certificate_path\":\"${CERT_DIR}/${HY2_SNI}/cert.pem\",\"key_path\":\"${CERT_DIR}/${HY2_SNI}/private.key\"}}"
    [[ -z "$INBOUNDS_JSON" ]] && INBOUNDS_JSON="$inbound" || INBOUNDS_JSON="${INBOUNDS_JSON},${inbound}"
    LINK="hysteria2://${use_pass}@${SERVER_IP}:${PORT}?insecure=1&sni=${HY2_SNI}#Hysteria2-${SERVER_IP}"
    local line="[Hysteria2] ${SERVER_IP}:${PORT} (SNI: ${HY2_SNI})\n${LINK}\n----------------------------------------\n\n"
    ALL_LINKS_TEXT+="$line"; HYSTERIA2_LINKS+="$line"
    INBOUND_TAGS+=("hy2-in-${PORT}"); INBOUND_PORTS+=("${PORT}"); INBOUND_PROTOS+=("Hysteria2"); INBOUND_SNIS+=("${HY2_SNI}"); INBOUND_RELAY_TAGS+=("direct")
    print_success "Hysteria2 添加完成"; save_links_to_files

    NEW_NODE_LINK="$LINK"
    NEW_NODE_EXTRA_INFO="密码: ${use_pass}  |  端口: ${PORT}\n伪装域名: ${HY2_SNI}"
}

# SOCKS5
setup_socks5() {
    echo ""; read_port_with_check 1080
    read -p "启用认证? [Y/n]: " ENABLE_AUTH; ENABLE_AUTH=${ENABLE_AUTH:-Y}
    local use_user=""; local use_pass=""; local inbound=""; local link=""
    if [[ "$ENABLE_AUTH" =~ ^[Yy]$ ]]; then
        local default_user=$(gen_random_user); local default_pass=$(gen_random_hex16)
        read -p "用户名 [${default_user}]: " use_user; use_user=${use_user:-$default_user}
        read -p "密码 [${default_pass}]: " use_pass; use_pass=${use_pass:-$default_pass}
        inbound="{\"type\":\"socks\",\"tag\":\"socks-in-${PORT}\",\"listen\":\"::\",\"listen_port\":${PORT},\"users\":[{\"username\":\"${use_user}\",\"password\":\"${use_pass}\"}]}"
        link="socks5://${use_user}:${use_pass}@${SERVER_IP}:${PORT}#SOCKS5-${SERVER_IP}"
        NEW_NODE_EXTRA_INFO="用户名: ${use_user}  |  密码: ${use_pass}\n端口: ${PORT}"
    else
        inbound="{\"type\":\"socks\",\"tag\":\"socks-in-${PORT}\",\"listen\":\"::\",\"listen_port\":${PORT}}"
        link="socks5://${SERVER_IP}:${PORT}#SOCKS5-${SERVER_IP}"
        NEW_NODE_EXTRA_INFO="无认证\n端口: ${PORT}"
    fi
    [[ -z "$INBOUNDS_JSON" ]] && INBOUNDS_JSON="$inbound" || INBOUNDS_JSON="${INBOUNDS_JSON},${inbound}"
    local line="[SOCKS5] ${SERVER_IP}:${PORT}\n${link}\n----------------------------------------\n\n"
    ALL_LINKS_TEXT+="$line"; SOCKS5_LINKS+="$line"
    INBOUND_TAGS+=("socks-in-${PORT}"); INBOUND_PORTS+=("${PORT}"); INBOUND_PROTOS+=("SOCKS5"); INBOUND_SNIS+=(""); INBOUND_RELAY_TAGS+=("direct")
    print_success "SOCKS5 添加完成"; save_links_to_files

    NEW_NODE_LINK="$link"
}

# ShadowTLS
setup_shadowtls() {
    echo ""; read_port_with_check 443
    read -p "伪装域名 [${DEFAULT_SNI}]: " SHADOWTLS_SNI; SHADOWTLS_SNI=${SHADOWTLS_SNI:-${DEFAULT_SNI}}
    local default_stls_pass=$(gen_random_hex16); local default_ss_pass=$(gen_random_base64_16)
    read -p "ShadowTLS密码 [${default_stls_pass}]: " use_stls_pass; use_stls_pass=${use_stls_pass:-$default_stls_pass}
    read -p "Shadowsocks密码 [${default_ss_pass}]: " use_ss_pass; use_ss_pass=${use_ss_pass:-$default_ss_pass}
    local inbound="{\"type\":\"shadowtls\",\"tag\":\"shadowtls-in-${PORT}\",\"listen\":\"::\",\"listen_port\":${PORT},\"version\":3,\"users\":[{\"password\":\"${use_stls_pass}\"}],\"handshake\":{\"server\":\"${SHADOWTLS_SNI}\",\"server_port\":443},\"strict_mode\":true,\"detour\":\"shadowsocks-in-${PORT}\"},{\"type\":\"shadowsocks\",\"tag\":\"shadowsocks-in-${PORT}\",\"listen\":\"127.0.0.1\",\"network\":\"tcp\",\"method\":\"2022-blake3-aes-128-gcm\",\"password\":\"${use_ss_pass}\"}"
    [[ -z "$INBOUNDS_JSON" ]] && INBOUNDS_JSON="$inbound" || INBOUNDS_JSON="${INBOUNDS_JSON},${inbound}"
    local ss_userinfo=$(echo -n "2022-blake3-aes-128-gcm:${use_ss_pass}" | base64 -w0 | sed 's/+/-/g; s/\//_/g; s/=//g')
    local plugin_json="{\"version\":\"3\",\"password\":\"${use_stls_pass}\",\"host\":\"${SHADOWTLS_SNI}\",\"port\":\"${PORT}\",\"address\":\"${SERVER_IP}\"}"
    local plugin_b64=$(echo -n "$plugin_json" | base64 -w0 | sed 's/+/-/g; s/\//_/g; s/=//g')
    LINK="ss://${ss_userinfo}@${SERVER_IP}:${PORT}?shadow-tls=${plugin_b64}#ShadowTLS-${SERVER_IP}"
    local line="[ShadowTLS v3] ${SERVER_IP}:${PORT} (SNI: ${SHADOWTLS_SNI})\n${LINK}\n----------------------------------------\n\n"
    ALL_LINKS_TEXT+="$line"; SHADOWTLS_LINKS+="$line"
    INBOUND_TAGS+=("shadowtls-in-${PORT}"); INBOUND_PORTS+=("${PORT}"); INBOUND_PROTOS+=("ShadowTLS v3"); INBOUND_SNIS+=("${SHADOWTLS_SNI}"); INBOUND_RELAY_TAGS+=("direct")
    print_success "ShadowTLS 添加完成"; save_links_to_files

    NEW_NODE_LINK="$LINK"
    NEW_NODE_EXTRA_INFO="ShadowTLS密码: ${use_stls_pass}  |  SS密码: ${use_ss_pass}\n端口: ${PORT}  |  伪装域名: ${SHADOWTLS_SNI}"
}

# HTTPS
setup_https() {
    echo ""; read_port_with_check 443
    read -p "伪装域名 [${DEFAULT_SNI}]: " HTTPS_SNI; HTTPS_SNI=${HTTPS_SNI:-${DEFAULT_SNI}}
    local default_uuid=$(gen_random_uuid)
    read -p "UUID [${default_uuid}]: " use_uuid; use_uuid=${use_uuid:-$default_uuid}
    gen_cert_for_sni "${HTTPS_SNI}" || return 1
    local inbound="{\"type\":\"vless\",\"tag\":\"vless-tls-in-${PORT}\",\"listen\":\"::\",\"listen_port\":${PORT},\"users\":[{\"uuid\":\"${use_uuid}\"}],\"tls\":{\"enabled\":true,\"server_name\":\"${HTTPS_SNI}\",\"certificate_path\":\"${CERT_DIR}/${HTTPS_SNI}/cert.pem\",\"key_path\":\"${CERT_DIR}/${HTTPS_SNI}/private.key\"}}"
    [[ -z "$INBOUNDS_JSON" ]] && INBOUNDS_JSON="$inbound" || INBOUNDS_JSON="${INBOUNDS_JSON},${inbound}"
    LINK="vless://${use_uuid}@${SERVER_IP}:${PORT}?encryption=none&security=tls&sni=${HTTPS_SNI}&type=tcp&allowInsecure=1#HTTPS-${SERVER_IP}"
    local line="[HTTPS] ${SERVER_IP}:${PORT} (SNI: ${HTTPS_SNI})\n${LINK}\n----------------------------------------\n\n"
    ALL_LINKS_TEXT+="$line"; HTTPS_LINKS+="$line"
    INBOUND_TAGS+=("vless-tls-in-${PORT}"); INBOUND_PORTS+=("${PORT}"); INBOUND_PROTOS+=("HTTPS"); INBOUND_SNIS+=("${HTTPS_SNI}"); INBOUND_RELAY_TAGS+=("direct")
    print_success "HTTPS 添加完成"; save_links_to_files

    NEW_NODE_LINK="$LINK"
    NEW_NODE_EXTRA_INFO="UUID: ${use_uuid}  |  端口: ${PORT}\n伪装域名: ${HTTPS_SNI}"
}

# AnyTLS
setup_anytls() {
    echo ""; read_port_with_check 443
    read -p "伪装域名 [${DEFAULT_SNI}]: " ANYTLS_SNI; ANYTLS_SNI=${ANYTLS_SNI:-${DEFAULT_SNI}}
    local default_pass=$(gen_random_hex16)
    read -p "密码 [${default_pass}]: " use_pass; use_pass=${use_pass:-$default_pass}
    gen_cert_for_sni "${ANYTLS_SNI}" || return 1
    local inbound="{\"type\":\"anytls\",\"tag\":\"anytls-in-${PORT}\",\"listen\":\"::\",\"listen_port\":${PORT},\"users\":[{\"password\":\"${use_pass}\"}],\"padding_scheme\":[],\"tls\":{\"enabled\":true,\"server_name\":\"${ANYTLS_SNI}\",\"certificate_path\":\"${CERT_DIR}/${ANYTLS_SNI}/cert.pem\",\"key_path\":\"${CERT_DIR}/${ANYTLS_SNI}/private.key\"}}"
    [[ -z "$INBOUNDS_JSON" ]] && INBOUNDS_JSON="$inbound" || INBOUNDS_JSON="${INBOUNDS_JSON},${inbound}"
    LINK="anytls://${use_pass}@${SERVER_IP}:${PORT}?security=tls&fp=chrome&insecure=1&sni=${ANYTLS_SNI}&type=tcp#AnyTLS-${SERVER_IP}"
    local line="[AnyTLS] ${SERVER_IP}:${PORT} (SNI: ${ANYTLS_SNI})\n${LINK}\n----------------------------------------\n\n"
    ALL_LINKS_TEXT+="$line"; ANYTLS_LINKS+="$line"
    INBOUND_TAGS+=("anytls-in-${PORT}"); INBOUND_PORTS+=("${PORT}"); INBOUND_PROTOS+=("AnyTLS"); INBOUND_SNIS+=("${ANYTLS_SNI}"); INBOUND_RELAY_TAGS+=("direct")
    print_success "AnyTLS 添加完成"; save_links_to_files

    NEW_NODE_LINK="$LINK"
    NEW_NODE_EXTRA_INFO="密码: ${use_pass}  |  端口: ${PORT}\n伪装域名: ${ANYTLS_SNI}"
}

# 其他辅助函数
cleanup_links() {
    rm -rf "${LINK_DIR}" 2>/dev/null || true
    ALL_LINKS_TEXT=""; REALITY_LINKS=""; HYSTERIA2_LINKS=""; SOCKS5_LINKS=""; SHADOWTLS_LINKS=""; HTTPS_LINKS=""; ANYTLS_LINKS=""
}

regenerate_all_links() {
    echo ""
    echo -e "${YELLOW}此操作将从配置文件重新生成所有节点链接${NC}"
    echo ""
    [[ ! -f "${CONFIG_FILE}" ]] && { print_error "配置文件不存在"; return 1; }
    cleanup_links
    if regenerate_links_from_config; then
        print_success "链接文件已重新生成，可在 [配置/查看节点] 中查看"
    else
        print_error "重新生成链接失败"
        return 1
    fi
}
# 放在 setup_anytls 函数之后，show_menu 之前
show_new_node_info() {
    if [[ -z "$NEW_NODE_LINK" ]]; then
        return
    fi
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}✅ 节点已启动，可直接复制链接：${NC}"
    echo -e "${YELLOW}${NEW_NODE_LINK}${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    if [[ -n "$NEW_NODE_EXTRA_INFO" ]]; then
        echo -e "$NEW_NODE_EXTRA_INFO"
    fi
    echo ""
    read -p "按回车继续..." _
}
# ==================== 协议选择菜单 ====================
show_menu() {
    # 检查 sing-box 是否已安装
    if ! command -v sing-box &>/dev/null; then
        print_error "sing-box 未安装，请先在主菜单选择 [7] 安装/更新 sing-box"
        return 1
    fi

    # 确保密钥已生成（首次安装后需要）
    gen_keys

    show_banner
    echo -e "${YELLOW}请选择要添加的协议节点:${NC}"
    echo ""
    echo -e "${GREEN}[1]${NC} VlessReality ${CYAN}→ 抗审查最强，伪装真实TLS，无需证书${NC} ${YELLOW}(⭐ 强烈推荐)${NC}"
    echo ""
    echo -e "${GREEN}[2]${NC} Hysteria2 ${CYAN}→ 基于QUIC，速度快，垃圾线路专用${NC}"
    echo ""
    echo -e "${GREEN}[3]${NC} SOCKS5 ${CYAN}→ 适合中转的代理协议${NC}"
    echo ""
    echo -e "${GREEN}[4]${NC} ShadowTLS v3 ${CYAN}→ TLS流量伪装${NC}"
    echo ""
    echo -e "${GREEN}[5]${NC} HTTPS ${CYAN}→ 标准HTTPS，可过CDN${NC}"
    echo ""
    echo -e "${GREEN}[6]${NC} AnyTLS ${CYAN}→ 通用TLS协议${NC}"
    echo ""
    read -p "选择 [1-6]: " choice

    # 清空上次添加的节点显示信息
    NEW_NODE_LINK=""
    NEW_NODE_EXTRA_INFO=""

    case $choice in
        1) setup_reality ;;
        2) setup_hysteria2 ;;
        3) setup_socks5 ;;
        4) setup_shadowtls ;;
        5) setup_https ;;
        6) setup_anytls ;;
        *) print_error "无效选项"; return 1 ;;
    esac

    if [[ -n "$INBOUNDS_JSON" ]]; then
        if generate_config && start_svc; then
            # 成功后才显示新节点的链接
            show_new_node_info
        fi
    fi
}

# ==================== 配置查看菜单 ====================
config_and_view_menu() {
    while true; do
        show_banner
        echo -e "${CYAN}╔═══════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║              ${GREEN}配置 / 查看节点菜单${CYAN}        ║${NC}"
        echo -e "${CYAN}╚═══════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  ${GREEN}[1]${NC} 重新加载配置并启动服务"
        echo ""
        echo -e "  ${GREEN}[2]${NC} 查看全部节点链接"
        echo ""
        echo -e "  ${GREEN}[3]${NC} 查看 Reality 节点"
        echo ""
        echo -e "  ${GREEN}[4]${NC} 查看 Hysteria2 节点"
        echo ""
        echo -e "  ${GREEN}[5]${NC} 查看 SOCKS5 节点"
        echo ""
        echo -e "  ${GREEN}[6]${NC} 查看 ShadowTLS 节点"
        echo ""
        echo -e "  ${GREEN}[7]${NC} 查看 HTTPS 节点"
        echo ""
        echo -e "  ${GREEN}[8]${NC} 查看 AnyTLS 节点"
        echo ""
        echo -e "  ${GREEN}[9]${NC} 删除单个节点"
        echo ""
        echo -e "  ${GREEN}[10]${NC} 删除全部节点"
        echo ""
        echo -e "  ${GREEN}[0]${NC} 返回主菜单"
        echo ""
        
        read -p "请选择 [0-10]: " cv_choice
        
        case $cv_choice in
            1)
                if [[ -f "${CONFIG_FILE}" ]]; then
                    generate_config && start_svc
                    print_success "配置已重新加载并启动服务"
                else
                    print_error "配置文件不存在，请先添加节点"
                fi
                read -p "按回车返回..." _
                ;;
            2)
                clear
                echo -e "${YELLOW}全部节点链接:${NC}"
                echo ""
                if [[ -z "$ALL_LINKS_TEXT" ]]; then
                    echo "(暂无节点)"
                else
                    echo -e "$ALL_LINKS_TEXT"
                fi
                echo ""
                read -p "按回车返回..." _
                ;;
            3)
                clear
                echo -e "${YELLOW}Reality 节点:${NC}"
                echo ""
                if [[ -z "$REALITY_LINKS" ]]; then
                    echo "(暂无 Reality 节点)"
                else
                    echo -e "$REALITY_LINKS"
                fi
                echo ""
                read -p "按回车返回..." _
                ;;
            4)
                clear
                echo -e "${YELLOW}Hysteria2 节点:${NC}"
                echo ""
                if [[ -z "$HYSTERIA2_LINKS" ]]; then
                    echo "(暂无 Hysteria2 节点)"
                else
                    echo -e "$HYSTERIA2_LINKS"
                fi
                echo ""
                read -p "按回车返回..." _
                ;;
            5)
                clear
                echo -e "${YELLOW}SOCKS5 节点:${NC}"
                echo ""
                if [[ -z "$SOCKS5_LINKS" ]]; then
                    echo "(暂无 SOCKS5 节点)"
                else
                    echo -e "$SOCKS5_LINKS"
                fi
                echo ""
                read -p "按回车返回..." _
                ;;
            6)
                clear
                echo -e "${YELLOW}ShadowTLS 节点:${NC}"
                echo ""
                if [[ -z "$SHADOWTLS_LINKS" ]]; then
                    echo "(暂无 ShadowTLS 节点)"
                else
                    echo -e "$SHADOWTLS_LINKS"
                    echo -e "${CYAN}提示: 可直接复制上方 ss:// 链接导入客户端${NC}"
                fi
                echo ""
                read -p "按回车返回..." _
                ;;
            7)
                clear
                echo -e "${YELLOW}HTTPS 节点:${NC}"
                echo ""
                if [[ -z "$HTTPS_LINKS" ]]; then
                    echo "(暂无 HTTPS 节点)"
                else
                    echo -e "$HTTPS_LINKS"
                fi
                echo ""
                read -p "按回车返回..." _
                ;;
            8)
                clear
                echo -e "${YELLOW}AnyTLS 节点:${NC}"
                echo ""
                if [[ -z "$ANYTLS_LINKS" ]]; then
                    echo "(暂无 AnyTLS 节点)"
                else
                    echo -e "$ANYTLS_LINKS"
                fi
                echo ""
                read -p "按回车返回..." _
                ;;
            9)
                delete_single_node
                read -p "按回车返回..." _
                ;;
            10)
                delete_all_nodes
                read -p "按回车返回..." _
                ;;
            0)
                break
                ;;
            *)
                print_error "无效选项"
                ;;
        esac
    done
}

# ==================== 节点删除 ====================
delete_single_node() {
    if [[ ${#INBOUND_TAGS[@]} -eq 0 ]]; then
        print_warning "当前没有可删除的节点"
        return 1
    fi
    
    echo ""
    echo -e "${CYAN}当前节点列表:${NC}"
    for i in "${!INBOUND_TAGS[@]}"; do
        idx=$((i+1))
        echo -e "  ${GREEN}[${idx}]${NC} 协议: ${INBOUND_PROTOS[$i]}, 端口: ${INBOUND_PORTS[$i]}, SNI: ${INBOUND_SNIS[$i]}, TAG: ${INBOUND_TAGS[$i]}"
    done
    echo ""
    echo -e "${RED}警告: 删除节点后无法恢复！${NC}"
    read -p "请输入要删除的节点序号 (输入 0 取消): " node_idx
    
    if [[ "$node_idx" == "0" ]]; then
        print_info "取消删除操作"
        return 0
    fi
    
    if ! [[ "$node_idx" =~ ^[0-9]+$ ]] || (( node_idx < 1 || node_idx > ${#INBOUND_TAGS[@]} )); then
        print_error "序号无效"
        return 1
    fi
    
    local index=$((node_idx-1))
    local tag="${INBOUND_TAGS[$index]}"
    local port="${INBOUND_PORTS[$index]}"
    local proto="${INBOUND_PROTOS[$index]}"
    local sni="${INBOUND_SNIS[$index]}"
    
    echo ""
    echo -e "${YELLOW}确认删除以下节点:${NC}"
    echo -e "  协议: ${proto}"
    echo -e "  端口: ${port}"
    echo -e "  SNI: ${sni}"
    echo -e "  TAG: ${tag}"
    echo ""
    
    read -p "确认删除? (y/N): " confirm_delete
    confirm_delete=${confirm_delete:-N}
    
    if [[ ! "$confirm_delete" =~ ^[Yy]$ ]]; then
        print_info "取消删除操作"
        return 0
    fi
    
    if [[ -f "${CONFIG_FILE}" ]] && command -v jq &>/dev/null; then
        local temp_config=$(mktemp)
        if [[ "$proto" == "ShadowTLS v3" ]]; then
            local ss_tag="shadowsocks-in-${port}"
            jq --arg tag "$tag" --arg ss_tag "$ss_tag" '.inbounds |= map(select(.tag != $tag and .tag != $ss_tag))' "${CONFIG_FILE}" > "$temp_config"
        else
            jq --arg tag "$tag" '.inbounds |= map(select(.tag != $tag))' "${CONFIG_FILE}" > "$temp_config"
        fi
        mv "$temp_config" "${CONFIG_FILE}"
        
        unset INBOUND_TAGS[$index]
        unset INBOUND_PORTS[$index]
        unset INBOUND_PROTOS[$index]
        unset INBOUND_SNIS[$index]
        unset INBOUND_RELAY_TAGS[$index]
        
        INBOUND_TAGS=("${INBOUND_TAGS[@]}")
        INBOUND_PORTS=("${INBOUND_PORTS[@]}")
        INBOUND_PROTOS=("${INBOUND_PROTOS[@]}")
        INBOUND_SNIS=("${INBOUND_SNIS[@]}")
        INBOUND_RELAY_TAGS=("${INBOUND_RELAY_TAGS[@]}")
        
        load_inbounds_from_config
        regenerate_links_from_config
        
        if command -v systemctl &>/dev/null; then
            systemctl restart sing-box
            sleep 2
            systemctl is-active --quiet sing-box && print_success "节点已删除，服务已重启" || print_error "服务重启失败"
        elif command -v rc-service &>/dev/null; then
            rc-service sing-box restart
            print_success "节点已删除"
        fi
    else
        print_error "无法删除节点"
        return 1
    fi
}

delete_all_nodes() {
    echo ""
    echo -e "${RED}⚠️  警告: 此操作将删除所有节点配置！${NC}"
    echo -e "${YELLOW}当前共有 ${#INBOUND_TAGS[@]} 个节点${NC}"
    echo ""
    read -p "确认删除所有节点? (输入 'YES' 确认): " confirm_delete
    
    if [[ "$confirm_delete" != "YES" ]]; then
        print_info "取消删除操作"
        return 0
    fi
    
    INBOUNDS_JSON=""
    INBOUND_TAGS=()
    INBOUND_PORTS=()
    INBOUND_PROTOS=()
    INBOUND_SNIS=()
    INBOUND_RELAY_TAGS=()
    
    cat > ${CONFIG_FILE} << EOFCONFIG
{
  "log": {"level": "info", "timestamp": true},
  "dns": {
    "servers": [{"tag": "local", "type": "local"}, {"tag": "remote", "type": "udp", "server": "8.8.8.8"}],
    "final": "remote"
  },
  "inbounds": [],
  "outbounds": [{"type": "direct", "tag": "direct"}],
  "route": {"final": "direct", "default_domain_resolver": "local"}
}
EOFCONFIG
    
    if command -v systemctl &>/dev/null; then
        systemctl stop sing-box 2>/dev/null || true
    elif command -v rc-service &>/dev/null; then
        rc-service sing-box stop 2>/dev/null || true
    fi
    
    cleanup_links
    print_success "所有节点已删除，配置文件已重置"
    
    read -p "是否启动空配置的 sing-box 服务? (y/N): " restart_service
    restart_service=${restart_service:-N}
    if [[ "$restart_service" =~ ^[Yy]$ ]]; then
        start_svc
    fi
}

# ==================== 中转管理菜单 ====================
setup_relay() {
    load_relays_from_file
    
    while true; do
        echo ""
        echo -e "${CYAN}╔═══════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║              ${GREEN}中转配置菜单${CYAN}                  ║${NC}"
        echo -e "${CYAN}╚═══════════════════════════════════════════════════════╝${NC}"
        echo ""
        
        if [[ ${#RELAY_TAGS[@]} -gt 0 ]]; then
            echo -e "${YELLOW}当前中转列表:${NC}"
            for i in "${!RELAY_TAGS[@]}"; do
                idx=$((i+1))
                echo -e "  ${GREEN}[${idx}]${NC} ${RELAY_DESCS[$i]}"
            done
            echo ""
        else
            echo -e "${YELLOW}当前没有配置中转${NC}"
            echo ""
        fi
        
        echo -e "  ${GREEN}[1]${NC} 添加新的中转链接"
        echo -e "  ${GREEN}[2]${NC} 为节点配置中转"
        echo -e "  ${GREEN}[3]${NC} 删除中转链接"
        echo -e "  ${GREEN}[0]${NC} 返回主菜单"
        echo ""
        read -p "请选择 [0-3]: " r_choice
        
        case $r_choice in
            1)
                echo ""
                echo -e "${CYAN}支持的中转协议格式:${NC}"
                echo -e "  SOCKS5, HTTP(S), Shadowsocks, VMess, VLESS, Trojan"
                echo -e "  直接粘贴分享链接即可"
                read -p "粘贴中转链接: " RELAY_LINK
                if [[ -n "$RELAY_LINK" ]]; then
                    if [[ "$RELAY_LINK" =~ ^socks ]]; then parse_socks_link "$RELAY_LINK"
                    elif [[ "$RELAY_LINK" =~ ^https? ]]; then parse_http_link "$RELAY_LINK"
                    elif [[ "$RELAY_LINK" =~ ^ss:// ]]; then parse_ss_link "$RELAY_LINK"
                    elif [[ "$RELAY_LINK" =~ ^vmess:// ]]; then parse_vmess_link "$RELAY_LINK"
                    elif [[ "$RELAY_LINK" =~ ^vless:// ]]; then parse_vless_link "$RELAY_LINK"
                    elif [[ "$RELAY_LINK" =~ ^trojan:// ]]; then parse_trojan_link "$RELAY_LINK"
                    else print_error "不支持的链接格式"
                    fi
                fi
                ;;
            2)
                if [[ ${#INBOUND_TAGS[@]} -eq 0 ]]; then
                    print_warning "请先添加节点"; continue
                fi
                if [[ ${#RELAY_TAGS[@]} -eq 0 ]]; then
                    print_warning "请先添加中转"; continue
                fi
                echo -e "选择要配置中转的节点:"
                for i in "${!INBOUND_TAGS[@]}"; do
                    idx=$((i+1))
                    local rt="${INBOUND_RELAY_TAGS[$i]}"
                    local desc="直连"
                    if [[ "$rt" != "direct" ]]; then
                        for j in "${!RELAY_TAGS[@]}"; do
                            [[ "${RELAY_TAGS[$j]}" == "$rt" ]] && desc="中转: ${RELAY_DESCS[$j]}" && break
                        done
                    fi
                    echo -e "  ${GREEN}[${idx}]${NC} ${INBOUND_PROTOS[$i]}:${INBOUND_PORTS[$i]} → ${YELLOW}${desc}${NC}"
                done
                read -p "节点序号: " node_idx
                if [[ "$node_idx" =~ ^[0-9]+$ ]] && (( node_idx >= 1 && node_idx <= ${#INBOUND_TAGS[@]} )); then
                    local n=$((node_idx-1))
                    echo -e "选择中转: [0] 直连"
                    for i in "${!RELAY_TAGS[@]}"; do echo -e "  ${GREEN}[$((i+1))]${NC} ${RELAY_DESCS[$i]}"; done
                    read -p "中转序号: " relay_idx
                    if [[ "$relay_idx" == "0" ]]; then
                        INBOUND_RELAY_TAGS[$n]="direct"
                    elif [[ "$relay_idx" =~ ^[0-9]+$ ]] && (( relay_idx >= 1 && relay_idx <= ${#RELAY_TAGS[@]} )); then
                        INBOUND_RELAY_TAGS[$n]="${RELAY_TAGS[$((relay_idx-1))]}"
                    else continue; fi
                    generate_config && start_svc
                fi
                ;;
            3)
                if [[ ${#RELAY_TAGS[@]} -eq 0 ]]; then continue; fi
                for i in "${!RELAY_TAGS[@]}"; do echo -e "  ${GREEN}[$((i+1))]${NC} ${RELAY_DESCS[$i]}"; done
                read -p "删除序号 (0全部, -1取消): " del_idx
                if [[ "$del_idx" == "0" ]]; then
                    RELAY_TAGS=(); RELAY_JSONS=(); RELAY_DESCS=(); rm -f "${RELAY_FILE}"
                    INBOUND_RELAY_TAGS=("${INBOUND_RELAY_TAGS[@]/*/direct}")
                    save_relays_to_file; generate_config && start_svc
                elif [[ "$del_idx" =~ ^[0-9]+$ ]] && (( del_idx >= 1 && del_idx <= ${#RELAY_TAGS[@]} )); then
                    local d=$((del_idx-1))
                    local del_tag="${RELAY_TAGS[$d]}"
                    unset RELAY_TAGS[$d]; unset RELAY_JSONS[$d]; unset RELAY_DESCS[$d]
                    RELAY_TAGS=("${RELAY_TAGS[@]}"); RELAY_JSONS=("${RELAY_JSONS[@]}"); RELAY_DESCS=("${RELAY_DESCS[@]}")
                    for i in "${!INBOUND_RELAY_TAGS[@]}"; do
                        [[ "${INBOUND_RELAY_TAGS[$i]}" == "$del_tag" ]] && INBOUND_RELAY_TAGS[$i]="direct"
                    done
                    save_relays_to_file; generate_config && start_svc
                fi
                ;;
            0) break ;;
            *) print_error "无效选项" ;;
        esac
    done
}

# ==================== IP 配置菜单 ====================
ip_config_menu() {
    while true; do
        clear
        echo -e "${CYAN}╔═══════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║              ${GREEN}出入站 IP 配置${CYAN}                ║${NC}"
        echo -e "${CYAN}╚═══════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "${YELLOW}当前配置:${NC}"
        echo -e "  IPv4 地址: ${GREEN}${SERVER_IP}${NC}"
        [[ -n "$SERVER_IPV6" ]] && echo -e "  IPv6 地址: ${GREEN}${SERVER_IPV6}${NC}"
        echo -e "  入站模式: ${GREEN}${INBOUND_IP_MODE}${NC}"
        echo -e "  出站模式: ${GREEN}${OUTBOUND_IP_MODE}${NC}"
        echo ""
        echo -e "  ${GREEN}[1]${NC} 设置入站为 IPv4"
        echo -e "  ${GREEN}[2]${NC} 设置入站为 IPv6"
        echo -e "  ${GREEN}[3]${NC} 设置出站为 IPv4"
        echo -e "  ${GREEN}[4]${NC} 设置出站为 IPv6"
        echo -e "  ${GREEN}[5]${NC} 设置出站为双栈 (IPv4+IPv6)"
        echo -e "  ${GREEN}[6]${NC} 手动修改 IPv4 地址"
        echo -e "  ${GREEN}[7]${NC} 手动修改 IPv6 地址"
        echo -e "  ${GREEN}[0]${NC} 返回主菜单"
        echo ""
        read -p "请选择 [0-7]: " ip_choice
        
        case $ip_choice in
            1) INBOUND_IP_MODE="ipv4"; save_ip_config ;;
            2) INBOUND_IP_MODE="ipv6"; save_ip_config ;;
            3) OUTBOUND_IP_MODE="ipv4"; save_ip_config ;;
            4) OUTBOUND_IP_MODE="ipv6"; save_ip_config ;;
            5) OUTBOUND_IP_MODE="dual"; save_ip_config ;;
            6) read -p "请输入 IPv4 地址: " new_ipv4; [[ -n "$new_ipv4" ]] && SERVER_IP="$new_ipv4" && save_ip_config ;;
            7) read -p "请输入 IPv6 地址: " new_ipv6; [[ -n "$new_ipv6" ]] && SERVER_IPV6="$new_ipv6" && save_ip_config ;;
            0) break ;;
            *) print_error "无效选项" ;;
        esac
        [[ "$ip_choice" != "0" ]] && read -p "按回车继续..." _
    done
}

# ==================== 保活（cron + 开机自启 cron） ====================
setup_keepalive() {
    # 确保 cron 守护进程已启动且开机自启
    if command -v systemctl &>/dev/null; then
        systemctl enable cron 2>/dev/null || systemctl enable crond 2>/dev/null || true
        systemctl start cron 2>/dev/null || systemctl start crond 2>/dev/null || true
    elif command -v rc-service &>/dev/null; then
        rc-update add crond default 2>/dev/null || true
        rc-service crond start 2>/dev/null || true
    fi

    local keepalive_cmd="*/5 * * * * root pgrep sing-box >/dev/null || (systemctl restart sing-box 2>/dev/null || rc-service sing-box restart)"
    if [[ -f /etc/cron.d/sing-box-keepalive ]]; then
        print_info "保活任务已存在"
    else
        echo "$keepalive_cmd" > /etc/cron.d/sing-box-keepalive
        print_success "已添加保活任务（每5分钟检查，重启后自动生效）"
    fi
    case $1 in
        enable) : ;;
        disable) rm -f /etc/cron.d/sing-box-keepalive; print_success "已关闭保活任务" ;;
    esac
}

# ==================== 卸载 ====================
delete_self() {
    echo -e "${YELLOW}此操作将卸载 sing-box、删除所有配置和脚本，且无法恢复。${NC}"
    read -p "确认完全卸载？(y/N): " CONFIRM_DELETE
    if [[ ! "$CONFIRM_DELETE" =~ ^[Yy]$ ]]; then
        print_info "已取消"; return 0
    fi
    
    if command -v systemctl &>/dev/null; then
        systemctl stop sing-box 2>/dev/null || true
        systemctl disable sing-box 2>/dev/null || true
        rm -f /etc/systemd/system/sing-box.service
    elif command -v rc-service &>/dev/null; then
        rc-service sing-box stop 2>/dev/null || true
        rc-update del sing-box 2>/dev/null || true
        rm -f /etc/init.d/sing-box
    fi
    
    rm -f ${INSTALL_DIR}/sing-box /usr/local/bin/sb
    rm -rf /etc/sing-box /var/log/sing-box /tmp/sb.tar.gz /tmp/sing-box-*
    rm -f /etc/cron.d/sing-box-keepalive
    
    print_success "已完全卸载"; exit 0
}

# ==================== 快捷命令 ====================
setup_sb_shortcut() {
    print_info "创建快捷命令 sb..."
    if [[ ! -f "${SCRIPT_PATH}" ]]; then
        print_warning "当前脚本并非磁盘文件，跳过创建 sb"
        return
    fi
    cat > /usr/local/bin/sb << EOSB
#!/bin/bash
bash "${SCRIPT_PATH}" "\$@"
EOSB
    chmod +x /usr/local/bin/sb
    print_success "已创建快捷命令: sb"
}

# ==================== 配置生成 ====================
generate_config() {
    print_info "生成最终配置文件..."
    [[ -z "$INBOUNDS_JSON" ]] && { print_error "未找到任何入站节点，请先添加节点"; return 1; }
    load_relays_from_file

    local outbounds_array=()
    for relay_json in "${RELAY_JSONS[@]}"; do outbounds_array+=("$relay_json"); done
    outbounds_array+=('{"type": "direct", "tag": "direct"}')
    local outbounds="["
    for i in "${!outbounds_array[@]}"; do
        [[ $i -gt 0 ]] && outbounds+=", "
        outbounds+="${outbounds_array[$i]}"
    done
    outbounds+="]"

    local route_rules=()
    for i in "${!INBOUND_TAGS[@]}"; do
        local rt="${INBOUND_RELAY_TAGS[$i]}"
        [[ "$rt" != "direct" ]] && route_rules+=("{\"inbound\":[\"${INBOUND_TAGS[$i]}\"],\"outbound\":\"${rt}\"}")
    done

    local route_json
    if [[ ${#route_rules[@]} -gt 0 ]]; then
        route_json="{\"rules\":["
        for i in "${!route_rules[@]}"; do
            [[ $i -gt 0 ]] && route_json+=","
            route_json+="${route_rules[$i]}"
        done
        route_json+="],\"final\":\"direct\",\"default_domain_resolver\":\"local\"}"
    else
        route_json="{\"final\":\"direct\",\"default_domain_resolver\":\"local\"}"
    fi

    local dns_json
    dns_json='{
    "servers": [
      {"tag": "local", "type": "local"},
      {"tag": "remote", "type": "udp", "server": "8.8.8.8"}
    ],
    "final": "remote"'
    [[ "$OUTBOUND_IP_MODE" == "ipv6" ]] && dns_json+=',"strategy": "prefer_ipv6"'
    [[ "$OUTBOUND_IP_MODE" == "ipv4" ]] && dns_json+=',"strategy": "prefer_ipv4"'
    dns_json+='}'

    cat > ${CONFIG_FILE} << EOFCONFIG
{
  "log": {"level": "info", "timestamp": true},
  "dns": ${dns_json},
  "inbounds": [${INBOUNDS_JSON}],
  "outbounds": ${outbounds},
  "route": ${route_json}
}
EOFCONFIG
    print_success "配置文件生成完成"
}

start_svc() {
    print_info "验证配置文件..."
    ${INSTALL_DIR}/sing-box check -c ${CONFIG_FILE} >/dev/null 2>&1 || { print_error "配置验证失败"; cat ${CONFIG_FILE}; return 1; }
    if command -v systemctl &>/dev/null; then
        systemctl restart sing-box
        sleep 2
        systemctl is-active --quiet sing-box && print_success "服务启动成功" || { print_error "启动失败"; journalctl -u sing-box -n 10 --no-pager; return 1; }
    elif command -v rc-service &>/dev/null; then
        rc-service sing-box restart
        sleep 2
        rc-service sing-box status &>/dev/null && print_success "服务启动成功" || print_error "启动失败"
    fi
}

# ==================== 主菜单 ====================
show_main_menu() {
    show_banner
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║          ${GREEN}Sing-Box 一键管理面板${CYAN}          ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}当前出入站配置:${NC}"
    if [[ -n "$SERVER_IP" ]]; then
        echo -e "  IPv4 地址: ${GREEN}${SERVER_IP}${NC}"
    fi
    if [[ -n "$SERVER_IPV6" ]]; then
        echo -e "  IPv6 地址: ${GREEN}${SERVER_IPV6}${NC}"
    fi
    echo -e "  入站模式: ${GREEN}${INBOUND_IP_MODE}${NC}     出站模式: ${GREEN}${OUTBOUND_IP_MODE}${NC}"
    echo -e "  当前节点数: ${GREEN}${#INBOUND_TAGS[@]}${NC}"
    if [[ -f /etc/cron.d/sing-box-keepalive ]]; then
        echo -e "  保活任务: ${GREEN}已开启${NC}"
    else
        echo -e "  保活任务: ${YELLOW}未开启${NC}"
    fi
    echo ""
    echo -e "  ${GREEN}[1]${NC} 添加/继续添加节点"
    echo -e "  ${GREEN}[2]${NC} 中转配置 (添加/配置/删除)"
    echo -e "  ${GREEN}[3]${NC} 出入站配置 (IPv4/IPv6)"
    echo -e "  ${GREEN}[4]${NC} 配置 / 查看节点"
    echo -e "  ${GREEN}[5]${NC} 重新生成链接文件"
    echo -e "  ${GREEN}[6]${NC} 开启/关闭保活"
    echo -e "  ${GREEN}[7]${NC} 安装/更新 sing-box"
    echo -e "  ${GREEN}[8]${NC} 完全卸载脚本"
    echo -e "  ${GREEN}[0]${NC} 退出脚本"
    echo ""
}

# ==================== 主循环 ====================
main_menu() {
    while true; do
        if [[ -f "${CONFIG_FILE}" ]]; then
            load_inbounds_from_config
        fi
        load_relays_from_file
        load_ip_config
        
        show_main_menu
        read -p "请选择 [0-8]: " m_choice
        
        case $m_choice in
            1) show_menu ;;
            2) setup_relay ;;
            3) ip_config_menu ;;
            4) config_and_view_menu ;;
            5) regenerate_all_links ;;
            6) 
                echo -e "  ${GREEN}[1]${NC} 开启保活  ${GREEN}[2]${NC} 关闭保活"
                read -p "选择: " ka
                case $ka in
                    1) setup_keepalive enable ;;
                    2) setup_keepalive disable ;;
                esac
                ;;
            7) install_or_update_singbox ;;
            8) delete_self ;;
            0) print_info "已退出"; exit 0 ;;
            *) print_error "无效选项" ;;
        esac
        echo ""
        [[ "$m_choice" != "0" ]] && read -p "按回车返回主菜单..." _
    done
}

# ==================== 初始化入口 ====================
main() {
    [[ $EUID -ne 0 ]] && { print_error "需要 root 权限"; exit 1; }
    detect_system
    ensure_deps
    mkdir -p /etc/sing-box
    if ! command -v sing-box &>/dev/null; then
        print_warning "sing-box 未安装，请从主菜单选择 [7] 先安装"
    else
        gen_keys
    fi
    load_ip_config
    [[ -z "${SERVER_IP}" ]] && get_ip
    setup_sb_shortcut
    [[ -f "${CONFIG_FILE}" ]] && load_inbounds_from_config
    load_relays_from_file
    load_links_from_files
    [[ -f "${CONFIG_FILE}" && -z "$ALL_LINKS_TEXT" ]] && regenerate_links_from_config
    main_menu
}

main
