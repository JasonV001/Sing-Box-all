#!/bin/bash

# ==================== 颜色定义 ====================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'

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
INBOUNDS_JSON=""
ALL_LINKS_TEXT=""
SERVER_IP=""
REALITY_LINKS=""
HYSTERIA2_LINKS=""
SOCKS5_LINKS=""
SHADOWTLS_LINKS=""
HTTPS_LINKS=""
ANYTLS_LINKS=""

SERVER_IPV6=""
INBOUND_IP_MODE="ipv4"
OUTBOUND_IP_MODE="dual"
IP_CONFIG_FILE="/etc/sing-box/ip_config.conf"

RELAY_TAGS=()
RELAY_JSONS=()
RELAY_DESCS=()
RELAY_FILE="/etc/sing-box/relays.conf"

INBOUND_TAGS=()
INBOUND_PORTS=()
INBOUND_PROTOS=()
INBOUND_RELAY_TAGS=()
INBOUND_SNIS=()

# 全局密钥
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

# ==================== 打印函数 ====================
print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }
show_banner() { clear; echo ""; }

# ==================== 系统检测（支持 Alpine） ====================
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

# ==================== 安装依赖与 sing-box（支持 apt/apk） ====================
install_deps() {
    if command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y curl wget jq openssl uuid-runtime >/dev/null 2>&1
    elif command -v apk &>/dev/null; then
        apk update && apk add curl wget jq openssl util-linux >/dev/null 2>&1
    else
        print_error "不支持的包管理器"
        exit 1
    fi
}

install_singbox() {
    print_info "检查依赖..."
    if ! command -v jq &>/dev/null || ! command -v openssl &>/dev/null; then
        install_deps
    fi

    LATEST=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r '.tag_name' | sed 's/v//')
    [[ -z "$LATEST" ]] && LATEST="1.12.0"

    if command -v sing-box &>/dev/null; then
        CURRENT=$(sing-box version 2>&1 | grep -oP 'sing-box version \K[0-9.]+' || echo "unknown")
        print_info "当前版本: ${CURRENT}，最新版本: ${LATEST}"
        if [[ "$CURRENT" == "$LATEST" ]]; then
            print_success "已是最新版本"; return 0
        fi
        echo -e "${YELLOW}发现新版本！ 当前:${GREEN}${CURRENT}${NC} 最新:${GREEN}${LATEST}${NC}"
        echo -e "  ${GREEN}[1]${NC} 更新  ${GREEN}[2]${NC} 不更新  ${GREEN}[0]${NC} 退出"
        read -p "选择: " ver_choice
        case $ver_choice in
            1) ;;
            2) print_info "跳过更新"; return 0 ;;
            0) exit 0 ;;
            *) print_error "无效，跳过"; return 0 ;;
        esac
    fi

    print_info "下载 sing-box v${LATEST}..."
    wget -q --show-progress -O /tmp/sb.tar.gz "https://github.com/SagerNet/sing-box/releases/download/v${LATEST}/sing-box-${LATEST}-linux-${ARCH}.tar.gz" || { print_error "下载失败"; return 1; }
    tar -xzf /tmp/sb.tar.gz -C /tmp || { print_error "解压失败"; rm -rf /tmp/sb.tar.gz /tmp/sing-box-*; return 1; }
    install -Dm755 /tmp/sing-box-${LATEST}-linux-${ARCH}/sing-box ${INSTALL_DIR}/sing-box
    rm -rf /tmp/sb.tar.gz /tmp/sing-box-*

    # 创建 systemd 服务 (兼容 OpenRC 则额外处理)
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
        # Alpine OpenRC
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
    print_success "sing-box ${LATEST} 安装完成"
}

# ==================== 证书生成 ====================
gen_cert_for_sni() {
    local sni="$1"; mkdir -p "${CERT_DIR}/${sni}"
    openssl genrsa -out "${CERT_DIR}/${sni}/private.key" 2048 2>/dev/null || { print_error "生成私钥失败"; return 1; }
    openssl req -new -x509 -days 36500 -key "${CERT_DIR}/${sni}/private.key" -out "${CERT_DIR}/${sni}/cert.pem" -subj "/C=US/ST=California/L=Cupertino/O=Apple Inc./CN=${sni}" 2>/dev/null || { print_error "生成证书失败"; return 1; }
    print_success "证书生成完成 (${sni})"
}

# ==================== 全局密钥管理 ====================
gen_keys() {
    print_info "生成全局密钥..."
    if [[ -f "${KEY_FILE}" ]]; then
        source "${KEY_FILE}"
        print_success "密钥已加载"; return 0
    fi
    KEYS=$(${INSTALL_DIR}/sing-box generate reality-keypair 2>/dev/null)
    REALITY_PRIVATE=$(echo "$KEYS" | grep "PrivateKey" | awk '{print $2}')
    REALITY_PUBLIC=$(echo "$KEYS" | grep "PublicKey" | awk '{print $2}')
    UUID=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)
    SHORT_ID=$(openssl rand -hex 8)
    HY2_PASSWORD=$(openssl rand -hex 16)
    SS_PASSWORD=$(openssl rand -base64 16)
    SHADOWTLS_PASSWORD=$(openssl rand -hex 16)
    ANYTLS_PASSWORD=$(openssl rand -hex 16)
    SOCKS_USER="user_$(openssl rand -hex 4)"
    SOCKS_PASS=$(openssl rand -hex 16)
    save_keys_to_file
    print_success "全局密钥生成完成"
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
    echo -en "${ALL_LINKS_TEXT}" > "${ALL_LINKS_FILE}"
    echo -en "${REALITY_LINKS}" > "${REALITY_LINKS_FILE}"
    echo -en "${HYSTERIA2_LINKS}" > "${HYSTERIA2_LINKS_FILE}"
    echo -en "${SOCKS5_LINKS}" > "${SOCKS5_LINKS_FILE}"
    echo -en "${SHADOWTLS_LINKS}" > "${SHADOWTLS_LINKS_FILE}"
    echo -en "${HTTPS_LINKS}" > "${HTTPS_LINKS_FILE}"
    echo -en "${ANYTLS_LINKS}" > "${ANYTLS_LINKS_FILE}"
    chmod 700 "${LINK_DIR}" 2>/dev/null || true
}

load_links_from_files() {
    mkdir -p "${LINK_DIR}"
    [[ -f "${ALL_LINKS_FILE}" ]] && ALL_LINKS_TEXT=$(cat "${ALL_LINKS_FILE}")
    [[ -f "${REALITY_LINKS_FILE}" ]] && REALITY_LINKS=$(cat "${REALITY_LINKS_FILE}")
    [[ -f "${HYSTERIA2_LINKS_FILE}" ]] && HYSTERIA2_LINKS=$(cat "${HYSTERIA2_LINKS_FILE}")
    [[ -f "${SOCKS5_LINKS_FILE}" ]] && SOCKS5_LINKS=$(cat "${SOCKS5_LINKS_FILE}")
    [[ -f "${SHADOWTLS_LINKS_FILE}" ]] && SHADOWTLS_LINKS=$(cat "${SHADOWTLS_LINKS_FILE}")
    [[ -f "${HTTPS_LINKS_FILE}" ]] && HTTPS_LINKS=$(cat "${HTTPS_LINKS_FILE}")
    [[ -f "${ANYTLS_LINKS_FILE}" ]] && ANYTLS_LINKS=$(cat "${ANYTLS_LINKS_FILE}")
}

# 加载节点配置（修复逗号问题：均使用数组方式进行拼接）
load_inbounds_from_config() {
    [[ ! -f "${CONFIG_FILE}" ]] && return 1
    command -v jq &>/dev/null || return 1
    INBOUND_TAGS=(); INBOUND_PORTS=(); INBOUND_PROTOS=(); INBOUND_SNIS=(); INBOUND_RELAY_TAGS=()
    # 用数组收集所有入站 JSON
    local inbounds_arr=()
    local inbounds_count=$(jq '.inbounds | length' "${CONFIG_FILE}" 2>/dev/null || echo "0")
    [[ "$inbounds_count" -eq 0 ]] && { INBOUNDS_JSON=""; return 1; }
    for ((i=0; i<inbounds_count; i++)); do
        local inbound=$(jq -c ".inbounds[${i}]" "${CONFIG_FILE}" 2>/dev/null)
        [[ -z "$inbound" ]] && continue
        inbounds_arr+=("$inbound")
        local tag=$(echo "$inbound" | jq -r '.tag' 2>/dev/null)
        local port=$(echo "$inbound" | jq -r '.listen_port' 2>/dev/null)
        local type=$(echo "$inbound" | jq -r '.type' 2>/dev/null)
        [[ "$tag" == "shadowsocks-in-"* ]] && continue
        local proto="unknown"; local sni=""
        if [[ "$tag" == *"vless-in-"* ]]; then proto="Reality"; sni=$(echo "$inbound" | jq -r '.tls.server_name // ""')
        elif [[ "$tag" == *"hy2-in-"* ]]; then proto="Hysteria2"; sni=$(echo "$inbound" | jq -r '.tls.server_name // ""')
        elif [[ "$tag" == *"shadowtls-in-"* ]]; then proto="ShadowTLS v3"; sni=$(echo "$inbound" | jq -r '.handshake.server // ""')
        elif [[ "$tag" == *"socks-in"* ]]; then proto="SOCKS5"
        elif [[ "$tag" == *"vless-tls-in-"* ]]; then proto="HTTPS"; sni=$(echo "$inbound" | jq -r '.tls.server_name // ""')
        elif [[ "$tag" == *"anytls-in-"* ]]; then proto="AnyTLS"; sni=$(echo "$inbound" | jq -r '.tls.server_name // ""')
        fi
        [[ -z "$sni" ]] && sni="${DEFAULT_SNI}"
        INBOUND_TAGS+=("$tag"); INBOUND_PORTS+=("$port"); INBOUND_PROTOS+=("$proto"); INBOUND_SNIS+=("$sni"); INBOUND_RELAY_TAGS+=("direct")
    done
    # 用逗号连接数组，避免前导/后置逗号
    INBOUNDS_JSON=$(IFS=,; echo "${inbounds_arr[*]}")
    # 恢复中转配置
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
    print_info "重新生成链接..."
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
            vless) # ... 保持原有生成逻辑不变，省略以节省篇幅 ...
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
            hysteria2) # ... 省略 ...
                local password=$(echo "$inbound" | jq -r '.users[0].password // ""')
                local sni=$(echo "$inbound" | jq -r '.tls.server_name // ""'); [[ -z "$sni" ]] && sni="${DEFAULT_SNI}"
                local link="hysteria2://${password}@${SERVER_IP}:${port}?insecure=1&sni=${sni}#Hysteria2-${SERVER_IP}"
                local line="[Hysteria2] ${SERVER_IP}:${port} (SNI: ${sni})\n${link}\n----------------------------------------\n\n"
                ALL_LINKS_TEXT+="$line"; HYSTERIA2_LINKS+="$line"
                ;;
            socks) # ... 省略 ...
                local username=$(echo "$inbound" | jq -r '.users[0].username // ""')
                local password=$(echo "$inbound" | jq -r '.users[0].password // ""')
                local link
                [[ -n "$username" ]] && link="socks5://${username}:${password}@${SERVER_IP}:${port}#SOCKS5-${SERVER_IP}" || link="socks5://${SERVER_IP}:${port}#SOCKS5-${SERVER_IP}"
                local line="[SOCKS5] ${SERVER_IP}:${port}\n${link}\n----------------------------------------\n\n"
                ALL_LINKS_TEXT+="$line"; SOCKS5_LINKS+="$line"
                ;;
            shadowtls) # ... 省略 ...
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
            anytls) # ... 省略 ...
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

# ==================== 节点配置（每节点独立随机凭证） ====================
gen_random_uuid() { uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid; }
gen_random_hex16() { openssl rand -hex 16; }
gen_random_base64_16() { openssl rand -base64 16; }
gen_random_user() { echo "user_$(openssl rand -hex 4)"; }

# 各 setup 函数使用数组追加，彻底消灭逗号错误
inbounds_array=()   # 全局 JSON 数组，替代 INBOUNDS_JSON 字符串

setup_reality() {
    echo ""; read_port_with_check 443
    read -p "伪装域名 [${DEFAULT_SNI}]: " SNI; SNI=${SNI:-${DEFAULT_SNI}}
    local default_uuid=$(gen_random_uuid)
    echo -e "节点 UUID (回车使用随机):"
    read -p "UUID [${default_uuid}]: " use_uuid; use_uuid=${use_uuid:-$default_uuid}
    local inbound="{
  \"type\": \"vless\",
  \"tag\": \"vless-in-${PORT}\",
  \"listen\": \"::\",
  \"listen_port\": ${PORT},
  \"users\": [{\"uuid\": \"${use_uuid}\", \"flow\": \"xtls-rprx-vision\"}],
  \"tls\": {
    \"enabled\": true,
    \"server_name\": \"${SNI}\",
    \"reality\": {
      \"enabled\": true,
      \"handshake\": {\"server\": \"${SNI}\", \"server_port\": 443},
      \"private_key\": \"${REALITY_PRIVATE}\",
      \"short_id\": [\"${SHORT_ID}\"]
    }
  }
}"
    inbounds_array+=("$inbound")
    INBOUND_TAGS+=("vless-in-${PORT}"); INBOUND_PORTS+=("${PORT}"); INBOUND_PROTOS+=("Reality"); INBOUND_SNIS+=("${SNI}"); INBOUND_RELAY_TAGS+=("direct")
    LINK="vless://${use_uuid}@${SERVER_IP}:${PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=chrome&pbk=${REALITY_PUBLIC}&sid=${SHORT_ID}&type=tcp#Reality-${SERVER_IP}"
    local line="[Reality] ${SERVER_IP}:${PORT} (SNI: ${SNI})\n${LINK}\n----------------------------------------\n\n"
    ALL_LINKS_TEXT+="$line"; REALITY_LINKS+="$line"
    print_success "Reality 添加完成"; save_links_to_files
}

setup_hysteria2() {
    echo ""; read_port_with_check 443
    read -p "伪装域名 [${DEFAULT_SNI}]: " HY2_SNI; HY2_SNI=${HY2_SNI:-${DEFAULT_SNI}}
    local default_pass=$(gen_random_hex16)
    echo -e "节点密码 (回车使用随机):"
    read -p "密码 [${default_pass}]: " use_pass; use_pass=${use_pass:-$default_pass}
    gen_cert_for_sni "${HY2_SNI}" || return 1
    local inbound="{
  \"type\": \"hysteria2\",
  \"tag\": \"hy2-in-${PORT}\",
  \"listen\": \"::\",
  \"listen_port\": ${PORT},
  \"users\": [{\"password\": \"${use_pass}\"}],
  \"tls\": {
    \"enabled\": true,
    \"alpn\": [\"h3\"],
    \"server_name\": \"${HY2_SNI}\",
    \"certificate_path\": \"${CERT_DIR}/${HY2_SNI}/cert.pem\",
    \"key_path\": \"${CERT_DIR}/${HY2_SNI}/private.key\"
  }
}"
    inbounds_array+=("$inbound")
    INBOUND_TAGS+=("hy2-in-${PORT}"); INBOUND_PORTS+=("${PORT}"); INBOUND_PROTOS+=("Hysteria2"); INBOUND_SNIS+=("${HY2_SNI}"); INBOUND_RELAY_TAGS+=("direct")
    LINK="hysteria2://${use_pass}@${SERVER_IP}:${PORT}?insecure=1&sni=${HY2_SNI}#Hysteria2-${SERVER_IP}"
    local line="[Hysteria2] ${SERVER_IP}:${PORT} (SNI: ${HY2_SNI})\n${LINK}\n----------------------------------------\n\n"
    ALL_LINKS_TEXT+="$line"; HYSTERIA2_LINKS+="$line"
    print_success "Hysteria2 添加完成"; save_links_to_files
}

# SOCKS5/ShadowTLS/HTTPS/AnyTLS 同理，均改用 inbounds_array+=("$inbound")
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
    else
        inbound="{\"type\":\"socks\",\"tag\":\"socks-in-${PORT}\",\"listen\":\"::\",\"listen_port\":${PORT}}"
        link="socks5://${SERVER_IP}:${PORT}#SOCKS5-${SERVER_IP}"
    fi
    inbounds_array+=("$inbound")
    INBOUND_TAGS+=("socks-in-${PORT}"); INBOUND_PORTS+=("${PORT}"); INBOUND_PROTOS+=("SOCKS5"); INBOUND_SNIS+=(""); INBOUND_RELAY_TAGS+=("direct")
    local line="[SOCKS5] ${SERVER_IP}:${PORT}\n${link}\n----------------------------------------\n\n"
    ALL_LINKS_TEXT+="$line"; SOCKS5_LINKS+="$line"
    print_success "SOCKS5 添加完成"; save_links_to_files
}

setup_shadowtls() {
    echo ""; read_port_with_check 443
    read -p "伪装域名 [${DEFAULT_SNI}]: " SHADOWTLS_SNI; SHADOWTLS_SNI=${SHADOWTLS_SNI:-${DEFAULT_SNI}}
    local default_stls_pass=$(gen_random_hex16); local default_ss_pass=$(gen_random_base64_16)
    read -p "ShadowTLS密码 [${default_stls_pass}]: " use_stls_pass; use_stls_pass=${use_stls_pass:-$default_stls_pass}
    read -p "Shadowsocks密码 [${default_ss_pass}]: " use_ss_pass; use_ss_pass=${use_ss_pass:-$default_ss_pass}
    local inbound="{\"type\":\"shadowtls\",\"tag\":\"shadowtls-in-${PORT}\",\"listen\":\"::\",\"listen_port\":${PORT},\"version\":3,\"users\":[{\"password\":\"${use_stls_pass}\"}],\"handshake\":{\"server\":\"${SHADOWTLS_SNI}\",\"server_port\":443},\"strict_mode\":true,\"detour\":\"shadowsocks-in-${PORT}\"},{\"type\":\"shadowsocks\",\"tag\":\"shadowsocks-in-${PORT}\",\"listen\":\"127.0.0.1\",\"network\":\"tcp\",\"method\":\"2022-blake3-aes-128-gcm\",\"password\":\"${use_ss_pass}\"}"
    inbounds_array+=("$inbound")
    INBOUND_TAGS+=("shadowtls-in-${PORT}"); INBOUND_PORTS+=("${PORT}"); INBOUND_PROTOS+=("ShadowTLS v3"); INBOUND_SNIS+=("${SHADOWTLS_SNI}"); INBOUND_RELAY_TAGS+=("direct")
    local ss_userinfo=$(echo -n "2022-blake3-aes-128-gcm:${use_ss_pass}" | base64 -w0 | sed 's/+/-/g; s/\//_/g; s/=//g')
    local plugin_json="{\"version\":\"3\",\"password\":\"${use_stls_pass}\",\"host\":\"${SHADOWTLS_SNI}\",\"port\":\"${PORT}\",\"address\":\"${SERVER_IP}\"}"
    local plugin_b64=$(echo -n "$plugin_json" | base64 -w0 | sed 's/+/-/g; s/\//_/g; s/=//g')
    LINK="ss://${ss_userinfo}@${SERVER_IP}:${PORT}?shadow-tls=${plugin_b64}#ShadowTLS-${SERVER_IP}"
    local line="[ShadowTLS v3] ${SERVER_IP}:${PORT} (SNI: ${SHADOWTLS_SNI})\n${LINK}\n----------------------------------------\n\n"
    ALL_LINKS_TEXT+="$line"; SHADOWTLS_LINKS+="$line"
    print_success "ShadowTLS 添加完成"; save_links_to_files
}

setup_https() {
    echo ""; read_port_with_check 443
    read -p "伪装域名 [${DEFAULT_SNI}]: " HTTPS_SNI; HTTPS_SNI=${HTTPS_SNI:-${DEFAULT_SNI}}
    local default_uuid=$(gen_random_uuid)
    read -p "UUID [${default_uuid}]: " use_uuid; use_uuid=${use_uuid:-$default_uuid}
    gen_cert_for_sni "${HTTPS_SNI}" || return 1
    local inbound="{\"type\":\"vless\",\"tag\":\"vless-tls-in-${PORT}\",\"listen\":\"::\",\"listen_port\":${PORT},\"users\":[{\"uuid\":\"${use_uuid}\"}],\"tls\":{\"enabled\":true,\"server_name\":\"${HTTPS_SNI}\",\"certificate_path\":\"${CERT_DIR}/${HTTPS_SNI}/cert.pem\",\"key_path\":\"${CERT_DIR}/${HTTPS_SNI}/private.key\"}}"
    inbounds_array+=("$inbound")
    INBOUND_TAGS+=("vless-tls-in-${PORT}"); INBOUND_PORTS+=("${PORT}"); INBOUND_PROTOS+=("HTTPS"); INBOUND_SNIS+=("${HTTPS_SNI}"); INBOUND_RELAY_TAGS+=("direct")
    LINK="vless://${use_uuid}@${SERVER_IP}:${PORT}?encryption=none&security=tls&sni=${HTTPS_SNI}&type=tcp&allowInsecure=1#HTTPS-${SERVER_IP}"
    local line="[HTTPS] ${SERVER_IP}:${PORT} (SNI: ${HTTPS_SNI})\n${LINK}\n----------------------------------------\n\n"
    ALL_LINKS_TEXT+="$line"; HTTPS_LINKS+="$line"
    print_success "HTTPS 添加完成"; save_links_to_files
}

setup_anytls() {
    echo ""; read_port_with_check 443
    read -p "伪装域名 [${DEFAULT_SNI}]: " ANYTLS_SNI; ANYTLS_SNI=${ANYTLS_SNI:-${DEFAULT_SNI}}
    local default_pass=$(gen_random_hex16)
    read -p "密码 [${default_pass}]: " use_pass; use_pass=${use_pass:-$default_pass}
    gen_cert_for_sni "${ANYTLS_SNI}" || return 1
    local inbound="{\"type\":\"anytls\",\"tag\":\"anytls-in-${PORT}\",\"listen\":\"::\",\"listen_port\":${PORT},\"users\":[{\"password\":\"${use_pass}\"}],\"padding_scheme\":[],\"tls\":{\"enabled\":true,\"server_name\":\"${ANYTLS_SNI}\",\"certificate_path\":\"${CERT_DIR}/${ANYTLS_SNI}/cert.pem\",\"key_path\":\"${CERT_DIR}/${ANYTLS_SNI}/private.key\"}}"
    inbounds_array+=("$inbound")
    INBOUND_TAGS+=("anytls-in-${PORT}"); INBOUND_PORTS+=("${PORT}"); INBOUND_PROTOS+=("AnyTLS"); INBOUND_SNIS+=("${ANYTLS_SNI}"); INBOUND_RELAY_TAGS+=("direct")
    LINK="anytls://${use_pass}@${SERVER_IP}:${PORT}?security=tls&fp=chrome&insecure=1&sni=${ANYTLS_SNI}&type=tcp#AnyTLS-${SERVER_IP}"
    local line="[AnyTLS] ${SERVER_IP}:${PORT} (SNI: ${ANYTLS_SNI})\n${LINK}\n----------------------------------------\n\n"
    ALL_LINKS_TEXT+="$line"; ANYTLS_LINKS+="$line"
    print_success "AnyTLS 添加完成"; save_links_to_files
}

# ==================== 中转链接解析（保持原样） ====================
parse_socks_link() { ... }  # 省略，实际需完整保留之前的实现
# 此处应补全所有 parse_* 函数，与之前提供的一致

# ==================== 配置生成（使用数组） ====================
generate_config() {
    print_info "生成配置文件..."
    [[ ${#inbounds_array[@]} -eq 0 ]] && { print_error "无节点"; return 1; }
    load_relays_from_file
    local inbounds_json_str=$(IFS=,; echo "${inbounds_array[*]}")
    local outbounds="["; local first=1
    for rjson in "${RELAY_JSONS[@]}"; do
        [[ $first -eq 1 ]] && outbounds+="$rjson" || outbounds+=", $rjson"; first=0
    done
    [[ -n "${RELAY_JSONS[*]}" ]] && outbounds+=", "
    outbounds+='{"type": "direct", "tag": "direct"}]'
    local route_rules=""
    for i in "${!INBOUND_TAGS[@]}"; do
        local rt="${INBOUND_RELAY_TAGS[$i]}"
        [[ "$rt" != "direct" ]] && route_rules+=",{\"inbound\":[\"${INBOUND_TAGS[$i]}\"],\"outbound\":\"$rt\"}"
    done
    route_rules="${route_rules#,}"
    local route_json="{\"final\":\"direct\",\"default_domain_resolver\":\"local\"}"
    [[ -n "$route_rules" ]] && route_json="{\"rules\":[${route_rules}],\"final\":\"direct\",\"default_domain_resolver\":\"local\"}"
    local dns_strategy=""
    [[ "$OUTBOUND_IP_MODE" == "ipv6" ]] && dns_strategy=',"strategy": "prefer_ipv6"'
    [[ "$OUTBOUND_IP_MODE" == "ipv4" ]] && dns_strategy=',"strategy": "prefer_ipv4"'
    cat > ${CONFIG_FILE} << EOFCONFIG
{
  "log": {"level": "info", "timestamp": true},
  "dns": {
    "servers": [{"tag": "local", "type": "local"}, {"tag": "remote", "type": "udp", "server": "8.8.8.8"}],
    "final": "remote"${dns_strategy}
  },
  "inbounds": [${inbounds_json_str}],
  "outbounds": ${outbounds},
  "route": ${route_json}
}
EOFCONFIG
    print_success "配置文件生成"
}

start_svc() {
    print_info "验证配置..."
    ${INSTALL_DIR}/sing-box check -c ${CONFIG_FILE} >/dev/null 2>&1 || { print_error "验证失败"; cat ${CONFIG_FILE}; return 1; }
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

# ==================== 保活功能（cron） ====================
setup_keepalive() {
    # 每5分钟检查一次服务状态，若不正常则重启
    local keepalive_cmd="*/5 * * * * root pgrep sing-box >/dev/null || (systemctl restart sing-box 2>/dev/null || rc-service sing-box restart)"
    if [[ -f /etc/cron.d/sing-box-keepalive ]]; then
        print_info "保活任务已存在"
    else
        echo "$keepalive_cmd" > /etc/cron.d/sing-box-keepalive
        print_success "已添加 sing-box 保活任务（每5分钟检查）"
    fi
    case $1 in
        enable) : ;;
        disable)
            rm -f /etc/cron.d/sing-box-keepalive
            print_success "已关闭保活任务"
            ;;
    esac
}

# ==================== 菜单界面 ====================
show_menu() {
    show_banner
    echo -e "${YELLOW}请选择协议:${NC}"
    echo -e "${GREEN}[1]${NC} VlessReality"
    echo -e "${GREEN}[2]${NC} Hysteria2"
    echo -e "${GREEN}[3]${NC} SOCKS5"
    echo -e "${GREEN}[4]${NC} ShadowTLS v3"
    echo -e "${GREEN}[5]${NC} HTTPS"
    echo -e "${GREEN}[6]${NC} AnyTLS"
    read -p "选择 [1-6]: " choice
    case $choice in
        1) setup_reality ;;
        2) setup_hysteria2 ;;
        3) setup_socks5 ;;
        4) setup_shadowtls ;;
        5) setup_https ;;
        6) setup_anytls ;;
        *) print_error "无效"; return 1 ;;
    esac
    [[ ${#inbounds_array[@]} -gt 0 ]] && generate_config && start_svc && { clear; echo "节点已添加并启动"; }
}

config_and_view_menu() {
    while true; do
        show_banner
        echo -e "配置/查看节点"
        echo -e "  ${GREEN}[1]${NC} 重新加载配置并启动"
        echo -e "  ${GREEN}[2]${NC} 查看全部链接"
        echo -e "  ${GREEN}[3]${NC} 查看 Reality"   # ... 同之前，省略
        echo -e "  ${GREEN}[9]${NC} 删除单个节点"
        echo -e "  ${GREEN}[10]${NC} 删除全部节点"
        echo -e "  ${GREEN}[11]${NC} 开启/关闭保活"
        echo -e "  ${GREEN}[0]${NC} 返回"
        read -p "选择: " c
        case $c in
            1) generate_config && start_svc ;;
            2) [[ -z "$ALL_LINKS_TEXT" ]] && echo "无节点" || echo -e "$ALL_LINKS_TEXT" ;;
            9) delete_single_node ;;
            10) delete_all_nodes ;;
            11)
                echo -e "  ${GREEN}[1]${NC} 开启保活  ${GREEN}[2]${NC} 关闭保活"
                read -p "选择: " ka; case $ka in 1) setup_keepalive enable ;; 2) setup_keepalive disable ;; esac
                ;;
            0) break ;;
        esac
        read -p "按回车继续..." _
    done
}

delete_single_node() { ... }  # 使用数组索引删除，并重新生成 inbounds_array
delete_all_nodes() { inbounds_array=(); ... }

show_main_menu() {
    show_banner
    echo -e "${CYAN}╔═══════════════════════════════╗"
    echo -e "║      Sing-Box 管理面板        ║"
    echo -e "╚═══════════════════════════════╝${NC}"
    echo -e "当前IP: ${GREEN}${SERVER_IP}${NC}  入站:${INBOUND_IP_MODE} 出站:${OUTBOUND_IP_MODE}"
    echo -e "节点数: ${#INBOUND_TAGS[@]}"
    echo -e "  ${GREEN}[1]${NC} 添加节点"
    echo -e "  ${GREEN}[2]${NC} 中转配置"
    echo -e "  ${GREEN}[3]${NC} IP配置"
    echo -e "  ${GREEN}[4]${NC} 配置/查看节点"
    echo -e "  ${GREEN}[5]${NC} 重新生成链接"
    echo -e "  ${GREEN}[6]${NC} 开启/关闭保活"
    echo -e "  ${GREEN}[7]${NC} 卸载"
    echo -e "  ${GREEN}[0]${NC} 退出"
}

# 主循环中增加保活选项
main() {
    # ... 初始化 ...
    while true; do
        [[ -f "${CONFIG_FILE}" ]] && load_inbounds_from_config   # 同步数组与文件
        load_relays_from_file
        show_main_menu
        read -p "选择 [0-7]: " m_choice
        case $m_choice in
            1) show_menu ;;
            2) setup_relay ;;
            3) ip_config_menu ;;
            4) config_and_view_menu ;;
            5) regenerate_all_links ;;
            6) setup_keepalive enable ;;
            7) delete_self ;;
            0) exit 0 ;;
            *) print_error "无效" ;;
        esac
        read -p "按回车返回主菜单..." _
    done
}

# 调用 main
