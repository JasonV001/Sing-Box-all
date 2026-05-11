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

# 链接文件路径
ALL_LINKS_FILE="${LINK_DIR}/all.txt"
REALITY_LINKS_FILE="${LINK_DIR}/reality.txt"
HYSTERIA2_LINKS_FILE="${LINK_DIR}/hysteria2.txt"
SOCKS5_LINKS_FILE="${LINK_DIR}/socks5.txt"
SHADOWTLS_LINKS_FILE="${LINK_DIR}/shadowtls.txt"
HTTPS_LINKS_FILE="${LINK_DIR}/https.txt"
ANYTLS_LINKS_FILE="${LINK_DIR}/anytls.txt"
ARGO_LINKS_FILE="${LINK_DIR}/argo_links.txt"

# 脚本路径
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

# IP 配置
SERVER_IPV6=""
INBOUND_IP_MODE="dual"   # ipv4 / ipv6 / dual
OUTBOUND_IP_MODE="dual"  # ipv4 / ipv6 / dual
IP_CONFIG_FILE="/etc/sing-box/ip_config.conf"

# 中转配置数组
RELAY_TAGS=()
RELAY_JSONS=()
RELAY_DESCS=()
RELAY_FILE="/etc/sing-box/relays.conf"

# 节点数组
INBOUND_TAGS=()
INBOUND_PORTS=()
INBOUND_PROTOS=()
INBOUND_RELAY_TAGS=()
INBOUND_SNIS=()

# 密钥变量
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

# 默认SNI
DEFAULT_SNI="time.is"

# 日志标记
LOGROTATE_FLAG="/etc/sing-box/.logrotate_setup"

# 系统标记
ALPINE=0
# ==================== 打印函数 ====================
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# ==================== 系统检测 ====================
detect_system() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        if [[ "$ID" == "alpine" ]]; then
            ALPINE=1
        else
            ALPINE=0
        fi
    else
        print_error "无法检测系统"
        exit 1
    fi
    
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)   ARCH="amd64" ;;
        aarch64)  ARCH="arm64" ;;
        armv7l)   ARCH="armv7" ;;
        *)        print_error "不支持的架构: $ARCH"; exit 1 ;;
    esac
    
    print_success "系统: ${ID:-unknown} (${ARCH})"
}

# 检查双栈支持
check_ipv6_bindv6only() {
    local val
    val=$(sysctl -n net.ipv6.bindv6only 2>/dev/null)
    [[ "$val" == "0" ]] && return 0 || return 1
}

# ==================== 服务控制 ====================
svc_start() {
    if [[ $ALPINE -eq 1 ]]; then
        rc-service sing-box start 2>/dev/null
    else
        systemctl start sing-box
    fi
}

svc_stop() {
    if [[ $ALPINE -eq 1 ]]; then
        rc-service sing-box stop 2>/dev/null
    else
        systemctl stop sing-box
    fi
}

svc_restart() {
    if [[ $ALPINE -eq 1 ]]; then
        rc-service sing-box restart 2>/dev/null
    else
        systemctl restart sing-box
    fi
}

svc_enable() {
    if [[ $ALPINE -eq 1 ]]; then
        rc-update add sing-box default >/dev/null 2>&1
    else
        systemctl enable sing-box >/dev/null 2>&1
    fi
}

svc_disable() {
    if [[ $ALPINE -eq 1 ]]; then
        rc-update del sing-box default >/dev/null 2>&1
    else
        systemctl disable sing-box >/dev/null 2>&1
    fi
}

svc_is_active() {
    if [[ $ALPINE -eq 1 ]]; then
        rc-service sing-box status 2>/dev/null | grep -q 'started'
    else
        systemctl is-active --quiet sing-box
    fi
}

# ==================== 日志自动清理 ====================
setup_log_cleanup() {
    [[ -f "${LOGROTATE_FLAG}" ]] && return 0

    print_info "配置日志自动清理（7天 / 100M）..."

    if [[ $ALPINE -eq 1 ]]; then
        apk add --no-cache logrotate dcron 2>/dev/null || {
            print_warning "logrotate/dcron 安装失败，跳过日志清理"
            return 0
        }
        cat > /etc/logrotate.d/sing-box << 'EOF'
/var/log/sing-box.log {
    daily
    rotate 7
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
    maxsize 100M
}
EOF
        rc-update add dcron default 2>/dev/null
        rc-service dcron start 2>/dev/null
        print_success "Alpine 日志清理已配置"
    else
        mkdir -p /etc/systemd/journald.conf.d
        cat > /etc/systemd/journald.conf.d/sing-box-log.conf << 'EOF'
[Journal]
SystemMaxUse=100M
MaxRetentionSec=7day
EOF
        systemctl restart systemd-journald 2>/dev/null
        print_success "systemd 日志限制已生效"
    fi

    mkdir -p "$(dirname "${LOGROTATE_FLAG}")"
    touch "${LOGROTATE_FLAG}"
}
# ==================== 安装 sing-box ====================
install_singbox() {
    print_info "检查 sing-box 安装状态..."

    # 1. 依赖检查
    if ! command -v jq &>/dev/null; then
        print_info "安装基础依赖..."
        if [[ $ALPINE -eq 1 ]]; then
            for pkg in curl wget jq openssl util-linux coreutils gcompat; do
                apk add --no-cache "$pkg" >/dev/null 2>&1
                sleep 0.5
            done
        else
            apt-get update -qq && apt-get install -y curl wget jq openssl uuid-runtime >/dev/null 2>&1
        fi
        print_success "依赖安装完成"
    fi

    # 2. 二进制检查
    local need_download=1
    if [[ -x "${INSTALL_DIR}/sing-box" ]]; then
        if ${INSTALL_DIR}/sing-box version >/dev/null 2>&1; then
            local ver=$(${INSTALL_DIR}/sing-box version 2>&1 | grep -oP 'sing-box version \K[0-9.]+' || echo "unknown")
            print_success "sing-box 已安装 (版本: ${ver})"
            need_download=0
        else
            print_warning "sing-box 损坏，重新下载"
            rm -f "${INSTALL_DIR}/sing-box"
        fi
    fi

    # 3. 下载安装
    if [[ $need_download -eq 1 ]]; then
        LATEST=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r '.tag_name' | sed 's/v//')
        [[ -z "$LATEST" ]] && LATEST="1.12.0"
        print_info "下载 sing-box ${LATEST} (linux-${ARCH})..."

        rm -rf /tmp/sb.tar.gz /tmp/sing-box-${LATEST}-linux-${ARCH}
        wget -q --show-progress -O /tmp/sb.tar.gz \
            "https://github.com/SagerNet/sing-box/releases/download/v${LATEST}/sing-box-${LATEST}-linux-${ARCH}.tar.gz" 2>&1

        if [[ ! -f /tmp/sb.tar.gz ]]; then
            print_error "下载失败，请检查网络"
            return 1
        fi

        tar -xzf /tmp/sb.tar.gz -C /tmp 4>/dev/null || {
            print_error "解压失败（可能内存不足）"
            rm -f /tmp/sb.tar.gz
            return 1
        }

        if [[ -f "/tmp/sing-box-${LATEST}-linux-${ARCH}/sing-box" ]]; then
            install -Dm755 "/tmp/sing-box-${LATEST}-linux-${ARCH}/sing-box" "${INSTALL_DIR}/sing-box"
            rm -rf "/tmp/sing-box-${LATEST}-linux-${ARCH}" /tmp/sb.tar.gz
            print_success "sing-box 安装完成"
        else
            print_error "未找到 sing-box 二进制"
            return 1
        fi
    fi

    # 4. 服务文件
    local need_service=0
    if [[ $ALPINE -eq 1 ]]; then
        if [[ ! -f /etc/init.d/sing-box ]]; then
            need_service=1
        elif ! grep -q "/var/log/sing-box.log" /etc/init.d/sing-box; then
            need_service=1
        fi
    else
        [[ ! -f /etc/systemd/system/sing-box.service ]] && need_service=1
    fi

    if [[ $need_service -eq 1 ]]; then
        print_info "创建服务文件..."
        if [[ $ALPINE -eq 1 ]]; then
            cat > /etc/init.d/sing-box << 'EOF'
#!/sbin/openrc-run
name="sing-box"
description="sing-box service"
command="/bin/sh"
command_args="-c 'exec /usr/local/bin/sing-box run -c /etc/sing-box/config.json >> /var/log/sing-box.log 2>&1'"
pidfile="/run/${name}.pid"
required_files="/etc/sing-box/config.json"
supervisor="supervise-daemon"
respawn_delay=10
respawn_max=0
depend() { need net; after firewall; }
EOF
            chmod +x /etc/init.d/sing-box
        else
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
        fi
        print_success "服务文件已创建"
    fi

    svc_enable
    setup_log_cleanup
    print_success "sing-box 安装/修复完成"
}
# ==================== 证书生成 ====================
gen_cert_for_sni() {
    local sni="$1"
    local node_cert_dir="${CERT_DIR}/${sni}"
    
    mkdir -p "${node_cert_dir}"
    
    openssl genrsa -out "${node_cert_dir}/private.key" 2048 2>/dev/null
    openssl req -new -x509 -days 36500 \
        -key "${node_cert_dir}/private.key" \
        -out "${node_cert_dir}/cert.pem" \
        -subj "/C=US/ST=California/L=Cupertino/O=Apple Inc./CN=${sni}" 2>/dev/null
    
    print_success "证书已生成 (${sni}, 100年有效)"
}

# ==================== 密钥管理 ====================
gen_keys() {
    print_info "生成/加载密钥..."
    
    if [[ -f "${KEY_FILE}" ]]; then
        source "${KEY_FILE}"
        print_success "密钥已加载"
        return 0
    fi
    
    # Reality 密钥对
    KEYS=$(${INSTALL_DIR}/sing-box generate reality-keypair 2>/dev/null)
    REALITY_PRIVATE=$(echo "$KEYS" | grep "PrivateKey" | awk '{print $2}')
    REALITY_PUBLIC=$(echo "$KEYS" | grep "PublicKey" | awk '{print $2}')
    
    # UUID
    UUID=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid 2>/dev/null)
    
    # Short ID 自动随机生成
    SHORT_ID=$(openssl rand -hex 8)
    
    # 各类密码
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
# ==================== IP 配置管理 ====================
save_ip_config() {
    mkdir -p "$(dirname "${IP_CONFIG_FILE}")"
    cat > "${IP_CONFIG_FILE}" << EOF
SERVER_IP="${SERVER_IP}"
SERVER_IPV6="${SERVER_IPV6}"
INBOUND_IP_MODE="${INBOUND_IP_MODE}"
OUTBOUND_IP_MODE="${OUTBOUND_IP_MODE}"
EOF
}

load_ip_config() {
    if [[ -f "${IP_CONFIG_FILE}" ]]; then
        source "${IP_CONFIG_FILE}"
    fi
}

# ==================== 网络工具 ====================
get_ip() {
    print_info "获取服务器 IP 地址..."
    local old_ip="${SERVER_IP}"
    local old_ipv6="${SERVER_IPV6}"
    
    # 获取 IPv4
    local ipv4=$(curl -s4m5 ifconfig.me 2>/dev/null || curl -s4m5 api.ipify.org 2>/dev/null || curl -s4m5 ip.sb 2>/dev/null)
    
    # 获取 IPv6
    local ipv6=$(curl -s6m5 ifconfig.me 2>/dev/null || curl -s6m5 api6.ipify.org 2>/dev/null || curl -s6m5 ip.sb 2>/dev/null)
    
    echo ""
    [[ -n "$ipv4" ]] && echo -e "  ${GREEN}IPv4:${NC} ${ipv4}"
    [[ -n "$ipv6" ]] && echo -e "  ${GREEN}IPv6:${NC} ${ipv6}"
    echo ""
    
    if [[ -z "$ipv4" && -z "$ipv6" ]]; then
        print_error "无法获取服务器 IP"
        exit 1
    fi
    
    # 优先 IPv4
    if [[ -n "$ipv4" ]]; then
        SERVER_IP="$ipv4"
        SERVER_IPV6="$ipv6"
        print_success "使用 IPv4: ${SERVER_IP}"
        [[ -n "$ipv6" ]] && echo -e "${CYAN}提示: 可在菜单中切换 IPv6${NC}"
    else
        SERVER_IP="$ipv6"
        SERVER_IPV6=""
        INBOUND_IP_MODE="ipv6"
        OUTBOUND_IP_MODE="ipv6"
        print_success "仅 IPv6，已自动设置入站/出站为 IPv6"
    fi
    
    # 自动检测双栈（首次安装时 INBOUND_IP_MODE 在 load_ip_config 中可能为空）
    if [[ -z "$INBOUND_IP_MODE" ]]; then
        if check_ipv6_bindv6only; then
            INBOUND_IP_MODE="dual"
            print_info "检测到 bindv6only=0，入站自动设为双栈"
        else
            INBOUND_IP_MODE="ipv4"
        fi
    fi
    [[ -z "$OUTBOUND_IP_MODE" ]] && OUTBOUND_IP_MODE="dual"
    
    [[ -n "$old_ip" && "$old_ip" != "$SERVER_IP" ]] && print_warning "IPv4 已变更，建议重新生成链接"
    [[ -n "$old_ipv6" && "$old_ipv6" != "$SERVER_IPV6" ]] && print_warning "IPv6 已变更，建议重新生成链接"
    
    save_ip_config
}

# 获取监听地址
get_listen_addr() {
    case "${INBOUND_IP_MODE}" in
        ipv4) echo "0.0.0.0" ;;
        ipv6) echo "::" ;;
        dual) echo "::" ;;
        *)    echo "::" ;;
    esac
}

# 端口检查
check_port_in_use() {
    local port="$1"
    if command -v ss &>/dev/null; then
        ss -tuln | awk '{print $5}' | grep -E "[:.]${port}$" >/dev/null 2>&1 && return 0 || return 1
    elif command -v netstat &>/dev/null; then
        netstat -tuln | awk '{print $4}' | grep -E "[:.]${port}$" >/dev/null 2>&1 && return 0 || return 1
    else
        return 1
    fi
}

read_port_with_check() {
    local default_port="$1"
    while true; do
        read -p "监听端口 [${default_port}]: " PORT
        PORT=${PORT:-${default_port}}
        if ! [[ "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
            print_error "端口无效，请输入 1-65535"
            continue
        fi
        if check_port_in_use "$PORT"; then
            print_warning "端口 ${PORT} 已被占用"
            continue
        fi
        break
    done
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
    print_success "链接已保存到 ${LINK_DIR}"
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

cleanup_links() {
    rm -rf "${LINK_DIR}" 2>/dev/null || true
    ALL_LINKS_TEXT=""
    REALITY_LINKS=""
    HYSTERIA2_LINKS=""
    SOCKS5_LINKS=""
    SHADOWTLS_LINKS=""
    HTTPS_LINKS=""
    ANYTLS_LINKS=""
}

# ==================== 从配置文件加载节点 ====================
load_inbounds_from_config() {
    if [[ ! -f "${CONFIG_FILE}" ]] || ! command -v jq &>/dev/null; then
        return 1
    fi
    
    INBOUND_TAGS=()
    INBOUND_PORTS=()
    INBOUND_PROTOS=()
    INBOUND_SNIS=()
    INBOUND_RELAY_TAGS=()
    INBOUNDS_JSON=""
    
    local inbounds_count=$(jq '.inbounds | length' "${CONFIG_FILE}" 2>/dev/null || echo "0")
    [[ "$inbounds_count" -eq 0 ]] && return 1
    
    local inbound_list=""
    for ((i=0; i<inbounds_count; i++)); do
        local inbound=$(jq -c ".inbounds[${i}]" "${CONFIG_FILE}" 2>/dev/null)
        [[ -z "$inbound" ]] && continue
        
        [[ -z "$inbound_list" ]] && inbound_list="$inbound" || inbound_list="${inbound_list},${inbound}"
        
        local tag=$(echo "$inbound" | jq -r '.tag' 2>/dev/null)
        local port=$(echo "$inbound" | jq -r '.listen_port' 2>/dev/null)
        
        [[ "$tag" == "shadowsocks-in-"* ]] && continue
        
        local proto="unknown"
        local sni=""
        
        case "$tag" in
            *"vless-tls-in"*)   proto="HTTPS"; sni=$(echo "$inbound" | jq -r '.tls.server_name // ""' 2>/dev/null) ;;
            *"vless-in"*)       proto="Reality"; sni=$(echo "$inbound" | jq -r '.tls.server_name // ""' 2>/dev/null) ;;
            *"hy2-in"*)         proto="Hysteria2"; sni=$(echo "$inbound" | jq -r '.tls.server_name // ""' 2>/dev/null) ;;
            *"shadowtls-in"*)   proto="ShadowTLS v3"; sni=$(echo "$inbound" | jq -r '.handshake.server // ""' 2>/dev/null) ;;
            *"socks-in"*)       proto="SOCKS5" ;;
            *"anytls-in"*)      proto="AnyTLS"; sni=$(echo "$inbound" | jq -r '.tls.server_name // ""' 2>/dev/null) ;;
        esac
        
        [[ -z "$sni" ]] && sni="${DEFAULT_SNI}"
        
        INBOUND_TAGS+=("$tag")
        INBOUND_PORTS+=("$port")
        INBOUND_PROTOS+=("$proto")
        INBOUND_SNIS+=("$sni")
        INBOUND_RELAY_TAGS+=("direct")
    done
    
    INBOUNDS_JSON="$inbound_list"
    
    # 恢复中转配置
    local route_rules=$(jq -c '.route.rules[]? // empty' "${CONFIG_FILE}" 2>/dev/null)
    if [[ -n "$route_rules" ]]; then
        while IFS= read -r rule; do
            local inbound_array=$(echo "$rule" | jq -r '.inbound[]? // empty' 2>/dev/null)
            local outbound=$(echo "$rule" | jq -r '.outbound // ""' 2>/dev/null)
            if [[ -n "$outbound" && "$outbound" != "direct" ]]; then
                while IFS= read -r inbound_tag; do
                    for i in "${!INBOUND_TAGS[@]}"; do
                        [[ "${INBOUND_TAGS[$i]}" == "$inbound_tag" ]] && INBOUND_RELAY_TAGS[$i]="$outbound" && break
                    done
                done <<< "$inbound_array"
            fi
        done <<< "$route_rules"
    fi
    
    return 0
}

# ==================== 从配置文件重新生成链接 ====================
regenerate_links_from_config() {
    print_info "正在从配置文件重新生成链接..."

    cleanup_links
    [[ -f "${KEY_FILE}" ]] && source "${KEY_FILE}"
    [[ -z "${SERVER_IP}" ]] && get_ip

    if [[ ! -f "${CONFIG_FILE}" ]] || ! command -v jq &>/dev/null; then
        print_warning "无法重新生成：缺少配置文件或 jq"
        return 1
    fi

    local count=$(jq '.inbounds | length' "${CONFIG_FILE}" 2>/dev/null || echo "0")
    [[ "$count" -eq 0 ]] && { print_warning "配置文件中无节点"; return 1; }

    for ((i=0; i<count; i++)); do
        local inbound=$(jq -c ".inbounds[${i}]" "${CONFIG_FILE}" 2>/dev/null)
        [[ -z "$inbound" ]] && continue

        local type=$(echo "$inbound" | jq -r '.type' 2>/dev/null)
        local port=$(echo "$inbound" | jq -r '.listen_port' 2>/dev/null)
        local tag=$(echo "$inbound" | jq -r '.tag' 2>/dev/null)

        [[ -z "$type" || -z "$port" ]] && continue

        case "$type" in
            "vless")
                local tls_enabled=$(echo "$inbound" | jq -r '.tls.enabled // false' 2>/dev/null)
                if [[ "$tls_enabled" == "true" ]]; then
                    local reality_enabled=$(echo "$inbound" | jq -r '.tls.reality.enabled // false' 2>/dev/null)
                    if [[ "$reality_enabled" == "true" ]]; then
                        # Reality
                        local uuid=$(echo "$inbound" | jq -r '.users[0].uuid // ""' 2>/dev/null)
                        local sni=$(echo "$inbound" | jq -r '.tls.server_name // ""' 2>/dev/null)
                        local pbk=$(echo "$inbound" | jq -r '.tls.reality.public_key // ""' 2>/dev/null)
                        local sid=$(echo "$inbound" | jq -r '.tls.reality.short_id[0] // ""' 2>/dev/null)

                        [[ -z "$uuid" && -n "${UUID}" ]] && uuid="${UUID}"
                        [[ -z "$pbk" && -n "${REALITY_PUBLIC}" ]] && pbk="${REALITY_PUBLIC}"
                        [[ -z "$sid" && -n "${SHORT_ID}" ]] && sid="${SHORT_ID}"
                        [[ -z "$sni" ]] && sni="${DEFAULT_SNI}"

                        if [[ -n "$uuid" && -n "$pbk" ]]; then
                            local LINK="vless://${uuid}@${SERVER_IP}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=chrome&pbk=${pbk}&sid=${sid}&type=tcp#Reality-${SERVER_IP}"
                            local line="[Reality] ${SERVER_IP}:${port} (SNI: ${sni})\n${LINK}\n----------------------------------------\n\n"
                            ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}"
                            REALITY_LINKS="${REALITY_LINKS}${line}"
                        fi
                    else
                        # HTTPS
                        local uuid=$(echo "$inbound" | jq -r '.users[0].uuid // ""' 2>/dev/null)
                        local sni=$(echo "$inbound" | jq -r '.tls.server_name // ""' 2>/dev/null)

                        [[ -z "$uuid" && -n "${UUID}" ]] && uuid="${UUID}"
                        [[ -z "$sni" ]] && sni="${DEFAULT_SNI}"

                        if [[ -n "$uuid" ]]; then
                            local LINK="vless://${uuid}@${SERVER_IP}:${port}?encryption=none&security=tls&sni=${sni}&type=tcp&allowInsecure=1#HTTPS-${SERVER_IP}"
                            local line="[HTTPS] ${SERVER_IP}:${port} (SNI: ${sni})\n${LINK}\n----------------------------------------\n\n"
                            ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}"
                            HTTPS_LINKS="${HTTPS_LINKS}${line}"
                        fi
                    fi
                fi
                ;;
            "hysteria2")
                local password=$(echo "$inbound" | jq -r '.users[0].password // ""' 2>/dev/null)
                local sni=$(echo "$inbound" | jq -r '.tls.server_name // ""' 2>/dev/null)
                local obfs_type=$(echo "$inbound" | jq -r '.obfs.type // ""' 2>/dev/null)
                local obfs_password=$(echo "$inbound" | jq -r '.obfs.password // ""' 2>/dev/null)
                local port_range_num=$(echo "$inbound" | jq -r '.port_range // 0' 2>/dev/null)
                local listen_port=$(echo "$inbound" | jq -r '.listen_port' 2>/dev/null)

                [[ -z "$sni" ]] && sni="${DEFAULT_SNI}"

                if [[ -n "$password" ]]; then
                    local port_part="$port"
                    if [[ "$port_range_num" -gt 1 ]]; then
                        local end_port=$(( listen_port + port_range_num - 1 ))
                        port_part="${listen_port}-${end_port}"
                    fi
                    local LINK="hysteria2://${password}@${SERVER_IP}:${port_part}?insecure=1&sni=${sni}"
                    if [[ "$obfs_type" == "salamander" && -n "$obfs_password" ]]; then
                        LINK="${LINK}&obfs=salamander&obfs-password=${obfs_password}"
                    fi
                    LINK="${LINK}#Hysteria2-${SERVER_IP}"
                    local line="[Hysteria2] ${SERVER_IP}:${port_part} (SNI: ${sni})\n${LINK}\n----------------------------------------\n\n"
                    ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}"
                    HYSTERIA2_LINKS="${HYSTERIA2_LINKS}${line}"
                fi
                ;;
            "socks")
                local username=$(echo "$inbound" | jq -r '.users[0].username // ""' 2>/dev/null)
                local password=$(echo "$inbound" | jq -r '.users[0].password // ""' 2>/dev/null)
                local LINK=""
                if [[ -n "$username" && -n "$password" ]]; then
                    LINK="socks5://${username}:${password}@${SERVER_IP}:${port}#SOCKS5-${SERVER_IP}"
                else
                    LINK="socks5://${SERVER_IP}:${port}#SOCKS5-${SERVER_IP}"
                fi
                if [[ -n "$LINK" ]]; then
                    local line="[SOCKS5] ${SERVER_IP}:${port}\n${LINK}\n----------------------------------------\n\n"
                    ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}"
                    SOCKS5_LINKS="${SOCKS5_LINKS}${line}"
                fi
                ;;
            "shadowtls")
                local shadowtls_password=$(echo "$inbound" | jq -r '.users[0].password // ""' 2>/dev/null)
                local sni=$(echo "$inbound" | jq -r '.handshake.server // ""' 2>/dev/null)
                [[ -z "$sni" ]] && sni="${DEFAULT_SNI}"
                if [[ -n "$shadowtls_password" ]]; then
                    local ss_inbound=$(jq -c ".inbounds[] | select(.tag == \"shadowsocks-in-${port}\")" "${CONFIG_FILE}" 2>/dev/null)
                    local ss_password=$(echo "$ss_inbound" | jq -r '.password // ""' 2>/dev/null)
                    local ss_method=$(echo "$ss_inbound" | jq -r '.method // "2022-blake3-aes-128-gcm"' 2>/dev/null)
                    if [[ -n "$ss_password" ]]; then
                        local ss_userinfo=$(echo -n "${ss_method}:${ss_password}" | base64 -w0 | sed 's/+/-/g; s/\//_/g; s/=//g')
                        local plugin_json="{\"version\":\"3\",\"password\":\"${shadowtls_password}\",\"host\":\"${sni}\",\"port\":\"${port}\",\"address\":\"${SERVER_IP}\"}"
                        local plugin_base64=$(echo -n "$plugin_json" | base64 -w0 | sed 's/+/-/g; s/\//_/g; s/=//g')
                        local LINK="ss://${ss_userinfo}@${SERVER_IP}:${port}?shadow-tls=${plugin_base64}#ShadowTLS-${SERVER_IP}"
                        local line="[ShadowTLS v3] ${SERVER_IP}:${port} (SNI: ${sni})\n${LINK}\n----------------------------------------\n\n"
                        ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}"
                        SHADOWTLS_LINKS="${SHADOWTLS_LINKS}${line}"
                    fi
                fi
                ;;
            "anytls")
                local password=$(echo "$inbound" | jq -r '.users[0].password // ""' 2>/dev/null)
                local sni=$(echo "$inbound" | jq -r '.tls.server_name // ""' 2>/dev/null)
                [[ -z "$sni" ]] && sni="${DEFAULT_SNI}"
                if [[ -n "$password" ]]; then
                    local LINK="anytls://${password}@${SERVER_IP}:${port}?security=tls&fp=chrome&insecure=1&sni=${sni}&type=tcp#AnyTLS-${SERVER_IP}"
                    local line="[AnyTLS] ${SERVER_IP}:${port} (SNI: ${sni})\n${LINK}\n----------------------------------------\n\n"
                    ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}"
                    ANYTLS_LINKS="${ANYTLS_LINKS}${line}"
                fi
                ;;
        esac
    done

    print_success "链接重新生成完成"
    save_links_to_files
}

regenerate_all_links() {
    echo ""
    echo -e "${YELLOW}此操作将从配置文件重新生成所有节点链接${NC}"
    echo ""
    [[ ! -f "${CONFIG_FILE}" ]] && { print_error "配置文件不存在"; return 1; }
    cleanup_links
    if regenerate_links_from_config; then
        print_success "链接文件已重新生成"
    else
        print_error "重新生成失败"
        return 1
    fi
}
# ==================== Reality ====================
setup_reality() {
    echo ""
    read_port_with_check 443
    
    echo -e "${YELLOW}请输入 SNI 域名${NC} (例如: itunes.apple.com, time.is)"
    read -p "SNI [${DEFAULT_SNI}]: " SNI
    SNI=${SNI:-${DEFAULT_SNI}}

    # Short ID 交互式修改（密钥文件中已有默认随机值）
    echo -e "${YELLOW}当前 Short ID: ${SHORT_ID}${NC}"
    read -p "是否修改 Short ID？(y/N): " CHANGE_SID
    if [[ "$CHANGE_SID" =~ ^[Yy]$ ]]; then
        read -p "请输入 16 位十六进制 Short ID: " NEW_SID
        if [[ ${#NEW_SID} -eq 16 && "$NEW_SID" =~ ^[0-9a-fA-F]{16}$ ]]; then
            SHORT_ID="$NEW_SID"
            print_success "Short ID 已更新"
            save_keys_to_file
        else
            print_warning "格式无效，继续使用原 Short ID"
        fi
    fi

    local LISTEN_ADDR=$(get_listen_addr)
    print_info "生成配置文件..."
    
    local inbound="{
  \"type\": \"vless\",
  \"tag\": \"vless-in-${PORT}\",
  \"listen\": \"${LISTEN_ADDR}\",
  \"listen_port\": ${PORT},
  \"users\": [{\"uuid\": \"${UUID}\", \"flow\": \"xtls-rprx-vision\"}],
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
    
    [[ -z "$INBOUNDS_JSON" ]] && INBOUNDS_JSON="$inbound" || INBOUNDS_JSON="${INBOUNDS_JSON},${inbound}"
    
    local LINK="vless://${UUID}@${SERVER_IP}:${PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=chrome&pbk=${REALITY_PUBLIC}&sid=${SHORT_ID}&type=tcp#Reality-${SERVER_IP}"
    local line="[Reality] ${SERVER_IP}:${PORT} (SNI: ${SNI})\n${LINK}\n----------------------------------------\n\n"
    ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}"
    REALITY_LINKS="${REALITY_LINKS}${line}"
    
    INBOUND_TAGS+=("vless-in-${PORT}")
    INBOUND_PORTS+=("${PORT}")
    INBOUND_PROTOS+=("Reality")
    INBOUND_SNIS+=("${SNI}")
    INBOUND_RELAY_TAGS+=("direct")
    
    print_success "Reality 配置完成 (SNI: ${SNI})"
    save_links_to_files
}

# ==================== Hysteria2 (支持端口跳跃) ====================
setup_hysteria2() {
    echo ""
    read_port_with_check 443
    
    # 端口跳跃
    read -p "是否启用端口跳跃？(y/N): " ENABLE_JUMP
    ENABLE_JUMP=${ENABLE_JUMP:-N}
    local port_range=0
    local end_port=$PORT
    if [[ "$ENABLE_JUMP" =~ ^[Yy]$ ]]; then
        read -p "跳跃端口数量 (例如 10，则端口范围为 ${PORT}-$((PORT+9))): " port_range
        [[ -z "$port_range" || ! "$port_range" =~ ^[0-9]+$ ]] && port_range=10
        end_port=$((PORT + port_range - 1))
    fi
    
    echo -e "${YELLOW}请输入 SNI 域名${NC}"
    read -p "SNI [${DEFAULT_SNI}]: " HY2_SNI
    HY2_SNI=${HY2_SNI:-${DEFAULT_SNI}}
    
    # 混淆
    read -p "是否启用 Salamander 混淆？(y/N): " ENABLE_OBFS
    ENABLE_OBFS=${ENABLE_OBFS:-N}
    local OBFS_PASSWORD=""
    if [[ "$ENABLE_OBFS" =~ ^[Yy]$ ]]; then
        read -p "混淆密码 (留空随机): " OBFS_PASSWORD
        [[ -z "$OBFS_PASSWORD" ]] && OBFS_PASSWORD=$(openssl rand -hex 16)
    fi
    
    gen_cert_for_sni "${HY2_SNI}"
    local LISTEN_ADDR=$(get_listen_addr)
    print_info "生成配置文件..."
    
    # 构建 obfs 配置
    local obfs_config=""
    [[ "$ENABLE_OBFS" =~ ^[Yy]$ ]] && obfs_config=",\"obfs\": {\"type\": \"salamander\", \"password\": \"${OBFS_PASSWORD}\"}"
    
    # 端口跳跃配置
    local port_range_config=""
    [[ $port_range -gt 1 ]] && port_range_config=",\"port_range\": ${port_range}"
    
    local inbound="{
  \"type\": \"hysteria2\",
  \"tag\": \"hy2-in-${PORT}\",
  \"listen\": \"${LISTEN_ADDR}\",
  \"listen_port\": ${PORT}${port_range_config},
  \"users\": [{\"password\": \"${HY2_PASSWORD}\"}],
  \"tls\": {
    \"enabled\": true,
    \"alpn\": [\"h3\"],
    \"server_name\": \"${HY2_SNI}\",
    \"certificate_path\": \"${CERT_DIR}/${HY2_SNI}/cert.pem\",
    \"key_path\": \"${CERT_DIR}/${HY2_SNI}/private.key\"
  }${obfs_config}
}"
    
    [[ -z "$INBOUNDS_JSON" ]] && INBOUNDS_JSON="$inbound" || INBOUNDS_JSON="${INBOUNDS_JSON},${inbound}"
    
    # 生成链接
    local port_part="$PORT"
    [[ $port_range -gt 1 ]] && port_part="${PORT}-${end_port}"
    local LINK="hysteria2://${HY2_PASSWORD}@${SERVER_IP}:${port_part}?insecure=1&sni=${HY2_SNI}"
    [[ "$ENABLE_OBFS" =~ ^[Yy]$ ]] && LINK="${LINK}&obfs=salamander&obfs-password=${OBFS_PASSWORD}"
    LINK="${LINK}#Hysteria2-${SERVER_IP}"
    
    local line="[Hysteria2] ${SERVER_IP}:${port_part} (SNI: ${HY2_SNI})\n${LINK}\n----------------------------------------\n\n"
    ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}"
    HYSTERIA2_LINKS="${HYSTERIA2_LINKS}${line}"
    
    INBOUND_TAGS+=("hy2-in-${PORT}")
    INBOUND_PORTS+=("${PORT}")
    INBOUND_PROTOS+=("Hysteria2")
    INBOUND_SNIS+=("${HY2_SNI}")
    INBOUND_RELAY_TAGS+=("direct")
    
    print_success "Hysteria2 配置完成"
    [[ $port_range -gt 1 ]] && print_info "端口跳跃: ${PORT}-${end_port}"
    save_links_to_files
}

# ==================== SOCKS5 ====================
setup_socks5() {
    echo ""
    read_port_with_check 1080
    read -p "启用认证? [Y/n]: " ENABLE_AUTH
    ENABLE_AUTH=${ENABLE_AUTH:-Y}
    
    local LISTEN_ADDR=$(get_listen_addr)
    print_info "生成配置文件..."
    
    local inbound=""
    local LINK=""
    if [[ "$ENABLE_AUTH" =~ ^[Yy]$ ]]; then
        inbound="{
  \"type\": \"socks\",
  \"tag\": \"socks-in-${PORT}\",
  \"listen\": \"${LISTEN_ADDR}\",
  \"listen_port\": ${PORT},
  \"users\": [{\"username\": \"${SOCKS_USER}\", \"password\": \"${SOCKS_PASS}\"}]
}"
        LINK="socks5://${SOCKS_USER}:${SOCKS_PASS}@${SERVER_IP}:${PORT}#SOCKS5-${SERVER_IP}"
    else
        inbound="{
  \"type\": \"socks\",
  \"tag\": \"socks-in-${PORT}\",
  \"listen\": \"${LISTEN_ADDR}\",
  \"listen_port\": ${PORT}
}"
        LINK="socks5://${SERVER_IP}:${PORT}#SOCKS5-${SERVER_IP}"
    fi
    
    [[ -z "$INBOUNDS_JSON" ]] && INBOUNDS_JSON="$inbound" || INBOUNDS_JSON="${INBOUNDS_JSON},${inbound}"
    
    local line="[SOCKS5] ${SERVER_IP}:${PORT}\n${LINK}\n----------------------------------------\n\n"
    ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}"
    SOCKS5_LINKS="${SOCKS5_LINKS}${line}"
    
    INBOUND_TAGS+=("socks-in-${PORT}")
    INBOUND_PORTS+=("${PORT}")
    INBOUND_PROTOS+=("SOCKS5")
    INBOUND_SNIS+=("")
    INBOUND_RELAY_TAGS+=("direct")
    
    print_success "SOCKS5 配置完成"
    save_links_to_files
}
# ==================== ShadowTLS v3 ====================
setup_shadowtls() {
    echo ""
    read_port_with_check 443
    
    read -p "SNI [${DEFAULT_SNI}]: " SHADOWTLS_SNI
    SHADOWTLS_SNI=${SHADOWTLS_SNI:-${DEFAULT_SNI}}
    
    local LISTEN_ADDR=$(get_listen_addr)
    print_info "生成配置文件..."
    
    local inbound="{
  \"type\": \"shadowtls\",
  \"tag\": \"shadowtls-in-${PORT}\",
  \"listen\": \"${LISTEN_ADDR}\",
  \"listen_port\": ${PORT},
  \"version\": 3,
  \"users\": [{\"password\": \"${SHADOWTLS_PASSWORD}\"}],
  \"handshake\": {
    \"server\": \"${SHADOWTLS_SNI}\",
    \"server_port\": 443
  },
  \"strict_mode\": true,
  \"detour\": \"shadowsocks-in-${PORT}\"
},
{
  \"type\": \"shadowsocks\",
  \"tag\": \"shadowsocks-in-${PORT}\",
  \"listen\": \"127.0.0.1\",
  \"network\": \"tcp\",
  \"method\": \"2022-blake3-aes-128-gcm\",
  \"password\": \"${SS_PASSWORD}\"
}"
    
    local ss_userinfo=$(echo -n "2022-blake3-aes-128-gcm:${SS_PASSWORD}" | base64 -w0 | sed 's/+/-/g; s/\//_/g; s/=//g')
    local plugin_json="{\"version\":\"3\",\"password\":\"${SHADOWTLS_PASSWORD}\",\"host\":\"${SHADOWTLS_SNI}\",\"port\":\"${PORT}\",\"address\":\"${SERVER_IP}\"}"
    local plugin_base64=$(echo -n "$plugin_json" | base64 -w0 | sed 's/+/-/g; s/\//_/g; s/=//g')
    local LINK="ss://${ss_userinfo}@${SERVER_IP}:${PORT}?shadow-tls=${plugin_base64}#ShadowTLS-${SERVER_IP}"
    
    [[ -z "$INBOUNDS_JSON" ]] && INBOUNDS_JSON="$inbound" || INBOUNDS_JSON="${INBOUNDS_JSON},${inbound}"
    
    # 客户端配置
    local client_config_file="${LINK_DIR}/shadowtls_client_${PORT}.json"
    cat > "${client_config_file}" << EOFCLIENT
{
  "log": {"level": "info"},
  "dns": {"servers": [{"tag": "google", "address": "8.8.8.8"}]},
  "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 1080, "sniff": true}],
  "outbounds": [
    {"type": "selector", "tag": "proxy", "outbounds": ["ShadowTLS-${PORT}"], "default": "ShadowTLS-${PORT}"},
    {"type": "shadowsocks", "tag": "ShadowTLS-${PORT}", "method": "2022-blake3-aes-128-gcm", "password": "${SS_PASSWORD}", "detour": "shadowtls-out-${PORT}"},
    {"type": "shadowtls", "tag": "shadowtls-out-${PORT}", "server": "${SERVER_IP}", "server_port": ${PORT}, "version": 3, "password": "${SHADOWTLS_PASSWORD}", "tls": {"enabled": true, "server_name": "${SHADOWTLS_SNI}", "utls": {"enabled": true, "fingerprint": "chrome"}}},
    {"type": "direct", "tag": "direct"},
    {"type": "block", "tag": "block"}
  ],
  "route": {"rules": [{"geosite": "cn", "outbound": "direct"}, {"geoip": "cn", "outbound": "direct"}], "final": "proxy"}
}
EOFCLIENT
    
    local line="[ShadowTLS v3] ${SERVER_IP}:${PORT} (SNI: ${SHADOWTLS_SNI})\n${LINK}\n客户端配置: ${client_config_file}\n----------------------------------------\n\n"
    ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}"
    SHADOWTLS_LINKS="${SHADOWTLS_LINKS}${line}"
    
    INBOUND_TAGS+=("shadowtls-in-${PORT}")
    INBOUND_PORTS+=("${PORT}")
    INBOUND_PROTOS+=("ShadowTLS v3")
    INBOUND_SNIS+=("${SHADOWTLS_SNI}")
    INBOUND_RELAY_TAGS+=("direct")
    
    print_success "ShadowTLS v3 配置完成"
    save_links_to_files
}

# ==================== HTTPS ====================
setup_https() {
    echo ""
    read_port_with_check 443
    
    read -p "SNI [${DEFAULT_SNI}]: " HTTPS_SNI
    HTTPS_SNI=${HTTPS_SNI:-${DEFAULT_SNI}}
    
    gen_cert_for_sni "${HTTPS_SNI}"
    local LISTEN_ADDR=$(get_listen_addr)
    print_info "生成配置文件..."
    
    local inbound="{
  \"type\": \"vless\",
  \"tag\": \"vless-tls-in-${PORT}\",
  \"listen\": \"${LISTEN_ADDR}\",
  \"listen_port\": ${PORT},
  \"users\": [{\"uuid\": \"${UUID}\"}],
  \"tls\": {
    \"enabled\": true,
    \"server_name\": \"${HTTPS_SNI}\",
    \"certificate_path\": \"${CERT_DIR}/${HTTPS_SNI}/cert.pem\",
    \"key_path\": \"${CERT_DIR}/${HTTPS_SNI}/private.key\"
  }
}"
    
    local LINK="vless://${UUID}@${SERVER_IP}:${PORT}?encryption=none&security=tls&sni=${HTTPS_SNI}&type=tcp&allowInsecure=1#HTTPS-${SERVER_IP}"
    
    [[ -z "$INBOUNDS_JSON" ]] && INBOUNDS_JSON="$inbound" || INBOUNDS_JSON="${INBOUNDS_JSON},${inbound}"
    
    local line="[HTTPS] ${SERVER_IP}:${PORT} (SNI: ${HTTPS_SNI})\n${LINK}\n----------------------------------------\n\n"
    ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}"
    HTTPS_LINKS="${HTTPS_LINKS}${line}"
    
    INBOUND_TAGS+=("vless-tls-in-${PORT}")
    INBOUND_PORTS+=("${PORT}")
    INBOUND_PROTOS+=("HTTPS")
    INBOUND_SNIS+=("${HTTPS_SNI}")
    INBOUND_RELAY_TAGS+=("direct")
    
    print_success "HTTPS 配置完成"
    save_links_to_files
}

# ==================== AnyTLS ====================
setup_anytls() {
    echo ""
    read_port_with_check 443
    
    read -p "SNI [${DEFAULT_SNI}]: " ANYTLS_SNI
    ANYTLS_SNI=${ANYTLS_SNI:-${DEFAULT_SNI}}
    
    read -p "启用随机填充混淆 (推荐)？[Y/n]: " ENABLE_PADDING
    ENABLE_PADDING=${ENABLE_PADDING:-Y}
    local padding_config=""
    if [[ ! "$ENABLE_PADDING" =~ ^[Nn]$ ]]; then
        padding_config="[
    \"stop=8\",
    \"0=30-30\",
    \"1=100-400\",
    \"2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\",
    \"3=9-9,500-1000\",
    \"4=500-1000\",
    \"5=500-1000\",
    \"6=500-1000\",
    \"7=500-1000\"
  ]"
    else
        padding_config="[]"
    fi
    
    gen_cert_for_sni "${ANYTLS_SNI}"
    local LISTEN_ADDR=$(get_listen_addr)
    print_info "生成配置文件..."
    
    local inbound="{
  \"type\": \"anytls\",
  \"tag\": \"anytls-in-${PORT}\",
  \"listen\": \"${LISTEN_ADDR}\",
  \"listen_port\": ${PORT},
  \"users\": [{\"password\": \"${ANYTLS_PASSWORD}\"}],
  \"padding_scheme\": ${padding_config},
  \"tls\": {
    \"enabled\": true,
    \"server_name\": \"${ANYTLS_SNI}\",
    \"certificate_path\": \"${CERT_DIR}/${ANYTLS_SNI}/cert.pem\",
    \"key_path\": \"${CERT_DIR}/${ANYTLS_SNI}/private.key\"
  }
}"
    
    local LINK="anytls://${ANYTLS_PASSWORD}@${SERVER_IP}:${PORT}?security=tls&fp=chrome&insecure=1&sni=${ANYTLS_SNI}&type=tcp#AnyTLS-${SERVER_IP}"
    
    [[ -z "$INBOUNDS_JSON" ]] && INBOUNDS_JSON="$inbound" || INBOUNDS_JSON="${INBOUNDS_JSON},${inbound}"
    
    local line="[AnyTLS] ${SERVER_IP}:${PORT} (SNI: ${ANYTLS_SNI})\n${LINK}\n----------------------------------------\n\n"
    ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}"
    ANYTLS_LINKS="${ANYTLS_LINKS}${line}"
    
    INBOUND_TAGS+=("anytls-in-${PORT}")
    INBOUND_PORTS+=("${PORT}")
    INBOUND_PROTOS+=("AnyTLS")
    INBOUND_SNIS+=("${ANYTLS_SNI}")
    INBOUND_RELAY_TAGS+=("direct")
    
    print_success "AnyTLS 配置完成"
    save_links_to_files
}
# ==================== 配置生成 ====================
generate_config() {
    print_info "生成最终配置文件..."
    [[ -z "$INBOUNDS_JSON" ]] && { print_error "请先添加节点"; return 1; }

    load_relays_from_file

    # 构建 outbounds
    local outbounds_array=()
    for relay_json in "${RELAY_JSONS[@]}"; do
        outbounds_array+=("$relay_json")
    done

    local strategy_field=""
    if [[ "$OUTBOUND_IP_MODE" == "ipv4" ]]; then
        strategy_field=', "domain_strategy": "prefer_ipv4"'
    elif [[ "$OUTBOUND_IP_MODE" == "ipv6" ]]; then
        strategy_field=', "domain_strategy": "prefer_ipv6"'
    fi
    outbounds_array+=("{\"type\": \"direct\", \"tag\": \"direct\"${strategy_field}}")

    local outbounds="["
    for i in "${!outbounds_array[@]}"; do
        [[ $i -gt 0 ]] && outbounds+=", "
        outbounds+="${outbounds_array[$i]}"
    done
    outbounds+="]"

    # 路由规则
    local route_rules=()
    for i in "${!INBOUND_TAGS[@]}"; do
        local relay_tag="${INBOUND_RELAY_TAGS[$i]}"
        [[ "$relay_tag" != "direct" ]] && route_rules+=("{\"inbound\":[\"${INBOUND_TAGS[$i]}\"],\"outbound\":\"${relay_tag}\"}")
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

    # DNS 策略
    local dns_strategy=""
    if [[ "$OUTBOUND_IP_MODE" == "ipv4" ]]; then
        dns_strategy=', "strategy": "prefer_ipv4"'
    elif [[ "$OUTBOUND_IP_MODE" == "ipv6" ]]; then
        dns_strategy=', "strategy": "prefer_ipv6"'
    fi

    cat > ${CONFIG_FILE} << EOFCONFIG
{
  "log": {"level": "info", "timestamp": true},
  "dns": {
    "servers": [
      {"tag": "local", "type": "local"},
      {"tag": "remote", "type": "udp", "server": "8.8.8.8"}
    ],
    "final": "remote"${dns_strategy}
  },
  "inbounds": [${INBOUNDS_JSON}],
  "outbounds": ${outbounds},
  "route": ${route_json}
}
EOFCONFIG

    print_success "配置文件生成完成"
}

start_svc() {
    print_info "验证配置文件..."
    local check_output=$(${INSTALL_DIR}/sing-box check -c ${CONFIG_FILE} 2>&1)
    if [[ $? -ne 0 ]]; then
        print_error "配置验证失败"
        echo "$check_output"
        return 1
    fi

    print_success "配置验证通过"
    svc_restart
    sleep 2

    if svc_is_active; then
        print_success "服务启动成功"
    else
        print_error "服务启动失败"
        [[ $ALPINE -eq 1 ]] && tail -10 /var/log/sing-box.log || journalctl -u sing-box -n 10 --no-pager
        return 1
    fi
}

# ==================== 中转链接解析 ====================
parse_socks_link() {
    local link="$1"
    if [[ "$link" =~ ^socks://([A-Za-z0-9+/=]+) ]]; then
        local base64_part="${BASH_REMATCH[1]}"
        local decoded=$(echo "$base64_part" | base64 -d 2>/dev/null)
        [[ -z "$decoded" ]] && { print_error "base64 解码失败"; return 1; }
        link="socks5://${decoded}"
    fi
    local data=$(echo "$link" | sed 's|socks5\?://||' | cut -d'?' -f1 | cut -d'#' -f1)
    local relay_json="" relay_desc=""
    if [[ "$data" =~ @ ]]; then
        local userpass=$(echo "$data" | cut -d'@' -f1)
        local username=$(echo "$userpass" | cut -d':' -f1)
        local password=$(echo "$userpass" | cut -d':' -f2-)
        local server_port=$(echo "$data" | cut -d'@' -f2)
        local server=$(echo "$server_port" | cut -d':' -f1)
        local port=$(echo "$server_port" | cut -d':' -f2)
        [[ ! "$port" =~ ^[0-9]+$ ]] && { print_error "端口无效"; return 1; }
        local tag="relay-socks5-${#RELAY_TAGS[@]}"
        relay_json="{\"type\":\"socks\",\"tag\":\"${tag}\",\"server\":\"${server}\",\"server_port\":${port},\"version\":\"5\",\"username\":\"${username}\",\"password\":\"${password}\"}"
        relay_desc="SOCKS5 ${server}:${port} (认证)"
    else
        local server=$(echo "$data" | cut -d':' -f1)
        local port=$(echo "$data" | cut -d':' -f2)
        [[ ! "$port" =~ ^[0-9]+$ ]] && { print_error "端口无效"; return 1; }
        local tag="relay-socks5-${#RELAY_TAGS[@]}"
        relay_json="{\"type\":\"socks\",\"tag\":\"${tag}\",\"server\":\"${server}\",\"server_port\":${port},\"version\":\"5\"}"
        relay_desc="SOCKS5 ${server}:${port}"
    fi
    RELAY_TAGS+=("$tag"); RELAY_JSONS+=("$relay_json"); RELAY_DESCS+=("$relay_desc")
    save_relays_to_file
    print_success "SOCKS5 中转已添加: ${relay_desc}"
}

parse_http_link() {
    local link="$1"
    local protocol=$(echo "$link" | cut -d':' -f1)
    local data=$(echo "$link" | sed 's|https\?://||')
    local tls="false"; [[ "$protocol" == "https" ]] && tls="true"
    local tag="relay-http-${#RELAY_TAGS[@]}"
    local relay_json="" relay_desc=""
    if [[ "$data" =~ @ ]]; then
        local userpass=$(echo "$data" | cut -d'@' -f1)
        local username=$(echo "$userpass" | cut -d':' -f1)
        local password=$(echo "$userpass" | cut -d':' -f2)
        local server_port=$(echo "$data" | cut -d'@' -f2)
        local server=$(echo "$server_port" | cut -d':' -f1)
        local port=$(echo "$server_port" | cut -d':' -f2 | cut -d'/' -f1 | cut -d'#' -f1 | cut -d'?' -f1)
        relay_json="{\"type\":\"http\",\"tag\":\"${tag}\",\"server\":\"${server}\",\"server_port\":${port},\"username\":\"${username}\",\"password\":\"${password}\",\"tls\":{\"enabled\":${tls}}}"
        relay_desc="${protocol^^} ${server}:${port} (认证)"
    else
        local server=$(echo "$data" | cut -d':' -f1)
        local port=$(echo "$data" | cut -d':' -f2 | cut -d'/' -f1 | cut -d'#' -f1 | cut -d'?' -f1)
        relay_json="{\"type\":\"http\",\"tag\":\"${tag}\",\"server\":\"${server}\",\"server_port\":${port},\"tls\":{\"enabled\":${tls}}}"
        relay_desc="${protocol^^} ${server}:${port}"
    fi
    RELAY_TAGS+=("$tag"); RELAY_JSONS+=("$relay_json"); RELAY_DESCS+=("$relay_desc")
    save_relays_to_file
    print_success "HTTP(S) 中转已添加: ${relay_desc}"
}

parse_ss_link() {
    local link="$1"
    local data=$(echo "$link" | sed 's|ss://||' | cut -d'#' -f1)
    if [[ "$data" =~ @ ]]; then
        local userinfo=$(echo "$data" | cut -d'@' -f1)
        local server_port=$(echo "$data" | cut -d'@' -f2 | cut -d'?' -f1)
        local server=$(echo "$server_port" | cut -d':' -f1)
        local port=$(echo "$server_port" | cut -d':' -f2)
        local decoded=$(echo "$userinfo" | base64 -d 2>/dev/null)
        [[ -z "$decoded" ]] && { print_error "Shadowsocks 链接解码失败"; return 1; }
        local method=$(echo "$decoded" | cut -d':' -f1)
        local password=$(echo "$decoded" | cut -d':' -f2-)
        local tag="relay-ss-${#RELAY_TAGS[@]}"
        local relay_json="{\"type\":\"shadowsocks\",\"tag\":\"${tag}\",\"server\":\"${server}\",\"server_port\":${port},\"method\":\"${method}\",\"password\":\"${password}\"}"
        local relay_desc="Shadowsocks ${server}:${port}"
        RELAY_TAGS+=("$tag"); RELAY_JSONS+=("$relay_json"); RELAY_DESCS+=("$relay_desc")
        save_relays_to_file
        print_success "Shadowsocks 中转已添加: ${relay_desc}"
    else
        print_error "Shadowsocks 链接格式错误"
        return 1
    fi
}

parse_vmess_link() {
    local link="$1"
    local base64_data=$(echo "$link" | sed 's|vmess://||')
    local json=$(echo "$base64_data" | base64 -d 2>/dev/null)
    [[ -z "$json" ]] && { print_error "VMess 链接解码失败"; return 1; }
    if ! command -v jq &>/dev/null; then
        print_error "需要 jq 工具来解析 VMess 链接"
        return 1
    fi
    local server=$(echo "$json" | jq -r '.add // .address')
    local port=$(echo "$json" | jq -r '.port')
    local uuid=$(echo "$json" | jq -r '.id')
    local alterId=$(echo "$json" | jq -r '.aid // 0')
    local security=$(echo "$json" | jq -r '.scy // "auto"')
    local tag="relay-vmess-${#RELAY_TAGS[@]}"
    local relay_json="{\"type\":\"vmess\",\"tag\":\"${tag}\",\"server\":\"${server}\",\"server_port\":${port},\"uuid\":\"${uuid}\",\"alter_id\":${alterId},\"security\":\"${security}\"}"
    local relay_desc="VMess ${server}:${port}"
    RELAY_TAGS+=("$tag"); RELAY_JSONS+=("$relay_json"); RELAY_DESCS+=("$relay_desc")
    save_relays_to_file
    print_success "VMess 中转已添加: ${relay_desc}"
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
    local security="none"
    local sni=""
    local flow=""
    [[ "$params" =~ security=([^&]+) ]] && security="${BASH_REMATCH[1]}"
    [[ "$params" =~ sni=([^&]+) ]] && sni="${BASH_REMATCH[1]}"
    [[ "$params" =~ flow=([^&]+) ]] && flow="${BASH_REMATCH[1]}"
    local tls_config=""
    if [[ "$security" == "tls" || "$security" == "reality" ]]; then
        tls_config=",\"tls\":{\"enabled\":true,\"server_name\":\"${sni}\"}"
    fi
    local flow_config=""
    [[ -n "$flow" ]] && flow_config=",\"flow\":\"${flow}\""
    local tag="relay-vless-${#RELAY_TAGS[@]}"
    local relay_json="{\"type\":\"vless\",\"tag\":\"${tag}\",\"server\":\"${server}\",\"server_port\":${port},\"uuid\":\"${uuid}\"${flow_config}${tls_config}}"
    local relay_desc="VLESS ${server}:${port}"
    RELAY_TAGS+=("$tag"); RELAY_JSONS+=("$relay_json"); RELAY_DESCS+=("$relay_desc")
    save_relays_to_file
    print_success "VLESS 中转已添加: ${relay_desc}"
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
    local sni=""
    [[ "$params" =~ sni=([^&]+) ]] && sni="${BASH_REMATCH[1]}"
    local tag="relay-trojan-${#RELAY_TAGS[@]}"
    local relay_json="{\"type\":\"trojan\",\"tag\":\"${tag}\",\"server\":\"${server}\",\"server_port\":${port},\"password\":\"${password}\",\"tls\":{\"enabled\":true,\"server_name\":\"${sni}\"}}"
    local relay_desc="Trojan ${server}:${port}"
    RELAY_TAGS+=("$tag"); RELAY_JSONS+=("$relay_json"); RELAY_DESCS+=("$relay_desc")
    save_relays_to_file
    print_success "Trojan 中转已添加: ${relay_desc}"
}

# ==================== 中转配置管理 ====================
save_relays_to_file() {
    mkdir -p "$(dirname "${RELAY_FILE}")"

    cat > "${RELAY_FILE}" << EOF
# Sing-box 中转配置文件
EOF
    for i in "${!RELAY_TAGS[@]}"; do
        local json_base64=$(echo "${RELAY_JSONS[$i]}" | base64 -w0)
        echo "${RELAY_TAGS[$i]}|${RELAY_DESCS[$i]}|${json_base64}" >> "${RELAY_FILE}"
    done
}

load_relays_from_file() {
    RELAY_TAGS=()
    RELAY_JSONS=()
    RELAY_DESCS=()
    [[ ! -f "${RELAY_FILE}" ]] && return 0
    while IFS='|' read -r tag desc json_base64; do
        [[ "$tag" =~ ^#.*$ || -z "$tag" ]] && continue
        local json=$(echo "$json_base64" | base64 -d 2>/dev/null)
        [[ -n "$json" ]] && RELAY_TAGS+=("$tag") && RELAY_DESCS+=("$desc") && RELAY_JSONS+=("$json")
    done < "${RELAY_FILE}"
}

setup_relay() {
    load_relays_from_file
    while true; do
        echo ""
        echo -e "${CYAN}中转配置菜单${NC}"
        echo -e "  [1] 添加中转链接"
        echo -e "  [2] 为节点配置中转"
        echo -e "  [3] 删除中转链接"
        echo -e "  [4] 清空全部中转"
        echo -e "  [0] 返回主菜单"
        read -p "选择: " r_choice
        case $r_choice in
            1)
                echo -e "${YELLOW}粘贴中转链接:${NC}"
                read -p "链接: " RELAY_LINK
                case "$RELAY_LINK" in
                    socks*)   parse_socks_link "$RELAY_LINK" ;;
                    http*)    parse_http_link "$RELAY_LINK" ;;
                    ss://*)   parse_ss_link "$RELAY_LINK" ;;
                    vmess://*) parse_vmess_link "$RELAY_LINK" ;;
                    vless://*) parse_vless_link "$RELAY_LINK" ;;
                    trojan://*) parse_trojan_link "$RELAY_LINK" ;;
                    *)        print_error "不支持的链接格式" ;;
                esac
                ;;
            2)
                if [[ ${#INBOUND_TAGS[@]} -eq 0 ]]; then
                    print_warning "当前无节点"
                    continue
                fi
                if [[ ${#RELAY_TAGS[@]} -eq 0 ]]; then
                    print_warning "无中转链接，请先添加"
                    continue
                fi
                echo "选择节点:"
                for i in "${!INBOUND_TAGS[@]}"; do
                    local relay_status="${INBOUND_RELAY_TAGS[$i]}"
                    local relay_desc="直连"
                    if [[ "$relay_status" != "direct" ]]; then
                        for j in "${!RELAY_TAGS[@]}"; do
                            [[ "${RELAY_TAGS[$j]}" == "$relay_status" ]] && relay_desc="中转: ${RELAY_DESCS[$j]}" && break
                        done
                    fi
                    echo "  [$((i+1))] ${INBOUND_PROTOS[$i]}:${INBOUND_PORTS[$i]} → ${relay_desc}"
                done
                read -p "节点序号 (0 取消): " node_idx
                [[ "$node_idx" == "0" ]] && continue
                if ! [[ "$node_idx" =~ ^[0-9]+$ ]] || (( node_idx < 1 || node_idx > ${#INBOUND_TAGS[@]} )); then
                    print_error "无效序号"; continue
                fi
                local n=$((node_idx-1))
                echo "选择中转: 0=直连"
                for i in "${!RELAY_TAGS[@]}"; do
                    echo "  [$((i+1))] ${RELAY_DESCS[$i]}"
                done
                read -p "选择: " relay_idx
                if [[ "$relay_idx" == "0" ]]; then
                    INBOUND_RELAY_TAGS[$n]="direct"
                    print_success "已设为直连"
                elif [[ "$relay_idx" =~ ^[0-9]+$ ]] && (( relay_idx >= 1 && relay_idx <= ${#RELAY_TAGS[@]} )); then
                    local r=$((relay_idx-1))
                    INBOUND_RELAY_TAGS[$n]="${RELAY_TAGS[$r]}"
                    print_success "已设为: ${RELAY_DESCS[$r]}"
                else
                    print_error "无效选择"; continue
                fi
                [[ -n "$INBOUNDS_JSON" ]] && generate_config && start_svc
                ;;
            3)
                if [[ ${#RELAY_TAGS[@]} -eq 0 ]]; then
                    print_warning "无中转链接"; continue
                fi
                echo "选择要删除的中转 (0 取消):"
                for i in "${!RELAY_TAGS[@]}"; do
                    echo "  [$((i+1))] ${RELAY_DESCS[$i]}"
                done
                read -p "序号: " del_idx
                [[ "$del_idx" == "0" ]] && continue
                if [[ "$del_idx" =~ ^[0-9]+$ ]] && (( del_idx >= 1 && del_idx <= ${#RELAY_TAGS[@]} )); then
                    local d=$((del_idx-1))
                    local del_tag="${RELAY_TAGS[$d]}"
                    local del_desc="${RELAY_DESCS[$d]}"
                    echo -n "确认删除 ${del_desc}? (y/N): "
                    read -p "" confirm
                    if [[ "$confirm" =~ ^[Yy]$ ]]; then
                        unset RELAY_TAGS[$d]; unset RELAY_JSONS[$d]; unset RELAY_DESCS[$d]
                        RELAY_TAGS=("${RELAY_TAGS[@]}"); RELAY_JSONS=("${RELAY_JSONS[@]}"); RELAY_DESCS=("${RELAY_DESCS[@]}")
                        for i in "${!INBOUND_RELAY_TAGS[@]}"; do
                            [[ "${INBOUND_RELAY_TAGS[$i]}" == "$del_tag" ]] && INBOUND_RELAY_TAGS[$i]="direct"
                        done
                        save_relays_to_file
                        print_success "已删除: ${del_desc}"
                        [[ -n "$INBOUNDS_JSON" ]] && generate_config && start_svc
                    fi
                else
                    print_error "无效序号"
                fi
                ;;
            4)
                read -p "确认清空全部中转? (y/N): " confirm
                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    RELAY_TAGS=(); RELAY_JSONS=(); RELAY_DESCS=()
                    for i in "${!INBOUND_RELAY_TAGS[@]}"; do INBOUND_RELAY_TAGS[$i]="direct"; done
                    rm -f "${RELAY_FILE}"
                    [[ -n "$INBOUNDS_JSON" ]] && generate_config && start_svc
                    print_success "已清空全部中转"
                fi
                ;;
            0) break ;;
        esac
    done
}

# ==================== 节点删除 ====================
delete_single_node() {
    if [[ ${#INBOUND_TAGS[@]} -eq 0 ]]; then
        print_warning "当前无节点"
        return 1
    fi
    echo "当前节点:"
    for i in "${!INBOUND_TAGS[@]}"; do
        echo "  [$((i+1))] ${INBOUND_PROTOS[$i]}:${INBOUND_PORTS[$i]} (SNI: ${INBOUND_SNIS[$i]})"
    done
    read -p "删除序号 (0 取消): " node_idx
    [[ "$node_idx" == "0" ]] && return
    if ! [[ "$node_idx" =~ ^[0-9]+$ ]] || (( node_idx < 1 || node_idx > ${#INBOUND_TAGS[@]} )); then
        print_error "无效序号"; return 1
    fi
    local index=$((node_idx-1))
    local tag="${INBOUND_TAGS[$index]}"
    local port="${INBOUND_PORTS[$index]}"
    local proto="${INBOUND_PROTOS[$index]}"
    echo -n "确认删除 ${proto}:${port}? (y/N): "
    read -p "" confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        print_info "已取消"
        return
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
        unset INBOUND_TAGS[$index]; unset INBOUND_PORTS[$index]; unset INBOUND_PROTOS[$index]; unset INBOUND_SNIS[$index]; unset INBOUND_RELAY_TAGS[$index]
        INBOUND_TAGS=("${INBOUND_TAGS[@]}"); INBOUND_PORTS=("${INBOUND_PORTS[@]}"); INBOUND_PROTOS=("${INBOUND_PROTOS[@]}"); INBOUND_SNIS=("${INBOUND_SNIS[@]}"); INBOUND_RELAY_TAGS=("${INBOUND_RELAY_TAGS[@]}")
        load_inbounds_from_config
        regenerate_links_from_config
        svc_restart
        sleep 2
        if svc_is_active; then
            print_success "节点已删除: ${proto}:${port}"
        else
            print_error "服务重启失败"
        fi
    else
        print_error "无法操作配置文件"
    fi
}

delete_all_nodes() {
    echo -e "${RED}将删除所有节点配置！${NC}"
    read -p "确认? 输入 YES: " confirm
    if [[ "$confirm" != "YES" ]]; then
        print_info "已取消"
        return
    fi
    INBOUNDS_JSON=""
    INBOUND_TAGS=(); INBOUND_PORTS=(); INBOUND_PROTOS=(); INBOUND_SNIS=(); INBOUND_RELAY_TAGS=()
    local dns_strategy="prefer_ipv4"
    [[ "$OUTBOUND_IP_MODE" == "ipv6" ]] && dns_strategy="prefer_ipv6"
    cat > ${CONFIG_FILE} << EOFCONFIG
{
  "log": {"level": "info", "timestamp": true},
  "dns": {
    "servers": [
      {"tag": "local", "type": "local"},
      {"tag": "remote", "type": "udp", "server": "8.8.8.8"}
    ],
    "final": "remote",
    "strategy": "${dns_strategy}"
  },
  "inbounds": [],
  "outbounds": [{"type": "direct", "tag": "direct"}],
  "route": {"final": "direct", "default_domain_resolver": "local"}
}
EOFCONFIG
    svc_stop
    cleanup_links
    print_success "所有节点已删除"
    read -p "启动空配置服务? (y/N): " start_svc_choice
    [[ "$start_svc_choice" =~ ^[Yy]$ ]] && svc_start
}
# ==================== 协议选择菜单 ====================
show_menu() {
    echo ""
    echo -e "${YELLOW}选择要添加的协议节点:${NC}"
    echo ""
    echo -e "  ${GREEN}[1]${NC} Reality        ${CYAN}→ 抗审查最强，无需证书${NC} ${YELLOW}(⭐推荐)${NC}"
    echo -e "  ${GREEN}[2]${NC} Hysteria2     ${CYAN}→ QUIC 高速，可选端口跳跃${NC}"
    echo -e "  ${GREEN}[3]${NC} SOCKS5        ${CYAN}→ 通用代理${NC}"
    echo -e "  ${GREEN}[4]${NC} ShadowTLS v3  ${CYAN}→ TLS 伪装${NC}"
    echo -e "  ${GREEN}[5]${NC} HTTPS         ${CYAN}→ 标准 TLS，可过 CDN${NC}"
    echo -e "  ${GREEN}[6]${NC} AnyTLS        ${CYAN}→ 通用 TLS 协议${NC}"
    echo ""
    read -p "选择 [1-6]: " choice
    
    case $choice in
        1) setup_reality ;;
        2) setup_hysteria2 ;;
        3) setup_socks5 ;;
        4) setup_shadowtls ;;
        5) setup_https ;;
        6) setup_anytls ;;
        *) print_error "无效选项"; return 1 ;;
    esac
    
    [[ -n "$INBOUNDS_JSON" ]] && generate_config && start_svc && show_result
}

show_result() {
    clear
    echo -e "${CYAN}╔═══════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║           ${GREEN}🎉 配置完成！${CYAN}              ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}服务器:${NC} ${SERVER_IP}"
    echo -e "${YELLOW}协议:${NC} ${PROTO}"
    echo -e "${YELLOW}端口:${NC} ${PORT}"
    [[ -n "$EXTRA_INFO" ]] && echo -e "${YELLOW}详情:${NC}\n${EXTRA_INFO}"
    echo ""
    echo -e "${GREEN}节点链接:${NC}"
    echo -e "${YELLOW}${LINK}${NC}"
}

# ==================== 出入站 IP 配置菜单 ====================
ip_config_menu() {
    while true; do
        clear
        echo -e "${CYAN}╔═══════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║           ${GREEN}出入站 IP 配置${CYAN}              ║${NC}"
        echo -e "${CYAN}╚═══════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "  IPv4: ${GREEN}${SERVER_IP:-无}${NC}    IPv6: ${GREEN}${SERVER_IPV6:-无}${NC}"
        echo -e "  入站模式: ${GREEN}${INBOUND_IP_MODE}${NC}    出站模式: ${GREEN}${OUTBOUND_IP_MODE}${NC}"
        if check_ipv6_bindv6only; then
            echo -e "  ${CYAN}✓ 系统支持双栈入站${NC}"
        else
            echo -e "  ${YELLOW}✗ 仅 IPv6 入站${NC}"
        fi
        echo ""
        echo -e "  ${GREEN}[1]${NC} 入站 IPv4    ${GREEN}[2]${NC} 入站 IPv6    ${GREEN}[3]${NC} 入站双栈(推荐)"
        echo -e "  ${GREEN}[4]${NC} 出站 IPv4    ${GREEN}[5]${NC} 出站 IPv6    ${GREEN}[6]${NC} 出站双栈"
        echo -e "  ${GREEN}[7]${NC} 修改 IPv4    ${GREEN}[8]${NC} 修改 IPv6    ${GREEN}[0]${NC} 返回"
        echo ""
        read -p "选择 [0-8]: " ip_choice
        
        case $ip_choice in
            1) INBOUND_IP_MODE="ipv4"; save_ip_config; print_success "入站已设为 IPv4" ;;
            2) INBOUND_IP_MODE="ipv6"; save_ip_config; print_success "入站已设为 IPv6" ;;
            3) if check_ipv6_bindv6only; then INBOUND_IP_MODE="dual"; save_ip_config; print_success "入站已设为双栈"; else print_error "系统不支持双栈"; fi ;;
            4) OUTBOUND_IP_MODE="ipv4"; save_ip_config; print_success "出站已设为 IPv4" ;;
            5) OUTBOUND_IP_MODE="ipv6"; save_ip_config; print_success "出站已设为 IPv6" ;;
            6) OUTBOUND_IP_MODE="dual"; save_ip_config; print_success "出站已设为双栈" ;;
            7) read -p "IPv4: " v; [[ -n "$v" ]] && SERVER_IP="$v" && save_ip_config && print_success "已更新" ;;
            8) read -p "IPv6: " v; [[ -n "$v" ]] && SERVER_IPV6="$v" && save_ip_config && print_success "已更新" ;;
            0) break ;;
            *) print_error "无效选项" ;;
        esac
        
        [[ -n "$INBOUNDS_JSON" && "$ip_choice" =~ ^[1-6]$ ]] && { read -p "立即应用? (y/N): " r; [[ "$r" =~ ^[Yy]$ ]] && generate_config && start_svc; }
        [[ "$ip_choice" != "0" ]] && read -p "按回车继续..." _
    done
}

# ==================== 配置查看菜单 ====================
config_and_view_menu() {
    while true; do
        clear
        echo -e "${CYAN}配置 / 查看节点${NC}"
        echo -e "  [1] 重新加载配置    [2] 全部节点    [3] Reality"
        echo -e "  [4] Hysteria2       [5] SOCKS5      [6] ShadowTLS"
        echo -e "  [7] HTTPS           [8] AnyTLS"
        echo -e "  [9] 删除单个节点    [10] 删除全部   [0] 返回"
        read -p "选择: " cv_choice
        case $cv_choice in
            1) [[ -f "${CONFIG_FILE}" ]] && generate_config && start_svc && print_success "已应用" || print_error "无配置" ;;
            2) clear; echo -e "${ALL_LINKS_TEXT:-暂无节点}" ;;
            3) clear; echo -e "${REALITY_LINKS:-暂无 Reality 节点}" ;;
            4) clear; echo -e "${HYSTERIA2_LINKS:-暂无 Hysteria2 节点}" ;;
            5) clear; echo -e "${SOCKS5_LINKS:-暂无 SOCKS5 节点}" ;;
            6) clear; echo -e "${SHADOWTLS_LINKS:-暂无 ShadowTLS 节点}" ;;
            7) clear; echo -e "${HTTPS_LINKS:-暂无 HTTPS 节点}" ;;
            8) clear; echo -e "${ANYTLS_LINKS:-暂无 AnyTLS 节点}" ;;
            9) delete_single_node ;;
            10) delete_all_nodes ;;
            0) break ;;
        esac
        [[ "$cv_choice" != "0" ]] && read -p "按回车继续..." _
    done
}

# ==================== 主菜单 ====================
show_main_menu() {
    clear
    echo -e "${CYAN}╔═══════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║       ${GREEN}Sing-Box 管理面板${CYAN}               ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  入站: ${GREEN}${INBOUND_IP_MODE}${NC}    出站: ${GREEN}${OUTBOUND_IP_MODE}${NC}    节点: ${GREEN}${#INBOUND_TAGS[@]}${NC}"
    echo ""
    echo -e "  ${GREEN}[1]${NC} 添加节点        ${GREEN}[2]${NC} 中转配置"
    echo -e "  ${GREEN}[3]${NC} 出入站配置      ${GREEN}[4]${NC} 查看节点"
    echo -e "  ${GREEN}[5]${NC} 重新生成链接    ${GREEN}[6]${NC} 卸载脚本"
    echo -e "  ${GREEN}[7]${NC} Argo 隧道       ${GREEN}[0]${NC} 退出"
    echo ""
}
# ==================== Argo 隧道集成 ====================
argo_menu() {
    while true; do
        clear
        echo -e "${CYAN}Argo 隧道管理${NC}"
        echo -e "  [1] 启动 Argo 脚本 (梭哈/安装/管理)"
        echo -e "  [2] 查看 Argo 节点链接"
        echo -e "  [3] 删除 Argo 节点链接"
        echo -e "  [4] 卸载 Argo 服务"
        echo -e "  [0] 返回主菜单"
        read -p "选择: " argo_opt
        case $argo_opt in
            1)
                # 运行嵌入的 argo.sh (heredoc 子进程，隔离变量)
                bash <(cat <<'ARGO_EOF'
#!/bin/bash
# onekey suoha (optimized for Alpine & Debian, supports xray & sing-box, with Alpine process keepalive)
# 快捷命令: argo

# 强制使用 bash
if [ -z "$BASH_VERSION" ]; then
    if command -v bash >/dev/null 2>&1; then
        exec bash "$0" "$@"
    else
        echo "错误：需要 bash 环境，请先安装 bash (debian: apt install bash / alpine: apk add bash)"
        exit 1
    fi
fi

# ---------- 系统检测与包管理适配 ----------
detected_os=$(grep -i PRETTY_NAME /etc/os-release | cut -d \" -f2 | awk '{print $1}')
case "$detected_os" in
    Debian|Ubuntu)    pkg_update="apt update"; pkg_install="apt -y install" ;;
    CentOS|Fedora)    pkg_update="yum -y update"; pkg_install="yum -y install" ;;
    Alpine)           pkg_update="apk update"; pkg_install="apk add -f" ;;
    *)                echo "未适配系统，尝试使用 apt"; pkg_update="apt update"; pkg_install="apt -y install" ;;
esac

install_if_missing() {
    local cmd=$1 pkg=$2
    if ! command -v "$cmd" >/dev/null 2>&1; then
        $pkg_update
        $pkg_install "$pkg"
    fi
}

install_if_missing curl curl
install_if_missing unzip unzip
install_if_missing tar tar
# Alpine 不需要 systemctl
if [ "$detected_os" != "Alpine" ]; then
    install_if_missing systemctl systemd
fi

# ---------- 通用函数 ----------
cleanup_process() {
    local proc_name=$1
    if [ "$detected_os" = "Alpine" ]; then
        kill -9 $(ps -ef | grep "$proc_name" | grep -v grep | awk '{print $1}') 2>/dev/null
    else
        kill -9 $(ps -ef | grep "$proc_name" | grep -v grep | awk '{print $2}') 2>/dev/null
    fi
}

is_alpine() { [ "$detected_os" = "Alpine" ]; }

# base64 生成 vmess 链接（兼容 Alpine busybox）
gen_vmess_link() {
    local argo_host=$1 uuid=$2 urlpath=$3 isp=$4
    local node_name="${isp//_/ }"
    local tls_json="{\"add\":\"www.visa.com.sg\",\"aid\":\"0\",\"host\":\"$argo_host\",\"id\":\"$uuid\",\"net\":\"ws\",\"path\":\"$urlpath\",\"port\":\"443\",\"ps\":\"${node_name}_tls\",\"tls\":\"tls\",\"type\":\"none\",\"v\":\"2\"}"
    local notls_json="{\"add\":\"www.visa.com.sg\",\"aid\":\"0\",\"host\":\"$argo_host\",\"id\":\"$uuid\",\"net\":\"ws\",\"path\":\"$urlpath\",\"port\":\"80\",\"ps\":\"${node_name}\",\"tls\":\"\",\"type\":\"none\",\"v\":\"2\"}"

    if is_alpine; then
        echo "vmess://$(printf "%s" "$tls_json" | base64 | tr -d '\n' | awk '{ORS=(NR%76==0?RS:"");}1')"
        echo "vmess://$(printf "%s" "$notls_json" | base64 | tr -d '\n' | awk '{ORS=(NR%76==0?RS:"");}1')"
    else
        echo "vmess://$(printf "%s" "$tls_json" | base64 -w 0)"
        echo "vmess://$(printf "%s" "$notls_json" | base64 -w 0)"
    fi
}

# 下载并准备核心（根据 core_type 和架构，从官方 API 获取最新版本）
download_core() {
    local arch=$(uname -m)
    local download_dir="${1:-.}"
    mkdir -p "$download_dir"

    if [ "$core_type" = "xray" ]; then
        local core_path="$download_dir/xray"
        if [ -f "$core_path" ]; then
            echo "xray 已存在，跳过下载"
            return
        fi
        local latest_tag=$(curl -sL https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep '"tag_name"' | tr ',' '\n' | grep '"tag_name"' | sed 's/.*: "\(.*\)".*/\1/')
        if [ -z "$latest_tag" ]; then
            echo "无法获取 xray 最新版本，请检查网络"
            exit 1
        fi
        local arch_suffix
        case "$arch" in
            x86_64|amd64)    arch_suffix="64" ;;
            i386|i686)       arch_suffix="32" ;;
            armv8|arm64|aarch64) arch_suffix="arm64-v8a" ;;
            armv7l)          arch_suffix="arm32-v7a" ;;
            *)               echo "架构 $arch 不支持 xray"; exit 1 ;;
        esac
        local filename="Xray-linux-${arch_suffix}.zip"
        local url="https://github.com/XTLS/Xray-core/releases/download/${latest_tag}/${filename}"
        curl -sL "$url" -o xray.zip
        unzip -d xray_tmp xray.zip
        mv xray_tmp/xray "$core_path"
        rm -rf xray.zip xray_tmp
        chmod +x "$core_path"
        echo "xray 下载完成"
    else  # sing-box
        local core_path="$download_dir/sing-box"
        if [ -f "$core_path" ]; then
            echo "sing-box 已存在，跳过下载"
            return
        fi
        local latest_tag=$(curl -sL https://api.github.com/repos/SagerNet/sing-box/releases/latest | grep '"tag_name"' | tr ',' '\n' | grep '"tag_name"' | sed 's/.*: "\(.*\)".*/\1/')
        if [ -z "$latest_tag" ]; then
            echo "无法获取 sing-box 最新版本，请检查网络"
            exit 1
        fi
        local version=${latest_tag#v}
        local arch_suffix
        case "$arch" in
            x86_64|amd64)    arch_suffix="amd64" ;;
            aarch64|arm64)   arch_suffix="arm64" ;;
            armv7l)          arch_suffix="armv7" ;;
            *)               echo "架构 $arch 不支持 sing-box"; exit 1 ;;
        esac
        local filename="sing-box-${version}-linux-${arch_suffix}.tar.gz"
        local url="https://github.com/SagerNet/sing-box/releases/download/${latest_tag}/${filename}"
        curl -sL "$url" -o sing-box.tar.gz
        tar -xzf sing-box.tar.gz
        mv sing-box-*/sing-box "$core_path" 2>/dev/null || mv sing-box "$core_path"
        rm -rf sing-box.tar.gz sing-box-*
        chmod +x "$core_path"
        echo "sing-box 下载完成"
    fi
}

# 生成核心配置文件（xray 或 sing-box）
gen_config() {
    local port=$1 uuid=$2 urlpath=$3
    if [ "$core_type" = "xray" ]; then
        if [ "$protocol" == "1" ]; then
            cat > xray_config.json <<EOF
{
    "inbounds": [{
        "port": $port,
        "listen": "localhost",
        "protocol": "vmess",
        "settings": {
            "clients": [{ "id": "$uuid", "alterId": 0 }]
        },
        "streamSettings": {
            "network": "ws",
            "wsSettings": { "path": "$urlpath" }
        }
    }],
    "outbounds": [{ "protocol": "freedom", "settings": {} }]
}
EOF
        else
            cat > xray_config.json <<EOF
{
    "inbounds": [{
        "port": $port,
        "listen": "localhost",
        "protocol": "vless",
        "settings": {
            "decryption": "none",
            "clients": [{ "id": "$uuid" }]
        },
        "streamSettings": {
            "network": "ws",
            "wsSettings": { "path": "$urlpath" }
        }
    }],
    "outbounds": [{ "protocol": "freedom", "settings": {} }]
}
EOF
        fi
    else  # sing-box
        if [ "$protocol" == "1" ]; then
            cat > sing-box_config.json <<EOF
{
    "inbounds": [{
        "type": "vmess",
        "tag": "vmess-in",
        "listen": "127.0.0.1",
        "listen_port": $port,
        "users": [{ "uuid": "$uuid", "alterId": 0 }],
        "transport": {
            "type": "ws",
            "path": "$urlpath"
        }
    }],
    "outbounds": [{ "type": "direct", "tag": "direct" }]
}
EOF
        else
            cat > sing-box_config.json <<EOF
{
    "inbounds": [{
        "type": "vless",
        "tag": "vless-in",
        "listen": "127.0.0.1",
        "listen_port": $port,
        "users": [{ "uuid": "$uuid" }],
        "transport": {
            "type": "ws",
            "path": "$urlpath"
        }
    }],
    "outbounds": [{ "type": "direct", "tag": "direct" }]
}
EOF
        fi
    fi
}

# 启动核心进程（安装模式用 /opt/argo 下的文件）
start_core() {
    if [ "$core_type" = "xray" ]; then
        /opt/argo/xray run -config /opt/argo/config.json >/dev/null 2>&1 &
    else
        /opt/argo/sing-box run -c /opt/argo/config.json >/dev/null 2>&1 &
    fi
}

# ---------- 梭哈模式 ----------
quicktunnel() {
    rm -rf xray cloudflared-linux xray.zip /tmp/sing-box 2>/dev/null
    if [ "$core_type" = "xray" ]; then
        rm -f xray xray.zip 2>/dev/null
    else
        rm -f sing-box sing-box.tar.gz 2>/dev/null
    fi
    download_core "./"

    local arch=$(uname -m)
    case "$arch" in
        x86_64|amd64)   curl -sL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o cloudflared-linux ;;
        i386|i686)      curl -sL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-386 -o cloudflared-linux ;;
        arm64|aarch64)  curl -sL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64 -o cloudflared-linux ;;
        armv7l)         curl -sL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm -o cloudflared-linux ;;
        *)              echo "架构 $arch 无 cloudflared 支持"; exit 1 ;;
    esac
    chmod +x cloudflared-linux

    local uuid=$(cat /proc/sys/kernel/random/uuid)
    local urlpath=$(echo "$uuid" | awk -F- '{print $1}')
    local port=$((RANDOM+10000))
    gen_config "$port" "$uuid" "$urlpath"

    if [ "$core_type" = "xray" ]; then
        ./xray run -config xray_config.json >/dev/null 2>&1 &
    else
        ./sing-box run -c sing-box_config.json >/dev/null 2>&1 &
    fi

    ./cloudflared-linux tunnel --url http://localhost:$port --no-autoupdate --edge-ip-version "$ips" --protocol http2 > argo.log 2>&1 &
    sleep 1

    local n=0 argo
    while true; do
        n=$((n+1))
        clear
        echo "等待 cloudflare argo 生成地址 已等待 $n 秒"
        argo=$(cat argo.log | grep trycloudflare.com | awk 'NR==2{print}' | awk -F// '{print $2}' | awk '{print $1}')
        if [ $n -ge 15 ]; then
            n=0
            cleanup_process cloudflared-linux
            rm -f argo.log
            clear
            echo "argo 获取超时，重试中"
            ./cloudflared-linux tunnel --url http://localhost:$port --no-autoupdate --edge-ip-version "$ips" --protocol http2 > argo.log 2>&1 &
            sleep 1
        elif [ -z "$argo" ]; then
            sleep 1
        else
            rm -f argo.log
            break
        fi
    done

    clear
    > v2ray.txt
    if [ "$protocol" == "1" ]; then
        echo -e "vmess 链接已生成, 可替换为CF优选IP\n" >> v2ray.txt
        gen_vmess_link "$argo" "$uuid" "$urlpath" "$isp" >> v2ray.txt
        echo -e "\n端口 443 可改为 2053 2083 2087 2096 8443\n" >> v2ray.txt
        echo -e "端口 80 可改为 8080 8880 2052 2082 2086 2095" >> v2ray.txt
    else
        echo -e "vless 链接已生成, 可替换为CF优选IP\n" > v2ray.txt
        echo "vless://$uuid@www.visa.com.sg:443?encryption=none&security=tls&type=ws&host=$argo&path=$urlpath#$(echo "$isp" | sed 's/_/%20/g; s/,/%2C/g')_tls" >> v2ray.txt
        echo -e "\n端口 443 可改为 2053 2083 2087 2096 8443\n" >> v2ray.txt
        echo "vless://$uuid@www.visa.com.sg:80?encryption=none&security=none&type=ws&host=$argo&path=$urlpath#$(echo "$isp" | sed 's/_/%20/g; s/,/%2C/g')" >> v2ray.txt
        echo -e "\n端口 80 可改为 8080 8880 2052 2082 2086 2095" >> v2ray.txt
    fi
    cat v2ray.txt
    echo -e "\n信息已保存 /root/v2ray.txt，重启失效！"
}

# ---------- 安装服务模式 ----------
installtunnel() {
    mkdir -p /opt/argo
    download_core "/opt/argo"
    if [ ! -f /opt/argo/cloudflared-linux ]; then
        local arch=$(uname -m)
        case "$arch" in
            x86_64|amd64)   curl -sL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o /opt/argo/cloudflared-linux ;;
            i386|i686)      curl -sL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-386 -o /opt/argo/cloudflared-linux ;;
            arm64|aarch64)  curl -sL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64 -o /opt/argo/cloudflared-linux ;;
            armv7l)         curl -sL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm -o /opt/argo/cloudflared-linux ;;
            *)              echo "架构 $arch 无 cloudflared 支持"; exit 1 ;;
        esac
        chmod +x /opt/argo/cloudflared-linux
    fi

    local uuid=$(cat /proc/sys/kernel/random/uuid)
    local urlpath=$(echo "$uuid" | awk -F- '{print $1}')
    local port=$((RANDOM+10000))
    gen_config "$port" "$uuid" "$urlpath"
    mv xray_config.json /opt/argo/config.json 2>/dev/null || mv sing-box_config.json /opt/argo/config.json

    echo "$core_type" > /opt/argo/core_type

    clear
    echo -e "\e[1;31m请用浏览器打开以下链接授权 CF 域名：如 example.com\e[0m"
    /opt/argo/cloudflared-linux --edge-ip-version "$ips" --protocol http2 tunnel login
    clear
    /opt/argo/cloudflared-linux --edge-ip-version "$ips" --protocol http2 tunnel list > argo.log 2>&1
    echo -e "已绑定隧道列表：\n"
    sed 1,2d argo.log | awk '{print $2}'
    echo -e "\n输入要使用的完整二级域名 (如 xxx.example.com)："
    read -p "域名: " domain
    if [ -z "$domain" ] || [ $(grep -o '\.' <<< "$domain" | wc -l) -eq 0 ]; then
        echo "域名格式错误"; exit 1
    fi
    local name=$(echo "$domain" | awk -F\. '{print $1}')

    if sed 1,2d argo.log | grep -qw "$name"; then
        echo "隧道 $name 已存在，尝试复用"
        local existing_id=$(sed 1,2d argo.log | awk -v n="$name" '$2==n {print $1}')
        if [ -f "/root/.cloudflared/${existing_id}.json" ]; then
            /opt/argo/cloudflared-linux --edge-ip-version "$ips" --protocol http2 tunnel cleanup "$name" >argo.log 2>&1
        else
            /opt/argo/cloudflared-linux --edge-ip-version "$ips" --protocol http2 tunnel delete "$name" >argo.log 2>&1
            /opt/argo/cloudflared-linux --edge-ip-version "$ips" --protocol http2 tunnel create "$name" >argo.log 2>&1
        fi
    else
        /opt/argo/cloudflared-linux --edge-ip-version "$ips" --protocol http2 tunnel create "$name" >argo.log 2>&1
    fi

    /opt/argo/cloudflared-linux --edge-ip-version "$ips" --protocol http2 tunnel list > argo.log 2>&1
    local tunneliud=$(sed 1,2d argo.log | awk -v n="$name" '$2==n {print $1}')
    if [ -z "$tunneliud" ]; then echo "无法获取隧道 UUID"; exit 1; fi

    echo "绑定域名 $domain"
    /opt/argo/cloudflared-linux --edge-ip-version "$ips" --protocol http2 tunnel route dns --overwrite-dns "$name" "$domain" >argo.log 2>&1

    > /opt/argo/v2ray.txt
    local isp_escaped=$(echo "$isp" | sed 's/_/%20/g; s/,/%2C/g')
    if [ "$protocol" == "1" ]; then
        echo -e "vmess 链接已生成\n" >> /opt/argo/v2ray.txt
        gen_vmess_link "$domain" "$uuid" "$urlpath" "$isp" >> /opt/argo/v2ray.txt
        echo -e "\n端口 443 可改为 2053 2083 2087 2096 8443\n端口 80 可改为 8080 8880 2052 2082 2086 2095" >> /opt/argo/v2ray.txt
    else
        echo -e "vless 链接已生成\n" > /opt/argo/v2ray.txt
        echo "vless://$uuid@www.visa.com.sg:443?encryption=none&security=tls&type=ws&host=$domain&path=$urlpath#${isp_escaped}_tls" >> /opt/argo/v2ray.txt
        echo -e "\n端口 443 可改为 2053 2083 2087 2096 8443\n" >> /opt/argo/v2ray.txt
        echo "vless://$uuid@www.visa.com.sg:80?encryption=none&security=none&type=ws&host=$domain&path=$urlpath#${isp_escaped}" >> /opt/argo/v2ray.txt
        echo -e "\n端口 80 可改为 8080 8880 2052 2082 2086 2095" >> /opt/argo/v2ray.txt
    fi

    cat > /opt/argo/config.yaml <<EOF
tunnel: $tunneliud
credentials-file: /root/.cloudflared/${tunneliud}.json

ingress:
  - hostname: '*'
    service: http://localhost:$port
EOF

    # 自启服务 (Alpine 使用 supervise-daemon 守护，稳定可靠)
    if is_alpine; then
        # 确保 cgroups 服务已启用（supervise-daemon 依赖）
        rc-update add cgroups default >/dev/null 2>&1
        rc-service cgroups start >/dev/null 2>&1

        # 创建 cloudflared OpenRC 服务脚本
        cat > /etc/init.d/argo-cloudflared <<EOF
#!/sbin/openrc-run
name="argo-cloudflared"
description="Cloudflare Tunnel for argo"

command="/opt/argo/cloudflared-linux"
command_args="--edge-ip-version $ips --protocol http2 tunnel --config /opt/argo/config.yaml run $name"
pidfile="/run/\${name}.pid"
required_files="/opt/argo/config.yaml"
command_background=true

supervisor="supervise-daemon"
respawn_delay=10
respawn_max=0

depend() {
    need net
    after firewall
}
EOF
        chmod +x /etc/init.d/argo-cloudflared

        # 创建核心 OpenRC 服务脚本
        cat > /etc/init.d/argo-core <<EOF
#!/sbin/openrc-run
name="argo-core"
description="${core_type} core for argo"

command="/opt/argo/$core_type"
$([ "$core_type" = "xray" ] && echo 'command_args="run -config /opt/argo/config.json"' || echo 'command_args="run -c /opt/argo/config.json"')
pidfile="/run/\${name}.pid"
required_files="/opt/argo/config.json"
command_background=true

supervisor="supervise-daemon"
respawn_delay=10
respawn_max=0

depend() {
    need net
    after firewall
}
EOF
        chmod +x /etc/init.d/argo-core

        # 启用并启动服务（隐藏日志输出）
        rc-update add argo-cloudflared default
        rc-update add argo-core default
        rc-service argo-cloudflared start >/dev/null 2>&1
        rc-service argo-core start >/dev/null 2>&1

        # 删除旧版 local.d 脚本（如果存在）
        rm -f /etc/local.d/argo-cloudflared.start /etc/local.d/argo-core.start 2>/dev/null
    else
        # systemd 配置（已自带 Restart=on-failure 保活）
        cat > /etc/systemd/system/argo-cloudflared.service <<EOF
[Unit]
Description=Cloudflare Tunnel (argo)
After=network.target

[Service]
TimeoutStartSec=0
Type=simple
ExecStart=/opt/argo/cloudflared-linux --edge-ip-version $ips --protocol http2 tunnel --config /opt/argo/config.yaml run $name
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

        cat > /etc/systemd/system/argo-core.service <<EOF
[Unit]
Description=Core Service (argo)
After=network.target

[Service]
TimeoutStartSec=0
Type=simple
ExecStart=$([ "$core_type" = "xray" ] && echo "/opt/argo/xray run -config /opt/argo/config.json" || echo "/opt/argo/sing-box run -c /opt/argo/config.json")
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable argo-cloudflared.service argo-core.service
        systemctl start argo-cloudflared.service argo-core.service
    fi

    # 管理脚本
    cat > /opt/argo/argo-manager.sh <<'MANAGER'
#!/bin/bash
CT=$(cat /opt/argo/core_type 2>/dev/null || echo "xray")
clear
while true; do
    if [ -f /etc/alpine-release ]; then
        cstat=$(rc-service argo-cloudflared status 2>/dev/null | grep -q "started" && echo "running" || echo "stop")
        xstat=$(rc-service argo-core status 2>/dev/null | grep -q "started" && echo "running" || echo "stop")
    else
        cstat=$(systemctl is-active argo-cloudflared.service)
        xstat=$(systemctl is-active argo-core.service)
    fi
    echo "cloudflared: $cstat   core($CT): $xstat"
    echo "1. 管理 TUNNEL"
    echo "2. 启动服务"
    echo "3. 停止服务"
    echo "4. 重启服务"
    echo "5. 卸载服务"
    echo "6. 查看 v2ray 链接"
    echo "0. 退出"
    read -p "选择: " menu
    menu=${menu:-0}
    case $menu in
        1)
            clear
            while true; do
                echo "ARGO TUNNEL 列表："
                /opt/argo/cloudflared-linux tunnel list 2>/dev/null | tail -n +3
                echo ""
                echo "1. 删除隧道  0. 返回"
                read -p "选择: " ta
                if [ "$ta" = "1" ]; then
                    read -p "隧道名: " tn
                    /opt/argo/cloudflared-linux tunnel cleanup "$tn" >/dev/null 2>&1
                    /opt/argo/cloudflared-linux tunnel delete "$tn" >/dev/null 2>&1
                    echo "已删除隧道 $tn"
                    sleep 1
                else
                    break
                fi
            done
            ;;
        2)
            if [ -f /etc/alpine-release ]; then
                rc-service argo-cloudflared start >/dev/null 2>&1
                rc-service argo-core start >/dev/null 2>&1
            else
                systemctl start argo-cloudflared.service argo-core.service
            fi
            clear
            ;;
        3)
            if [ -f /etc/alpine-release ]; then
                rc-service argo-cloudflared stop >/dev/null 2>&1
                rc-service argo-core stop >/dev/null 2>&1
            else
                systemctl stop argo-cloudflared.service argo-core.service
            fi
            clear
            ;;
        4)
            if [ -f /etc/alpine-release ]; then
                rc-service argo-cloudflared restart >/dev/null 2>&1
                rc-service argo-core restart >/dev/null 2>&1
            else
                systemctl restart argo-cloudflared.service argo-core.service
            fi
            clear
            ;;
        5)
            if [ -f /etc/alpine-release ]; then
                rc-service argo-cloudflared stop >/dev/null 2>&1
                rc-service argo-core stop >/dev/null 2>&1
                rc-update del argo-cloudflared default
                rc-update del argo-core default
                rm -f /etc/init.d/argo-cloudflared /etc/init.d/argo-core
            else
                systemctl stop argo-cloudflared.service argo-core.service
                systemctl disable argo-cloudflared.service argo-core.service
                rm -f /etc/systemd/system/argo-cloudflared.service /etc/systemd/system/argo-core.service
                systemctl daemon-reload
            fi
            rm -rf /opt/argo /usr/bin/argo ~/.cloudflared
            echo "卸载完成，API Token 请手动删除"
            exit 0
            ;;
        6)
            clear
            cat /opt/argo/v2ray.txt
            ;;
        0)
            echo "退出"
            exit 0
            ;;
    esac
done
MANAGER

    chmod +x /opt/argo/argo-manager.sh
    ln -sf /opt/argo/argo-manager.sh /usr/bin/argo

    clear
    cat /opt/argo/v2ray.txt
    echo -e "\n安装完成！管理命令: argo"
}

# ---------- 主菜单 ----------
while true; do
    clear
    echo "       _       _                              _                "
    echo "      | |     | |       ___   _   _    ___   | |__     ____       "
    echo "    __| |_____| |_     / __| | | | |  / _ \  | |_ \   / _  |   "
    echo "   |__   ______  _|    \__ \ | |_| | | (_) | | | | | | (_| | "
    echo "      | |_    | |_     |___/  \___/   \___/  |_| |_|  \____|"
    echo "       \__|    \__|"
    echo ""
    echo "欢迎使用 Agro 一键脚本"
    echo "-------------------------------------------"
    echo "1. 梭哈模式（无需域名，重启失效）"
    echo "2. 安装服务（需要 CF 域名，重启不失效）"
    echo "3. 卸载服务"
    echo "4. 管理服务"
    echo "5. 清空缓存"
    echo "0. 退出"
    read -p "选择 (默认1): " mode
    mode=${mode:-1}

    if [ "$mode" == "2" ]; then
        if [ -f /usr/bin/argo ]; then
            echo "服务已安装，跳转管理..."
            argo
            continue
        fi
    fi

    if [ "$mode" == "1" ] || [ "$mode" == "2" ]; then
        read -p "选择核心 (1.xray, 2.sing-box, 默认1): " core_choice
        core_choice=${core_choice:-1}
        if [ "$core_choice" == "1" ]; then
            core_type="xray"
        elif [ "$core_choice" == "2" ]; then
            core_type="sing-box"
        else
            echo "核心选择错误"
            read -p "按回车继续..." _
            continue
        fi

        read -p "协议 (1.vmess, 2.vless, 默认1): " protocol
        protocol=${protocol:-1}
        if [ "$protocol" != "1" ] && [ "$protocol" != "2" ]; then
            echo "协议错误"
            read -p "按回车继续..." _
            continue
        fi

        read -p "IP 版本 (4 或 6, 默认4): " ips
        ips=${ips:-4}
        if [ "$ips" != "4" ] && [ "$ips" != "6" ]; then
            echo "IP 版本错误"
            read -p "按回车继续..." _
            continue
        fi

        isp=$(curl -$ips -s https://speed.cloudflare.com/meta | awk -F\" '{print $26"-"$18"-"$30}' | sed 's/ /_/g')
    fi

    case $mode in
        1)
            cleanup_process xray; cleanup_process sing-box; cleanup_process cloudflared-linux
            rm -rf xray cloudflared-linux v2ray.txt /tmp/sing-box 2>/dev/null
            quicktunnel
            ;;
        2)
            cleanup_process xray; cleanup_process sing-box; cleanup_process cloudflared-linux
            installtunnel
            ;;
        3)
            if is_alpine; then
                kill -9 $(ps -ef | grep -E "xray|sing-box|cloudflared" | grep -v grep | awk '{print $1}') 2>/dev/null
                pkill -f "argo-cloudflared.start" 2>/dev/null
                pkill -f "argo-core.start" 2>/dev/null
                rm -rf /opt/argo /usr/bin/argo /etc/local.d/argo-*
            else
                systemctl stop argo-cloudflared.service argo-core.service 2>/dev/null
                systemctl disable argo-cloudflared.service argo-core.service 2>/dev/null
                rm -rf /opt/argo /usr/bin/argo /etc/systemd/system/argo-* ~/.cloudflared
                systemctl daemon-reload
            fi
            echo "卸载完成"
            ;;
        4)
            if [ -f /usr/bin/argo ]; then
                argo
            else
                echo "请先安装服务 (模式2)"
            fi
            ;;
        5)
            cleanup_process xray; cleanup_process sing-box; cleanup_process cloudflared-linux
            rm -rf xray cloudflared-linux v2ray.txt
            echo "缓存已清空"
            ;;
        0)
            echo "退出"
            exit 0
            ;;
        *)
            echo "无效输入"
            ;;
    esac

    # 将生成的链接同步到 sing-box 链接目录
    [ -f /root/v2ray.txt ] && cp /root/v2ray.txt /etc/sing-box/links/argo_links.txt
    [ -f /opt/argo/v2ray.txt ] && cp /opt/argo/v2ray.txt /etc/sing-box/links/argo_links.txt

    echo ""
    read -p "按回车返回主菜单..." _
done
ARGO_EOF
)
                ;;
            2)
                clear
                if [[ -f "${ARGO_LINKS_FILE}" ]]; then
                    cat "${ARGO_LINKS_FILE}"
                else
                    echo "暂无 Argo 节点链接"
                fi
                read -p "按回车继续..." _
                ;;
            3)
                if [[ -f "${ARGO_LINKS_FILE}" ]]; then
                    rm -f "${ARGO_LINKS_FILE}"
                    print_success "Argo 节点链接已删除"
                else
                    print_info "没有 Argo 节点链接文件"
                fi
                read -p "按回车继续..." _
                ;;
            4)
                print_info "开始卸载 Argo 服务..."
                # 检查并卸载
                if [[ $ALPINE -eq 1 ]]; then
                    rc-service argo-cloudflared stop 2>/dev/null
                    rc-service argo-core stop 2>/dev/null
                    rc-update del argo-cloudflared default 2>/dev/null
                    rc-update del argo-core default 2>/dev/null
                    rm -f /etc/init.d/argo-cloudflared /etc/init.d/argo-core
                    pkill -f "argo-cloudflared.start" 2>/dev/null
                    pkill -f "argo-core.start" 2>/dev/null
                else
                    systemctl stop argo-cloudflared.service argo-core.service 2>/dev/null
                    systemctl disable argo-cloudflared.service argo-core.service 2>/dev/null
                    rm -f /etc/systemd/system/argo-cloudflared.service /etc/systemd/system/argo-core.service
                    systemctl daemon-reload
                fi
                rm -rf /opt/argo /usr/bin/argo /etc/local.d/argo-* ~/.cloudflared 2>/dev/null
                rm -f "${ARGO_LINKS_FILE}"
                print_success "Argo 服务已卸载"
                read -p "按回车继续..." _
                ;;
            0) break ;;
        esac
    done
}

# ==================== 卸载 ====================
delete_self() {
    echo -e "${RED}⚠ 此操作将彻底卸载 sing-box 及本脚本${NC}"
    read -p "确认卸载? (y/N): " c
    [[ ! "$c" =~ ^[Yy]$ ]] && { print_info "已取消"; return; }
    
    svc_stop
    svc_disable
    
    [[ $ALPINE -eq 1 ]] && rm -f /etc/init.d/sing-box || { rm -f /etc/systemd/system/sing-box.service; systemctl daemon-reload 2>/dev/null; }
    
    rm -rf /etc/sing-box /usr/local/bin/sing-box /usr/local/bin/sb 2>/dev/null
    rm -f "${SCRIPT_PATH}" 2>/dev/null
    
    print_success "卸载完成"
    exit 0
}

# ==================== 主循环 ====================
main_loop() {
    while true; do
        load_inbounds_from_config 2>/dev/null
        load_relays_from_file
        load_ip_config
        show_main_menu
        read -p "选择 [0-7]: " m_choice
        
        case $m_choice in
            1) show_menu ;;
            2) setup_relay ;;
            3) ip_config_menu ;;
            4) config_and_view_menu ;;
            5) regenerate_all_links ;;
            6) delete_self ;;
            7) argo_menu ;;
            0) echo "已退出"; exit 0 ;;
            *) print_error "无效选项" ;;
        esac
        
        [[ "$m_choice" != "0" ]] && read -p "按回车返回主菜单..." _
    done
}

# ==================== 启动 ====================
main() {
    [[ $EUID -ne 0 ]] && { print_error "需要 root 权限"; exit 1; }
    
    detect_system
    install_singbox
    mkdir -p /etc/sing-box
    gen_keys
    
    load_ip_config
    get_ip
    
    # 快捷命令 sb
    if [[ -f "${SCRIPT_PATH}" ]]; then
        cat > /usr/local/bin/sb << EOSB
#!/bin/bash
bash "${SCRIPT_PATH}"
EOSB
        chmod +x /usr/local/bin/sb
        print_success "快捷命令 sb 已创建"
    fi
    
    [[ -f "${CONFIG_FILE}" ]] && load_inbounds_from_config
    load_relays_from_file
    load_links_from_files
    
    [[ -f "${CONFIG_FILE}" && -z "$ALL_LINKS_TEXT" ]] && regenerate_links_from_config
    
    main_loop
}

main
