#!/bin/bash

# Sing-box 一键安装管理脚本 - 完整版
# 支持协议: Reality, Hysteria2, SOCKS5, ShadowTLS, HTTPS, AnyTLS
# 支持功能: 节点管理, 中转配置, 链接查看, 完整卸载

# ==================== 颜色定义 ====================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'

# ==================== 路径配置 ====================
AUTHOR_BLOG="${SERVER_IP}"
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

# 脚本路径
SCRIPT_PATH=$(readlink -f "$0" 2>/dev/null || realpath "$0" 2>/dev/null || echo "$0")

# ==================== 全局变量 ====================
INBOUNDS_JSON=""
OUTBOUND_TAG="direct"
ALL_LINKS_TEXT=""
REALITY_LINKS=""
HYSTERIA2_LINKS=""
SOCKS5_LINKS=""
SHADOWTLS_LINKS=""
HTTPS_LINKS=""
ANYTLS_LINKS=""

# IP 配置
SERVER_IPV6=""
INBOUND_IP_MODE="ipv4"   # ipv4 或 ipv6，控制入站监听地址
OUTBOUND_IP_MODE="ipv4"  # ipv4 或 ipv6，控制出站连接
IP_CONFIG_FILE="/etc/sing-box/ip_config.conf"

# 中转配置数组
RELAY_TAGS=()        # 中转标签数组
RELAY_JSONS=()       # 中转JSON配置数组
RELAY_DESCS=()       # 中转描述数组
RELAY_FILE="/etc/sing-box/relays.conf"

# 节点数组
INBOUND_TAGS=()
INBOUND_PORTS=()
INBOUND_PROTOS=()
INBOUND_RELAY_TAGS=()  # 存储每个节点使用的中转标签，"direct" 表示直连
INBOUND_SNIS=()

RELAY_JSON=""

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

show_banner() {
    clear
    echo ""
}

# ==================== 系统检测 ====================
detect_system() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS="${NAME}"
    else
        print_error "无法检测系统"
        exit 1
    fi
    
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            ARCH="amd64"
            ;;
        aarch64)
            ARCH="arm64"
            ;;
        *)
            print_error "不支持的架构: $ARCH"
            exit 1
            ;;
    esac
    
    print_success "系统: ${OS} (${ARCH})"
}

# ==================== 安装 sing-box ====================
install_singbox() {
    print_info "检查依赖和 sing-box..."
    
    if ! command -v jq &>/dev/null || ! command -v openssl &>/dev/null; then
        print_info "安装依赖包..."
        apt-get update -qq && apt-get install -y curl wget jq openssl uuid-runtime >/dev/null 2>&1
    fi
    
    if command -v sing-box &>/dev/null; then
        local version=$(sing-box version 2>&1 | grep -oP 'sing-box version \K[0-9.]+' || echo "unknown")
        print_success "sing-box 已安装 (版本: ${version})"
        return 0
    fi
    
    print_info "下载并安装 sing-box..."
    LATEST=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r '.tag_name' | sed 's/v//')
    
    if [[ -z "$LATEST" ]]; then
        LATEST="1.12.0"
    fi
    
    print_info "目标版本: ${LATEST}"
    
    wget -q --show-progress -O /tmp/sb.tar.gz "https://github.com/SagerNet/sing-box/releases/download/v${LATEST}/sing-box-${LATEST}-linux-${ARCH}.tar.gz" 2>&1
    
    tar -xzf /tmp/sb.tar.gz -C /tmp
    install -Dm755 /tmp/sing-box-${LATEST}-linux-${ARCH}/sing-box ${INSTALL_DIR}/sing-box
    rm -rf /tmp/sb.tar.gz /tmp/sing-box-*
    
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

[Install]
WantedBy=multi-user.target
EOFSVC
    
    systemctl daemon-reload
    systemctl enable sing-box >/dev/null 2>&1
    
    print_success "sing-box 安装完成 (版本: ${LATEST})"
}

# ==================== 证书生成 ====================
gen_cert_for_sni() {
    local sni="$1"
    local node_cert_dir="${CERT_DIR}/${sni}"
    
    mkdir -p "${node_cert_dir}"
    
    openssl genrsa -out "${node_cert_dir}/private.key" 2048 2>/dev/null
    openssl req -new -x509 -days 36500 -key "${node_cert_dir}/private.key" -out "${node_cert_dir}/cert.pem" -subj "/C=US/ST=California/L=Cupertino/O=Apple Inc./CN=${sni}" 2>/dev/null
    
    print_success "证书生成完成 (${sni}, 有效期100年)"
}

# ==================== 密钥管理 ====================
gen_keys() {
    print_info "生成密钥和 UUID..."
    
    if [[ -f "${KEY_FILE}" ]]; then
        print_info "从文件加载已保存的密钥..."
        source "${KEY_FILE}"
        print_success "密钥加载完成"
        return 0
    fi
    
    KEYS=$(${INSTALL_DIR}/sing-box generate reality-keypair 2>/dev/null)
    REALITY_PRIVATE=$(echo "$KEYS" | grep "PrivateKey" | awk '{print $2}')
    REALITY_PUBLIC=$(echo "$KEYS" | grep "PublicKey" | awk '{print $2}')
    UUID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen)
    SHORT_ID=$(openssl rand -hex 8)
    HY2_PASSWORD=$(openssl rand -base64 16)
    SS_PASSWORD=$(openssl rand -base64 32)
    SHADOWTLS_PASSWORD=$(openssl rand -hex 16)
    ANYTLS_PASSWORD=$(openssl rand -base64 16)
    SOCKS_USER="user_$(openssl rand -hex 4)"
    SOCKS_PASS=$(openssl rand -base64 12)
    
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
    print_success "密钥已保存到 ${KEY_FILE}"
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

# 从配置文件加载节点信息
load_inbounds_from_config() {
    if [[ ! -f "${CONFIG_FILE}" ]]; then
        return 1
    fi
    
    if ! command -v jq &>/dev/null; then
        return 1
    fi
    
    # 清空数组
    INBOUND_TAGS=()
    INBOUND_PORTS=()
    INBOUND_PROTOS=()
    INBOUND_SNIS=()
    INBOUND_RELAY_TAGS=()
    INBOUNDS_JSON=""
    
    local inbounds_count=$(jq '.inbounds | length' "${CONFIG_FILE}" 2>/dev/null || echo "0")
    
    if [[ "$inbounds_count" -eq 0 ]]; then
        return 1
    fi
    
    local inbound_list=""
    
    for ((i=0; i<inbounds_count; i++)); do
        local inbound=$(jq -c ".inbounds[${i}]" "${CONFIG_FILE}" 2>/dev/null)
        
        if [[ -z "$inbound" ]]; then
            continue
        fi
        
        # 添加到 INBOUNDS_JSON
        if [[ -z "$inbound_list" ]]; then
            inbound_list="$inbound"
        else
            inbound_list="${inbound_list},${inbound}"
        fi
        
        # 提取信息
        local tag=$(echo "$inbound" | jq -r '.tag' 2>/dev/null || echo "unknown")
        local port=$(echo "$inbound" | jq -r '.listen_port' 2>/dev/null || echo "0")
        local type=$(echo "$inbound" | jq -r '.type' 2>/dev/null || echo "unknown")
        
        # 判断协议类型
        local proto="unknown"
        local sni=""
        
        if [[ "$tag" == *"vless-in-"* ]]; then
            proto="Reality"
            sni=$(echo "$inbound" | jq -r '.tls.server_name // ""' 2>/dev/null)
        elif [[ "$tag" == *"hy2-in-"* ]]; then
            proto="Hysteria2"
            sni=$(echo "$inbound" | jq -r '.tls.server_name // ""' 2>/dev/null)
        elif [[ "$tag" == *"socks-in"* ]]; then
            proto="SOCKS5"
        elif [[ "$tag" == *"shadowtls-in-"* ]]; then
            proto="ShadowTLS v3"
            sni=$(echo "$inbound" | jq -r '.handshake.server // ""' 2>/dev/null)
        elif [[ "$tag" == *"vless-tls-in-"* ]]; then
            proto="HTTPS"
            sni=$(echo "$inbound" | jq -r '.tls.server_name // ""' 2>/dev/null)
        elif [[ "$tag" == *"anytls-in-"* ]]; then
            proto="AnyTLS"
            sni=$(echo "$inbound" | jq -r '.tls.server_name // ""' 2>/dev/null)
        fi
        
        [[ -z "$sni" ]] && sni="${DEFAULT_SNI}"
        
        INBOUND_TAGS+=("$tag")
        INBOUND_PORTS+=("$port")
        INBOUND_PROTOS+=("$proto")
        INBOUND_SNIS+=("$sni")
        INBOUND_RELAY_TAGS+=("direct")  # 默认直连，稍后从路由规则更新
    done
    
    INBOUNDS_JSON="$inbound_list"
    
    # 从路由规则中恢复中转配置
    local route_rules=$(jq -c '.route.rules[]? // empty' "${CONFIG_FILE}" 2>/dev/null)
    if [[ -n "$route_rules" ]]; then
        while IFS= read -r rule; do
            local inbound_array=$(echo "$rule" | jq -r '.inbound[]? // empty' 2>/dev/null)
            local outbound=$(echo "$rule" | jq -r '.outbound // ""' 2>/dev/null)
            
            if [[ -n "$outbound" && "$outbound" != "direct" ]]; then
                # 为匹配的 inbound 设置中转标签
                while IFS= read -r inbound_tag; do
                    for i in "${!INBOUND_TAGS[@]}"; do
                        if [[ "${INBOUND_TAGS[$i]}" == "$inbound_tag" ]]; then
                            INBOUND_RELAY_TAGS[$i]="$outbound"
                            break
                        fi
                    done
                done <<< "$inbound_array"
            fi
        done <<< "$route_rules"
    fi
    
    return 0
}

# 从配置文件重新生成链接
regenerate_links_from_config() {
    print_info "正在从配置文件重新生成链接..."
    
    # 清空所有链接变量
    ALL_LINKS_TEXT=""
    REALITY_LINKS=""
    HYSTERIA2_LINKS=""
    SOCKS5_LINKS=""
    SHADOWTLS_LINKS=""
    HTTPS_LINKS=""
    ANYTLS_LINKS=""
    
    # 加载密钥文件
    if [[ -f "${KEY_FILE}" ]]; then
        source "${KEY_FILE}"
    fi
    
    # 确保 SERVER_IP 已设置
    if [[ -z "${SERVER_IP}" ]]; then
        get_ip
    fi
    
    if [[ ! -f "${CONFIG_FILE}" ]] || ! command -v jq &>/dev/null; then
        print_warning "无法重新生成链接：配置文件不存在或 jq 未安装"
        return 1
    fi
    
    local inbounds_count=$(jq '.inbounds | length' "${CONFIG_FILE}" 2>/dev/null || echo "0")
    
    if [[ "$inbounds_count" -eq 0 ]]; then
        print_warning "配置文件中没有找到节点"
        return 1
    fi
    
    # 遍历每个inbound生成链接
    for ((i=0; i<inbounds_count; i++)); do
        local inbound=$(jq -c ".inbounds[${i}]" "${CONFIG_FILE}" 2>/dev/null)
        
        if [[ -z "$inbound" ]]; then
            continue
        fi
        
        local type=$(echo "$inbound" | jq -r '.type' 2>/dev/null)
        local port=$(echo "$inbound" | jq -r '.listen_port' 2>/dev/null)
        local tag=$(echo "$inbound" | jq -r '.tag' 2>/dev/null)
        
        if [[ -z "$type" || -z "$port" ]]; then
            continue
        fi
        
        # 根据类型生成链接
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
                            local link="vless://${uuid}@${SERVER_IP}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=chrome&pbk=${pbk}&sid=${sid}&type=tcp#Reality-${SERVER_IP}"
                            local line="[Reality] ${SERVER_IP}:${port} (SNI: ${sni})\n${link}\n\n----------------------------------------\n\n"
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
                            local link="vless://${uuid}@${SERVER_IP}:${port}?encryption=none&security=tls&sni=${sni}&type=tcp&allowInsecure=1#HTTPS-${SERVER_IP}"
                            local line="[HTTPS] ${SERVER_IP}:${port} (SNI: ${sni})\n${link}\n\n----------------------------------------\n\n"
                            ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}"
                            HTTPS_LINKS="${HTTPS_LINKS}${line}"
                        fi
                    fi
                fi
                ;;
            "hysteria2")
                local password=$(echo "$inbound" | jq -r '.users[0].password // ""' 2>/dev/null)
                local sni=$(echo "$inbound" | jq -r '.tls.server_name // ""' 2>/dev/null)
                
                [[ -z "$sni" ]] && sni="${DEFAULT_SNI}"
                
                if [[ -n "$password" ]]; then
                    local link="hysteria2://${password}@${SERVER_IP}:${port}?insecure=1&sni=${sni}&h2=#Hysteria2-${SERVER_IP}"
                    local line="[Hysteria2] ${SERVER_IP}:${port} (SNI: ${sni})\n${link}\n\n----------------------------------------\n\n"
                    ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}"
                    HYSTERIA2_LINKS="${HYSTERIA2_LINKS}${line}"
                fi
                ;;
            "socks")
                local username=$(echo "$inbound" | jq -r '.users[0].username // ""' 2>/dev/null)
                local password=$(echo "$inbound" | jq -r '.users[0].password // ""' 2>/dev/null)
                local link=""
                
                if [[ -n "$username" && -n "$password" ]]; then
                    link="socks5://${username}:${password}@${SERVER_IP}:${port}#SOCKS5-${SERVER_IP}"
                else
                    link="socks5://${SERVER_IP}:${port}#SOCKS5-${SERVER_IP}"
                fi
                
                if [[ -n "$link" ]]; then
                    local line="[SOCKS5] ${SERVER_IP}:${port}\n${link}\n\n----------------------------------------\n\n"
                    ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}"
                    SOCKS5_LINKS="${SOCKS5_LINKS}${line}"
                fi
                ;;
            "shadowtls")
                local shadowtls_password=$(echo "$inbound" | jq -r '.users[0].password // ""' 2>/dev/null)
                local sni=$(echo "$inbound" | jq -r '.handshake.server // ""' 2>/dev/null)
                
                [[ -z "$sni" ]] && sni="${DEFAULT_SNI}"
                
                if [[ -n "$shadowtls_password" ]]; then
                    # 查找对应的 shadowsocks-in inbound
                    local ss_inbound=$(jq -c ".inbounds[] | select(.tag == \"shadowsocks-in-${port}\")" "${CONFIG_FILE}" 2>/dev/null)
                    local ss_password=$(echo "$ss_inbound" | jq -r '.password // ""' 2>/dev/null)
                    local ss_method=$(echo "$ss_inbound" | jq -r '.method // "2022-blake3-aes-128-gcm"' 2>/dev/null)
                    
                    if [[ -n "$ss_password" ]]; then
                        # 生成 SS link
                        local ss_userinfo=$(echo -n "${ss_method}:${ss_password}" | base64 -w0)
                        local plugin_json="{\"version\":\"3\",\"host\":\"${sni}\",\"password\":\"${shadowtls_password}\"}"
                        local plugin_base64=$(echo -n "$plugin_json" | base64 -w0)
                        local link="ss://${ss_userinfo}@${SERVER_IP}:${port}?shadow-tls=${plugin_base64}#ShadowTLS-${SERVER_IP}"
                        
                        local line="[ShadowTLS v3] ${SERVER_IP}:${port} (SNI: ${sni})\n${link}\n\n----------------------------------------\n\n"
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
                    local link="anytls://${password}@${SERVER_IP}:${port}?security=tls&fp=chrome&insecure=1&sni=${sni}&type=tcp#AnyTLS-${SERVER_IP}"
                    local line="[AnyTLS] ${SERVER_IP}:${port} (SNI: ${sni})\n${link}\n\n----------------------------------------\n\n"
                    ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}"
                    ANYTLS_LINKS="${ANYTLS_LINKS}${line}"
                fi
                ;;
        esac
    done
    
    print_success "链接重新生成完成"
    save_links_to_files
}

# ==================== IP 配置管理 ====================
save_ip_config() {
    mkdir -p "$(dirname "${IP_CONFIG_FILE}")"
    cat > "${IP_CONFIG_FILE}" << EOF
# Sing-box IP 配置
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

# ==================== 中转配置管理 ====================
save_relays_to_file() {
    mkdir -p "$(dirname "${RELAY_FILE}")"
    
    cat > "${RELAY_FILE}" << EOF
# Sing-box 中转配置文件
# 格式: TAG|DESCRIPTION|JSON_CONFIG
EOF
    
    for i in "${!RELAY_TAGS[@]}"; do
        local tag="${RELAY_TAGS[$i]}"
        local desc="${RELAY_DESCS[$i]}"
        local json="${RELAY_JSONS[$i]}"
        # 使用 base64 编码 JSON 避免换行问题
        local json_base64=$(echo "$json" | base64 -w0)
        echo "${tag}|${desc}|${json_base64}" >> "${RELAY_FILE}"
    done
}

load_relays_from_file() {
    RELAY_TAGS=()
    RELAY_JSONS=()
    RELAY_DESCS=()
    
    if [[ ! -f "${RELAY_FILE}" ]]; then
        return 0
    fi
    
    while IFS='|' read -r tag desc json_base64; do
        # 跳过注释和空行
        [[ "$tag" =~ ^#.*$ || -z "$tag" ]] && continue
        
        local json=$(echo "$json_base64" | base64 -d 2>/dev/null)
        if [[ -n "$json" ]]; then
            RELAY_TAGS+=("$tag")
            RELAY_DESCS+=("$desc")
            RELAY_JSONS+=("$json")
        fi
    done < "${RELAY_FILE}"
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

regenerate_all_links() {
    echo ""
    echo -e "${YELLOW}此操作将从配置文件重新生成所有节点链接${NC}"
    echo ""
    
    if [[ ! -f "${CONFIG_FILE}" ]]; then
        print_error "配置文件不存在，无法重新生成链接"
        return 1
    fi
    
    print_info "清理旧链接文件..."
    cleanup_links
    
    print_info "从配置文件重新生成链接..."
    if regenerate_links_from_config; then
        print_success "链接文件已重新生成"
        print_info "可以在 [配置/查看节点] 菜单中查看"
    else
        print_error "重新生成链接失败"
        return 1
    fi
}

# ==================== 网络工具 ====================
get_ip() {
    print_info "获取服务器 IP 地址..."
    
    # 获取 IPv4
    local ipv4=$(curl -s4m5 ifconfig.me 2>/dev/null || curl -s4m5 api.ipify.org 2>/dev/null || curl -s4m5 ip.sb 2>/dev/null)
    
    # 获取 IPv6
    local ipv6=$(curl -s6m5 ifconfig.me 2>/dev/null || curl -s6m5 api6.ipify.org 2>/dev/null || curl -s6m5 ip.sb 2>/dev/null)
    
    # 显示检测到的 IP
    echo ""
    if [[ -n "$ipv4" ]]; then
        echo -e "  ${GREEN}检测到 IPv4:${NC} ${ipv4}"
    fi
    if [[ -n "$ipv6" ]]; then
        echo -e "  ${GREEN}检测到 IPv6:${NC} ${ipv6}"
    fi
    echo ""
    
    # 如果两个都没有，报错退出
    if [[ -z "$ipv4" && -z "$ipv6" ]]; then
        print_error "无法获取服务器 IP 地址"
        exit 1
    fi
    
    # 优先使用 IPv4，没有 IPv4 时使用 IPv6
    if [[ -n "$ipv4" ]]; then
        SERVER_IP="$ipv4"
        SERVER_IPV6="$ipv6"
        if [[ -n "$ipv6" ]]; then
            print_success "检测到双栈网络，默认使用 IPv4: ${SERVER_IP}"
            echo -e "${CYAN}提示: 可在主菜单 [出入站配置] 中切换 IPv6${NC}"
        else
            print_success "使用 IPv4: ${SERVER_IP}"
        fi
    elif [[ -n "$ipv6" ]]; then
        SERVER_IP="$ipv6"
        SERVER_IPV6=""
        INBOUND_IP_MODE="ipv6"
        OUTBOUND_IP_MODE="ipv6"
        print_success "使用 IPv6: ${SERVER_IP}"
        print_info "已自动设置出入站为 IPv6 模式"
    fi
    
    # 保存 IP 配置
    save_ip_config
}

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
            print_error "端口无效，请输入 1-65535 之间的数字"
            continue
        fi
        
        if check_port_in_use "$PORT"; then
            print_warning "端口 ${PORT} 已被占用，请重新输入"
            continue
        fi
        
        break
    done
}

# ==================== Reality 配置 ====================
setup_reality() {
    echo ""
    read_port_with_check 443
    
    echo -e "${YELLOW}请输入伪装域名（建议使用常见HTTPS网站域名）${NC}"
    echo -e "${CYAN}例如: itunes.apple.com, www.bing.com, www.google.com${NC}"
    read -p "伪装域名 [${DEFAULT_SNI}]: " SNI
    SNI=${SNI:-${DEFAULT_SNI}}
    
    print_info "生成配置文件..."
    
    local inbound="{
  \"type\": \"vless\",
  \"tag\": \"vless-in-${PORT}\",
  \"listen\": \"::\",
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
    
    if [[ -z "$INBOUNDS_JSON" ]]; then
        INBOUNDS_JSON="$inbound"
    else
        INBOUNDS_JSON="${INBOUNDS_JSON},${inbound}"
    fi
    
    LINK="vless://${UUID}@${SERVER_IP}:${PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=chrome&pbk=${REALITY_PUBLIC}&sid=${SHORT_ID}&type=tcp#Reality-${SERVER_IP}"
    
    PROTO="Reality"
    EXTRA_INFO="UUID: ${UUID}\nPublic Key: ${REALITY_PUBLIC}\nShort ID: ${SHORT_ID}\nSNI: ${SNI}"
    local line="[Reality] ${SERVER_IP}:${PORT} (SNI: ${SNI})\n${LINK}\n\n----------------------------------------\n\n"
    ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}"
    REALITY_LINKS="${REALITY_LINKS}${line}"
    
    INBOUND_TAGS+=("vless-in-${PORT}")
    INBOUND_PORTS+=("${PORT}")
    INBOUND_PROTOS+=("${PROTO}")
    INBOUND_SNIS+=("${SNI}")
    INBOUND_RELAY_TAGS+=("direct")
    
    print_success "Reality 配置完成 (SNI: ${SNI})"
    save_links_to_files
}

# ==================== Hysteria2 配置 ====================
setup_hysteria2() {
    echo ""
    read_port_with_check 443
    
    echo -e "${YELLOW}请输入伪装域名（建议使用常见HTTPS网站域名）${NC}"
    echo -e "${CYAN}例如: itunes.apple.com, www.bing.com, www.google.com${NC}"
    read -p "伪装域名 [${DEFAULT_SNI}]: " HY2_SNI
    HY2_SNI=${HY2_SNI:-${DEFAULT_SNI}}
    
    print_info "为 ${HY2_SNI} 生成自签证书..."
    gen_cert_for_sni "${HY2_SNI}"
    
    print_info "生成配置文件..."
    
    local inbound="{
  \"type\": \"hysteria2\",
  \"tag\": \"hy2-in-${PORT}\",
  \"listen\": \"::\",
  \"listen_port\": ${PORT},
  \"users\": [{\"password\": \"${HY2_PASSWORD}\"}],
  \"tls\": {
    \"enabled\": true,
    \"alpn\": [\"h3\"],
    \"server_name\": \"${HY2_SNI}\",
    \"certificate_path\": \"${CERT_DIR}/${HY2_SNI}/cert.pem\",
    \"key_path\": \"${CERT_DIR}/${HY2_SNI}/private.key\"
  }
}"
    
    if [[ -z "$INBOUNDS_JSON" ]]; then
        INBOUNDS_JSON="$inbound"
    else
        INBOUNDS_JSON="${INBOUNDS_JSON},${inbound}"
    fi
    
    LINK="hysteria2://${HY2_PASSWORD}@${SERVER_IP}:${PORT}?insecure=1&sni=${HY2_SNI}&h2=#Hysteria2-${SERVER_IP}"
    PROTO="Hysteria2"
    EXTRA_INFO="密码: ${HY2_PASSWORD}\n证书: 自签证书(${HY2_SNI})\nSNI: ${HY2_SNI}"
    local line="[Hysteria2] ${SERVER_IP}:${PORT} (SNI: ${HY2_SNI})\n${LINK}\n\n----------------------------------------\n\n"
    ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}"
    HYSTERIA2_LINKS="${HYSTERIA2_LINKS}${line}"
    
    INBOUND_TAGS+=("hy2-in-${PORT}")
    INBOUND_PORTS+=("${PORT}")
    INBOUND_PROTOS+=("${PROTO}")
    INBOUND_SNIS+=("${HY2_SNI}")
    INBOUND_RELAY_TAGS+=("direct")
    
    print_success "Hysteria2 配置完成 (SNI: ${HY2_SNI})"
    save_links_to_files
}

# ==================== SOCKS5 配置 ====================
setup_socks5() {
    echo ""
    read_port_with_check 1080
    read -p "是否启用认证? [Y/n]: " ENABLE_AUTH
    ENABLE_AUTH=${ENABLE_AUTH:-Y}
    
    print_info "生成配置文件..."
    
    if [[ "$ENABLE_AUTH" =~ ^[Yy]$ ]]; then
        local inbound="{
  \"type\": \"socks\",
  \"tag\": \"socks-in-${PORT}\",
  \"listen\": \"::\",
  \"listen_port\": ${PORT},
  \"users\": [{\"username\": \"${SOCKS_USER}\", \"password\": \"${SOCKS_PASS}\"}]
}"
        LINK="socks5://${SOCKS_USER}:${SOCKS_PASS}@${SERVER_IP}:${PORT}#SOCKS5-${SERVER_IP}"
        EXTRA_INFO="用户名: ${SOCKS_USER}\n密码: ${SOCKS_PASS}"
    else
        local inbound="{
  \"type\": \"socks\",
  \"tag\": \"socks-in-${PORT}\",
  \"listen\": \"::\",
  \"listen_port\": ${PORT}
}"
        LINK="socks5://${SERVER_IP}:${PORT}#SOCKS5-${SERVER_IP}"
        EXTRA_INFO="无认证"
    fi
    
    if [[ -z "$INBOUNDS_JSON" ]]; then
        INBOUNDS_JSON="$inbound"
    else
        INBOUNDS_JSON="${INBOUNDS_JSON},${inbound}"
    fi
    
    PROTO="SOCKS5"
    local line="[SOCKS5] ${SERVER_IP}:${PORT}\n${LINK}\n\n----------------------------------------\n\n"
    ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}"
    SOCKS5_LINKS="${SOCKS5_LINKS}${line}"
    
    INBOUND_TAGS+=("socks-in-${PORT}")
    INBOUND_PORTS+=("${PORT}")
    INBOUND_PROTOS+=("${PROTO}")
    INBOUND_SNIS+=("")
    INBOUND_RELAY_TAGS+=("direct")
    
    print_success "SOCKS5 配置完成"
    save_links_to_files
}

# ==================== ShadowTLS 配置 ====================
setup_shadowtls() {
    echo ""
    read_port_with_check 443
    
    echo -e "${YELLOW}请输入伪装域名（建议使用常见HTTPS网站域名）${NC}"
    echo -e "${CYAN}例如: itunes.apple.com, www.bing.com, www.google.com${NC}"
    read -p "伪装域名 [${DEFAULT_SNI}]: " SHADOWTLS_SNI
    SHADOWTLS_SNI=${SHADOWTLS_SNI:-${DEFAULT_SNI}}
    
    print_info "生成配置文件..."
    print_warning "ShadowTLS 通过伪装真实域名的TLS握手工作"
    
    local inbound="{
  \"type\": \"shadowtls\",
  \"tag\": \"shadowtls-in-${PORT}\",
  \"listen\": \"::\",
  \"listen_port\": ${PORT},
  \"version\": 3,
  \"users\": [{\"password\": \"${SHADOWTLS_PASSWORD}\"}],
  \"handshake\": {
    \"server\": \"${SHADOWTLS_SNI}\",
    \"server_port\": 443
  },
  \"strict_mode\": true,
  \"detour\": \"shadowsocks-in\"
},
{
  \"type\": \"shadowsocks\",
  \"tag\": \"shadowsocks-in-${PORT}\",
  \"listen\": \"127.0.0.1\",
  \"method\": \"2022-blake3-aes-128-gcm\",
  \"password\": \"${SS_PASSWORD}\"
}"
    
    local ss_userinfo=$(echo -n "2022-blake3-aes-128-gcm:${SS_PASSWORD}" | base64 -w0)
    local plugin_json="{\"version\":\"3\",\"host\":\"${SHADOWTLS_SNI}\",\"password\":\"${SHADOWTLS_PASSWORD}\"}"
    local plugin_base64=$(echo -n "$plugin_json" | base64 -w0)
    
    LINK="ss://${ss_userinfo}@${SERVER_IP}:${PORT}?shadow-tls=${plugin_base64}#ShadowTLS-${SERVER_IP}"
    
    if [[ -z "$INBOUNDS_JSON" ]]; then
        INBOUNDS_JSON="$inbound"
    else
        INBOUNDS_JSON="${INBOUNDS_JSON},${inbound}"
    fi
    
    PROTO="ShadowTLS v3"
    local line="[ShadowTLS v3] ${SERVER_IP}:${PORT} (SNI: ${SHADOWTLS_SNI})\n${LINK}\n\n----------------------------------------\n\n"
    ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}"
    SHADOWTLS_LINKS="${SHADOWTLS_LINKS}${line}"
    EXTRA_INFO="Shadowsocks方法: 2022-blake3-aes-128-gcm\nShadowsocks密码: ${SS_PASSWORD}\nShadowTLS密码: ${SHADOWTLS_PASSWORD}\n伪装域名: ${SHADOWTLS_SNI}\n\n说明: 可直接复制链接导入 Shadowrocket、NekoBox、v2rayN 等客户端"
    
    INBOUND_TAGS+=("shadowtls-in-${PORT}")
    INBOUND_PORTS+=("${PORT}")
    INBOUND_PROTOS+=("${PROTO}")
    INBOUND_SNIS+=("${SHADOWTLS_SNI}")
    INBOUND_RELAY_TAGS+=("direct")
    
    print_success "ShadowTLS v3 配置完成 (SNI: ${SHADOWTLS_SNI})"
    save_links_to_files
}

# ==================== HTTPS 配置 ====================
setup_https() {
    echo ""
    read_port_with_check 443
    
    echo -e "${YELLOW}请输入伪装域名（建议使用常见HTTPS网站域名）${NC}"
    echo -e "${CYAN}例如: itunes.apple.com, www.bing.com, www.google.com${NC}"
    read -p "伪装域名 [${DEFAULT_SNI}]: " HTTPS_SNI
    HTTPS_SNI=${HTTPS_SNI:-${DEFAULT_SNI}}
    
    print_info "为 ${HTTPS_SNI} 生成自签证书..."
    gen_cert_for_sni "${HTTPS_SNI}"
    
    print_info "生成配置文件..."
    
    local inbound="{
  \"type\": \"vless\",
  \"tag\": \"vless-tls-in-${PORT}\",
  \"listen\": \"::\",
  \"listen_port\": ${PORT},
  \"users\": [{\"uuid\": \"${UUID}\"}],
  \"tls\": {
    \"enabled\": true,
    \"server_name\": \"${HTTPS_SNI}\",
    \"certificate_path\": \"${CERT_DIR}/${HTTPS_SNI}/cert.pem\",
    \"key_path\": \"${CERT_DIR}/${HTTPS_SNI}/private.key\"
  }
}"
    
    LINK="vless://${UUID}@${SERVER_IP}:${PORT}?encryption=none&security=tls&sni=${HTTPS_SNI}&type=tcp&allowInsecure=1#HTTPS-${SERVER_IP}"
    
    if [[ -z "$INBOUNDS_JSON" ]]; then
        INBOUNDS_JSON="$inbound"
    else
        INBOUNDS_JSON="${INBOUNDS_JSON},${inbound}"
    fi
    
    PROTO="HTTPS"
    EXTRA_INFO="UUID: ${UUID}\n证书: 自签证书(${HTTPS_SNI})\nSNI: ${HTTPS_SNI}"
    local line="[HTTPS] ${SERVER_IP}:${PORT} (SNI: ${HTTPS_SNI})\n${LINK}\n\n----------------------------------------\n\n"
    ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}"
    HTTPS_LINKS="${HTTPS_LINKS}${line}"
    
    INBOUND_TAGS+=("vless-tls-in-${PORT}")
    INBOUND_PORTS+=("${PORT}")
    INBOUND_PROTOS+=("${PROTO}")
    INBOUND_SNIS+=("${HTTPS_SNI}")
    INBOUND_RELAY_TAGS+=("direct")
    
    print_success "HTTPS 配置完成 (SNI: ${HTTPS_SNI})"
    save_links_to_files
}

# ==================== AnyTLS 配置 ====================
setup_anytls() {
    echo ""
    read_port_with_check 443
    
    echo -e "${YELLOW}请输入伪装域名（建议使用常见HTTPS网站域名）${NC}"
    echo -e "${CYAN}例如: itunes.apple.com, www.bing.com, www.google.com${NC}"
    read -p "伪装域名 [${DEFAULT_SNI}]: " ANYTLS_SNI
    ANYTLS_SNI=${ANYTLS_SNI:-${DEFAULT_SNI}}
    
    print_info "为 ${ANYTLS_SNI} 生成自签证书..."
    gen_cert_for_sni "${ANYTLS_SNI}"
    
    print_info "生成配置文件..."
    
    local inbound="{
  \"type\": \"anytls\",
  \"tag\": \"anytls-in-${PORT}\",
  \"listen\": \"::\",
  \"listen_port\": ${PORT},
  \"users\": [{\"password\": \"${ANYTLS_PASSWORD}\"}],
  \"padding_scheme\": [],
  \"tls\": {
    \"enabled\": true,
    \"server_name\": \"${ANYTLS_SNI}\",
    \"certificate_path\": \"${CERT_DIR}/${ANYTLS_SNI}/cert.pem\",
    \"key_path\": \"${CERT_DIR}/${ANYTLS_SNI}/private.key\"
  }
}"
    
    LINK="anytls://${ANYTLS_PASSWORD}@${SERVER_IP}:${PORT}?security=tls&fp=chrome&insecure=1&sni=${ANYTLS_SNI}&type=tcp#AnyTLS-${SERVER_IP}"
    
    if [[ -z "$INBOUNDS_JSON" ]]; then
        INBOUNDS_JSON="$inbound"
    else
        INBOUNDS_JSON="${INBOUNDS_JSON},${inbound}"
    fi
    
    PROTO="AnyTLS"
    EXTRA_INFO="密码: ${ANYTLS_PASSWORD}\n自签证书: ${ANYTLS_SNI}\nSNI: ${ANYTLS_SNI}"
    local line="[AnyTLS] ${SERVER_IP}:${PORT} (SNI: ${ANYTLS_SNI})\n${LINK}\n\n----------------------------------------\n\n"
    ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}"
    ANYTLS_LINKS="${ANYTLS_LINKS}${line}"
    
    INBOUND_TAGS+=("anytls-in-${PORT}")
    INBOUND_PORTS+=("${PORT}")
    INBOUND_PROTOS+=("${PROTO}")
    INBOUND_SNIS+=("${ANYTLS_SNI}")
    INBOUND_RELAY_TAGS+=("direct")
    
    print_success "AnyTLS 配置完成 (SNI: ${ANYTLS_SNI})"
    save_links_to_files
}

# ==================== 中转配置解析 ====================
parse_socks_link() {
    local link="$1"
    
    if [[ "$link" =~ ^socks://([A-Za-z0-9+/=]+) ]]; then
        print_info "检测到 base64 编码的 SOCKS 链接，正在解码..."
        local base64_part="${BASH_REMATCH[1]}"
        local decoded=$(echo "$base64_part" | base64 -d 2>/dev/null)
        
        if [[ -z "$decoded" ]]; then
            print_error "base64 解码失败"
            return 1
        fi
        
        link="socks5://${decoded}"
    fi
    
    local data=$(echo "$link" | sed 's|socks5\?://||')
    data=$(echo "$data" | cut -d'?' -f1 | cut -d'#' -f1)
    
    local relay_json=""
    local relay_desc=""
    
    if [[ "$data" =~ @ ]]; then
        local userpass=$(echo "$data" | cut -d'@' -f1)
        local username=$(echo "$userpass" | cut -d':' -f1)
        local password=$(echo "$userpass" | cut -d':' -f2-)
        local server_port=$(echo "$data" | cut -d'@' -f2)
        local server=$(echo "$server_port" | cut -d':' -f1)
        local port=$(echo "$server_port" | cut -d':' -f2)
        
        # 验证端口是否为数字
        if ! [[ "$port" =~ ^[0-9]+$ ]]; then
            print_error "端口无效: ${port}"
            return 1
        fi
        
        local tag="relay-socks5-${#RELAY_TAGS[@]}"
        relay_json="{
  \"type\": \"socks\",
  \"tag\": \"${tag}\",
  \"server\": \"${server}\",
  \"server_port\": ${port},
  \"version\": \"5\",
  \"username\": \"${username}\",
  \"password\": \"${password}\"
}"
        relay_desc="SOCKS5 ${server}:${port} (认证)"
    else
        local server=$(echo "$data" | cut -d':' -f1)
        local port=$(echo "$data" | cut -d':' -f2)
        
        # 验证端口是否为数字
        if ! [[ "$port" =~ ^[0-9]+$ ]]; then
            print_error "端口无效: ${port}"
            return 1
        fi
        
        local tag="relay-socks5-${#RELAY_TAGS[@]}"
        relay_json="{
  \"type\": \"socks\",
  \"tag\": \"${tag}\",
  \"server\": \"${server}\",
  \"server_port\": ${port},
  \"version\": \"5\"
}"
        relay_desc="SOCKS5 ${server}:${port}"
    fi
    
    # 添加到数组
    RELAY_TAGS+=("relay-socks5-${#RELAY_TAGS[@]}")
    RELAY_JSONS+=("$relay_json")
    RELAY_DESCS+=("$relay_desc")
    
    save_relays_to_file
    print_success "SOCKS5 中转已添加: ${relay_desc}"
}

parse_http_link() {
    local link="$1"
    local protocol=$(echo "$link" | cut -d':' -f1)
    local data=$(echo "$link" | sed 's|https\?://||')
    
    local tls="false"
    [[ "$protocol" == "https" ]] && tls="true"
    
    local relay_json=""
    local relay_desc=""
    local tag="relay-http-${#RELAY_TAGS[@]}"
    
    if [[ "$data" =~ @ ]]; then
        local userpass=$(echo "$data" | cut -d'@' -f1)
        local username=$(echo "$userpass" | cut -d':' -f1)
        local password=$(echo "$userpass" | cut -d':' -f2)
        local server_port=$(echo "$data" | cut -d'@' -f2)
        local server=$(echo "$server_port" | cut -d':' -f1)
        local port=$(echo "$server_port" | cut -d':' -f2 | cut -d'/' -f1 | cut -d'#' -f1 | cut -d'?' -f1)
        
        relay_json="{
  \"type\": \"http\",
  \"tag\": \"${tag}\",
  \"server\": \"${server}\",
  \"server_port\": ${port},
  \"username\": \"${username}\",
  \"password\": \"${password}\",
  \"tls\": {\"enabled\": ${tls}}
}"
        relay_desc="${protocol^^} ${server}:${port} (认证)"
    else
        local server=$(echo "$data" | cut -d':' -f1)
        local port=$(echo "$data" | cut -d':' -f2 | cut -d'/' -f1 | cut -d'#' -f1 | cut -d'?' -f1)
        
        relay_json="{
  \"type\": \"http\",
  \"tag\": \"${tag}\",
  \"server\": \"${server}\",
  \"server_port\": ${port},
  \"tls\": {\"enabled\": ${tls}}
}"
        relay_desc="${protocol^^} ${server}:${port}"
    fi
    
    RELAY_TAGS+=("$tag")
    RELAY_JSONS+=("$relay_json")
    RELAY_DESCS+=("$relay_desc")
    
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
        if [[ -z "$decoded" ]]; then
            print_error "Shadowsocks 链接解码失败"
            return 1
        fi
        
        local method=$(echo "$decoded" | cut -d':' -f1)
        local password=$(echo "$decoded" | cut -d':' -f2-)
        
        local tag="relay-ss-${#RELAY_TAGS[@]}"
        local relay_json="{
  \"type\": \"shadowsocks\",
  \"tag\": \"${tag}\",
  \"server\": \"${server}\",
  \"server_port\": ${port},
  \"method\": \"${method}\",
  \"password\": \"${password}\"
}"
        local relay_desc="Shadowsocks ${server}:${port}"
        
        RELAY_TAGS+=("$tag")
        RELAY_JSONS+=("$relay_json")
        RELAY_DESCS+=("$relay_desc")
        
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
    
    if [[ -z "$json" ]]; then
        print_error "VMess 链接解码失败"
        return 1
    fi
    
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
    local relay_json="{
  \"type\": \"vmess\",
  \"tag\": \"${tag}\",
  \"server\": \"${server}\",
  \"server_port\": ${port},
  \"uuid\": \"${uuid}\",
  \"alter_id\": ${alterId},
  \"security\": \"${security}\"
}"
    local relay_desc="VMess ${server}:${port}"
    
    RELAY_TAGS+=("$tag")
    RELAY_JSONS+=("$relay_json")
    RELAY_DESCS+=("$relay_desc")
    
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
    
    if [[ -n "$params" ]]; then
        [[ "$params" =~ security=([^&]+) ]] && security="${BASH_REMATCH[1]}"
        [[ "$params" =~ sni=([^&]+) ]] && sni="${BASH_REMATCH[1]}"
        [[ "$params" =~ flow=([^&]+) ]] && flow="${BASH_REMATCH[1]}"
    fi
    
    local tls_config=""
    if [[ "$security" == "tls" || "$security" == "reality" ]]; then
        tls_config=",
  \"tls\": {
    \"enabled\": true,
    \"server_name\": \"${sni}\"
  }"
    fi
    
    local flow_config=""
    [[ -n "$flow" ]] && flow_config=",
  \"flow\": \"${flow}\""
    
    local tag="relay-vless-${#RELAY_TAGS[@]}"
    local relay_json="{
  \"type\": \"vless\",
  \"tag\": \"${tag}\",
  \"server\": \"${server}\",
  \"server_port\": ${port},
  \"uuid\": \"${uuid}\"${flow_config}${tls_config}
}"
    local relay_desc="VLESS ${server}:${port}"
    
    RELAY_TAGS+=("$tag")
    RELAY_JSONS+=("$relay_json")
    RELAY_DESCS+=("$relay_desc")
    
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
    local relay_json="{
  \"type\": \"trojan\",
  \"tag\": \"${tag}\",
  \"server\": \"${server}\",
  \"server_port\": ${port},
  \"password\": \"${password}\",
  \"tls\": {
    \"enabled\": true,
    \"server_name\": \"${sni}\"
  }
}"
    local relay_desc="Trojan ${server}:${port}"
    
    RELAY_TAGS+=("$tag")
    RELAY_JSONS+=("$relay_json")
    RELAY_DESCS+=("$relay_desc")
    
    save_relays_to_file
    print_success "Trojan 中转已添加: ${relay_desc}"
}

# ==================== 中转配置菜单 ====================
setup_relay() {
    # 加载中转配置
    load_relays_from_file
    
    while true; do
        echo ""
        echo -e "${CYAN}╔═══════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║              ${GREEN}中转配置菜单${CYAN}                  ║${NC}"
        echo -e "${CYAN}╚═══════════════════════════════════════════════════════╝${NC}"
        echo ""
        
        # 显示当前中转列表
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
                echo -e "${CYAN}╔═══════════════════════════════════════════════════════╗${NC}"
                echo -e "${CYAN}║          ${GREEN}支持的中转协议格式${CYAN}              ║${NC}"
                echo -e "${CYAN}╚═══════════════════════════════════════════════════════╝${NC}"
                echo ""
                echo -e "${GREEN}1. SOCKS5 代理${NC}"
                echo -e "   ${YELLOW}格式:${NC} socks5://[用户名:密码@]服务器:端口"
                echo -e "   ${CYAN}示例:${NC}"
                echo -e "     socks5://user:pass@1.2.3.4:1080"
                echo -e "     socks5://1.2.3.4:1080 ${YELLOW}(无认证)${NC}"
                echo ""
                echo -e "${GREEN}2. HTTP/HTTPS 代理${NC}"
                echo -e "   ${YELLOW}格式:${NC} http(s)://[用户名:密码@]服务器:端口"
                echo -e "   ${CYAN}示例:${NC}"
                echo -e "     http://user:pass@1.2.3.4:8080"
                echo -e "     https://1.2.3.4:443 ${YELLOW}(无认证)${NC}"
                echo ""
                echo -e "${GREEN}3. Shadowsocks${NC}"
                echo -e "   ${YELLOW}格式:${NC} ss://base64(加密方式:密码)@服务器:端口"
                echo -e "   ${CYAN}示例:${NC}"
                echo -e "     ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388"
                echo ""
                echo -e "${GREEN}4. VMess${NC}"
                echo -e "   ${YELLOW}格式:${NC} vmess://base64(JSON配置)"
                echo -e "   ${CYAN}说明:${NC} 标准 V2Ray 分享链接"
                echo ""
                echo -e "${GREEN}5. VLESS${NC}"
                echo -e "   ${YELLOW}格式:${NC} vless://UUID@服务器:端口?参数#备注"
                echo -e "   ${CYAN}示例:${NC}"
                echo -e "     vless://uuid@1.2.3.4:443?security=tls&sni=example.com"
                echo -e "   ${YELLOW}支持参数:${NC} security, sni, flow, type 等"
                echo ""
                echo -e "${GREEN}6. Trojan${NC}"
                echo -e "   ${YELLOW}格式:${NC} trojan://密码@服务器:端口?参数#备注"
                echo -e "   ${CYAN}示例:${NC}"
                echo -e "     trojan://password@1.2.3.4:443?sni=example.com"
                echo -e "   ${YELLOW}支持参数:${NC} sni, type, security 等"
                echo ""
                echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                echo -e "${YELLOW}提示:${NC} 直接粘贴完整的节点分享链接即可，脚本会自动识别协议类型"
                echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                echo ""
                read -p "粘贴中转链接: " RELAY_LINK
                
                if [[ -z "$RELAY_LINK" ]]; then
                    print_warning "未提供链接，中转配置保持不变"
                else
                    if [[ "$RELAY_LINK" =~ ^socks ]]; then
                        parse_socks_link "$RELAY_LINK"
                    elif [[ "$RELAY_LINK" =~ ^https? ]]; then
                        parse_http_link "$RELAY_LINK"
                    elif [[ "$RELAY_LINK" =~ ^ss:// ]]; then
                        parse_ss_link "$RELAY_LINK"
                    elif [[ "$RELAY_LINK" =~ ^vmess:// ]]; then
                        parse_vmess_link "$RELAY_LINK"
                    elif [[ "$RELAY_LINK" =~ ^vless:// ]]; then
                        parse_vless_link "$RELAY_LINK"
                    elif [[ "$RELAY_LINK" =~ ^trojan:// ]]; then
                        parse_trojan_link "$RELAY_LINK"
                    else
                        print_error "不支持的链接格式"
                    fi
                fi
                ;;
            2)
                if [[ ${#INBOUND_TAGS[@]} -eq 0 ]]; then
                    print_warning "当前尚未添加任何节点，请先添加节点"
                    continue
                fi
                
                if [[ ${#RELAY_TAGS[@]} -eq 0 ]]; then
                    print_warning "尚未添加任何中转链接，请先选择选项 [1] 添加中转"
                    continue
                fi
                
                # 选择节点
                echo ""
                echo -e "${CYAN}选择要配置中转的节点:${NC}"
                for i in "${!INBOUND_TAGS[@]}"; do
                    idx=$((i+1))
                    local relay_status="${INBOUND_RELAY_TAGS[$i]}"
                    local relay_desc="直连"
                    
                    if [[ "$relay_status" != "direct" ]]; then
                        # 查找中转描述
                        for j in "${!RELAY_TAGS[@]}"; do
                            if [[ "${RELAY_TAGS[$j]}" == "$relay_status" ]]; then
                                relay_desc="中转: ${RELAY_DESCS[$j]}"
                                break
                            fi
                        done
                    fi
                    
                    echo -e "  ${GREEN}[${idx}]${NC} ${INBOUND_PROTOS[$i]}:${INBOUND_PORTS[$i]} → ${YELLOW}${relay_desc}${NC}"
                done
                echo ""
                read -p "请输入节点序号 (输入 0 返回): " node_idx
                
                if [[ "$node_idx" == "0" ]]; then
                    continue
                fi
                
                if ! [[ "$node_idx" =~ ^[0-9]+$ ]] || (( node_idx < 1 || node_idx > ${#INBOUND_TAGS[@]} )); then
                    print_error "无效的节点序号"
                    continue
                fi
                
                local n=$((node_idx-1))
                
                # 选择中转
                echo ""
                echo -e "${CYAN}选择中转方式:${NC}"
                echo -e "  ${GREEN}[0]${NC} 直连 (不使用中转)"
                for i in "${!RELAY_TAGS[@]}"; do
                    idx=$((i+1))
                    echo -e "  ${GREEN}[${idx}]${NC} ${RELAY_DESCS[$i]}"
                done
                echo ""
                read -p "请选择: " relay_idx
                
                if [[ "$relay_idx" == "0" ]]; then
                    INBOUND_RELAY_TAGS[$n]="direct"
                    print_success "节点已设置为直连"
                elif [[ "$relay_idx" =~ ^[0-9]+$ ]] && (( relay_idx >= 1 && relay_idx <= ${#RELAY_TAGS[@]} )); then
                    local r=$((relay_idx-1))
                    INBOUND_RELAY_TAGS[$n]="${RELAY_TAGS[$r]}"
                    print_success "节点已设置为: ${RELAY_DESCS[$r]}"
                else
                    print_error "无效选择"
                    continue
                fi
                
                # 应用配置
                if [[ -n "$INBOUNDS_JSON" ]]; then
                    generate_config && start_svc
                fi
                ;;
            3)
                if [[ ${#RELAY_TAGS[@]} -eq 0 ]]; then
                    print_warning "当前没有中转链接"
                    continue
                fi
                
                echo ""
                echo -e "${CYAN}删除中转链接:${NC}"
                echo -e "  ${GREEN}[0]${NC} 删除全部中转"
                for i in "${!RELAY_TAGS[@]}"; do
                    idx=$((i+1))
                    echo -e "  ${GREEN}[${idx}]${NC} ${RELAY_DESCS[$i]}"
                done
                echo ""
                read -p "请选择要删除的中转 (输入 0 删除全部, 输入 -1 取消): " del_idx
                
                if [[ "$del_idx" == "-1" ]]; then
                    continue
                elif [[ "$del_idx" == "0" ]]; then
                    echo ""
                    read -p "确认删除全部中转? (y/N): " confirm
                    if [[ "$confirm" =~ ^[Yy]$ ]]; then
                        RELAY_TAGS=()
                        RELAY_JSONS=()
                        RELAY_DESCS=()
                        rm -f "${RELAY_FILE}"
                        
                        # 将所有节点设置为直连
                        for i in "${!INBOUND_RELAY_TAGS[@]}"; do
                            INBOUND_RELAY_TAGS[$i]="direct"
                        done
                        
                        print_success "已删除全部中转配置"
                        
                        # 重新生成配置
                        if [[ -n "$INBOUNDS_JSON" ]]; then
                            generate_config && start_svc
                        fi
                    fi
                elif [[ "$del_idx" =~ ^[0-9]+$ ]] && (( del_idx >= 1 && del_idx <= ${#RELAY_TAGS[@]} )); then
                    local d=$((del_idx-1))
                    local del_tag="${RELAY_TAGS[$d]}"
                    local del_desc="${RELAY_DESCS[$d]}"
                    
                    echo ""
                    read -p "确认删除中转: ${del_desc}? (y/N): " confirm
                    if [[ "$confirm" =~ ^[Yy]$ ]]; then
                        # 删除中转
                        unset RELAY_TAGS[$d]
                        unset RELAY_JSONS[$d]
                        unset RELAY_DESCS[$d]
                        
                        # 重建数组
                        RELAY_TAGS=("${RELAY_TAGS[@]}")
                        RELAY_JSONS=("${RELAY_JSONS[@]}")
                        RELAY_DESCS=("${RELAY_DESCS[@]}")
                        
                        # 将使用该中转的节点改为直连
                        for i in "${!INBOUND_RELAY_TAGS[@]}"; do
                            if [[ "${INBOUND_RELAY_TAGS[$i]}" == "$del_tag" ]]; then
                                INBOUND_RELAY_TAGS[$i]="direct"
                            fi
                        done
                        
                        save_relays_to_file
                        print_success "已删除中转: ${del_desc}"
                        
                        # 重新生成配置
                        if [[ -n "$INBOUNDS_JSON" ]]; then
                            generate_config && start_svc
                        fi
                    fi
                else
                    print_error "无效选择"
                fi
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

# ==================== 出入站 IP 配置菜单 ====================
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
        echo -e "${CYAN}说明:${NC}"
        echo -e "  ${YELLOW}入站${NC}: 控制节点监听的 IP 版本（客户端连接到哪个 IP）"
        echo -e "  ${YELLOW}出站${NC}: 控制服务器对外连接的 IP 版本（访问网站用哪个 IP）"
        echo ""
        echo -e "  ${GREEN}[1]${NC} 设置入站为 IPv4"
        echo -e "  ${GREEN}[2]${NC} 设置入站为 IPv6"
        echo -e "  ${GREEN}[3]${NC} 设置出站为 IPv4"
        echo -e "  ${GREEN}[4]${NC} 设置出站为 IPv6"
        echo -e "  ${GREEN}[5]${NC} 手动修改 IPv4 地址"
        echo -e "  ${GREEN}[6]${NC} 手动修改 IPv6 地址"
        echo -e "  ${GREEN}[0]${NC} 返回主菜单"
        echo ""
        read -p "请选择 [0-6]: " ip_choice
        
        case $ip_choice in
            1)
                INBOUND_IP_MODE="ipv4"
                save_ip_config
                print_success "入站已设置为 IPv4"
                echo -e "${YELLOW}提示: 需要重新生成配置才能生效${NC}"
                read -p "是否立即重新生成配置? (y/N): " regen
                if [[ "$regen" =~ ^[Yy]$ ]] && [[ -n "$INBOUNDS_JSON" ]]; then
                    generate_config && start_svc
                fi
                ;;
            2)
                if [[ -z "$SERVER_IPV6" ]]; then
                    print_error "未检测到 IPv6 地址，请先手动设置"
                    read -p "按回车继续..." _
                    continue
                fi
                INBOUND_IP_MODE="ipv6"
                save_ip_config
                print_success "入站已设置为 IPv6"
                echo -e "${YELLOW}提示: 需要重新生成配置才能生效${NC}"
                read -p "是否立即重新生成配置? (y/N): " regen
                if [[ "$regen" =~ ^[Yy]$ ]] && [[ -n "$INBOUNDS_JSON" ]]; then
                    generate_config && start_svc
                fi
                ;;
            3)
                OUTBOUND_IP_MODE="ipv4"
                save_ip_config
                print_success "出站已设置为 IPv4"
                echo -e "${YELLOW}提示: 需要重新生成配置才能生效${NC}"
                read -p "是否立即重新生成配置? (y/N): " regen
                if [[ "$regen" =~ ^[Yy]$ ]] && [[ -n "$INBOUNDS_JSON" ]]; then
                    generate_config && start_svc
                fi
                ;;
            4)
                if [[ -z "$SERVER_IPV6" ]]; then
                    print_error "未检测到 IPv6 地址，请先手动设置"
                    read -p "按回车继续..." _
                    continue
                fi
                OUTBOUND_IP_MODE="ipv6"
                save_ip_config
                print_success "出站已设置为 IPv6"
                echo -e "${YELLOW}提示: 需要重新生成配置才能生效${NC}"
                read -p "是否立即重新生成配置? (y/N): " regen
                if [[ "$regen" =~ ^[Yy]$ ]] && [[ -n "$INBOUNDS_JSON" ]]; then
                    generate_config && start_svc
                fi
                ;;
            5)
                read -p "请输入 IPv4 地址: " new_ipv4
                if [[ -n "$new_ipv4" ]]; then
                    SERVER_IP="$new_ipv4"
                    save_ip_config
                    print_success "IPv4 地址已更新: ${SERVER_IP}"
                    echo -e "${YELLOW}提示: 需要重新生成链接文件${NC}"
                fi
                ;;
            6)
                read -p "请输入 IPv6 地址: " new_ipv6
                if [[ -n "$new_ipv6" ]]; then
                    SERVER_IPV6="$new_ipv6"
                    save_ip_config
                    print_success "IPv6 地址已更新: ${SERVER_IPV6}"
                    echo -e "${YELLOW}提示: 需要重新生成链接文件${NC}"
                fi
                ;;
            0)
                break
                ;;
            *)
                print_error "无效选项"
                ;;
        esac
        
        [[ "$ip_choice" != "0" ]] && read -p "按回车继续..." _
    done
}

clear_relay() {
    echo ""
    read -p "确认删除全部中转配置并恢复直连? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        print_info "取消操作"
        return 0
    fi
    
    # 清空中转数组
    RELAY_TAGS=()
    RELAY_JSONS=()
    RELAY_DESCS=()
    rm -f "${RELAY_FILE}"
    
    # 将所有节点设置为直连
    if [[ ${#INBOUND_RELAY_TAGS[@]} -gt 0 ]]; then
        for i in "${!INBOUND_RELAY_TAGS[@]}"; do
            INBOUND_RELAY_TAGS[$i]="direct"
        done
    fi
    
    print_success "已删除全部中转配置，当前为直连模式"
    
    # 重新生成配置
    if [[ -n "$INBOUNDS_JSON" ]]; then
        generate_config && start_svc
    fi
}

# ==================== 节点删除功能 ====================
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
    
    # 从配置文件中删除节点
    if [[ -f "${CONFIG_FILE}" ]] && command -v jq &>/dev/null; then
        print_info "从配置文件删除节点..."
        
        # 使用 jq 过滤掉要删除的节点
        local temp_config=$(mktemp)
        
        # 如果是 ShadowTLS，需要同时删除对应的 shadowsocks-in 节点
        if [[ "$proto" == "ShadowTLS v3" ]]; then
            local ss_tag="shadowsocks-in-${port}"
            jq --arg tag "$tag" --arg ss_tag "$ss_tag" '.inbounds |= map(select(.tag != $tag and .tag != $ss_tag))' "${CONFIG_FILE}" > "$temp_config"
        else
            jq --arg tag "$tag" '.inbounds |= map(select(.tag != $tag))' "${CONFIG_FILE}" > "$temp_config"
        fi
        
        mv "$temp_config" "${CONFIG_FILE}"
        
        # 从数组中删除
        unset INBOUND_TAGS[$index]
        unset INBOUND_PORTS[$index]
        unset INBOUND_PROTOS[$index]
        unset INBOUND_SNIS[$index]
        unset INBOUND_RELAY_TAGS[$index]
        
        # 重建数组（移除空元素）
        INBOUND_TAGS=("${INBOUND_TAGS[@]}")
        INBOUND_PORTS=("${INBOUND_PORTS[@]}")
        INBOUND_PROTOS=("${INBOUND_PROTOS[@]}")
        INBOUND_SNIS=("${INBOUND_SNIS[@]}")
        INBOUND_RELAY_TAGS=("${INBOUND_RELAY_TAGS[@]}")
        
        # 重新加载配置
        load_inbounds_from_config
        
        # 重新生成链接文件
        print_info "重新生成链接文件..."
        regenerate_links_from_config
        
        # 重启服务
        print_info "重启服务..."
        systemctl restart sing-box
        sleep 2
        
        if systemctl is-active --quiet sing-box; then
            print_success "节点已删除: ${proto}:${port} (SNI: ${sni})"
            print_success "服务已重启"
        else
            print_error "服务重启失败"
            journalctl -u sing-box -n 10 --no-pager
        fi
    else
        print_error "无法删除节点：配置文件不存在或 jq 未安装"
        return 1
    fi
}

delete_all_nodes() {
    echo ""
    echo -e "${RED}⚠️  警告: 此操作将删除所有节点配置！${NC}"
    echo -e "${YELLOW}当前共有 ${#INBOUND_TAGS[@]} 个节点${NC}"
    echo ""
    echo -e "删除后:"
    echo -e "  1. 所有节点配置将被清空"
    echo -e "  2. 配置文件将只保留基础结构"
    echo -e "  3. 需要重新添加节点"
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
    
    cat > ${CONFIG_FILE} << 'EOFCONFIG'
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "final": "direct"
  }
}
EOFCONFIG
    
    print_info "停止 sing-box 服务..."
    systemctl stop sing-box 2>/dev/null || true
    
    cleanup_links
    
    print_success "所有节点已删除，配置文件已重置"
    
    read -p "是否启动空配置的 sing-box 服务? (y/N): " restart_service
    restart_service=${restart_service:-N}
    
    if [[ "$restart_service" =~ ^[Yy]$ ]]; then
        systemctl start sing-box
        sleep 2
        if systemctl is-active --quiet sing-box; then
            print_success "服务已启动 (空配置)"
        else
            print_error "服务启动失败"
        fi
    fi
}

# ==================== 配置生成 ====================
generate_config() {
    print_info "生成最终配置文件..."
    
    if [[ -z "$INBOUNDS_JSON" ]]; then
        print_error "未找到任何入站节点，请先添加节点"
        return 1
    fi
    
    # 加载中转配置
    load_relays_from_file
    
    # 构建 outbounds 数组
    local outbounds_array=()
    
    # 添加所有中转 outbound
    for relay_json in "${RELAY_JSONS[@]}"; do
        outbounds_array+=("$relay_json")
    done
    
    # 添加 direct outbound
    local direct_outbound='{"type": "direct", "tag": "direct"}'
    outbounds_array+=("$direct_outbound")
    
    # 组合 outbounds
    local outbounds="["
    for i in "${!outbounds_array[@]}"; do
        [[ $i -gt 0 ]] && outbounds+=", "
        outbounds+="${outbounds_array[$i]}"
    done
    outbounds+="]"
    
    # 构建路由规则
    local route_rules=()
    local has_relay=0
    
    # 为每个使用中转的节点创建路由规则
    for i in "${!INBOUND_TAGS[@]}"; do
        local relay_tag="${INBOUND_RELAY_TAGS[$i]}"
        if [[ "$relay_tag" != "direct" ]]; then
            route_rules+=("{\"inbound\":[\"${INBOUND_TAGS[$i]}\"],\"outbound\":\"${relay_tag}\"}")
            has_relay=1
        fi
    done
    
    # 组合路由配置
    local route_json
    if [[ $has_relay -eq 1 ]]; then
        route_json="{\"rules\":["
        for i in "${!route_rules[@]}"; do
            [[ $i -gt 0 ]] && route_json+=","
            route_json+="${route_rules[$i]}"
        done
        route_json+="],\"final\":\"direct\"}"
    else
        route_json='{"final":"direct"}'
    fi
    
    # 构建 DNS 配置（根据出站 IP 模式）
    local dns_json
    if [[ "$OUTBOUND_IP_MODE" == "ipv6" ]]; then
        dns_json='{
    "servers": [
      {
        "tag": "dns-direct",
        "address": "local",
        "detour": "direct"
      },
      {
        "tag": "dns-remote",
        "address": "tls://8.8.8.8",
        "address_resolver": "dns-direct",
        "detour": "direct"
      }
    ],
    "rules": [],
    "strategy": "prefer_ipv6",
    "independent_cache": true
  }'
    else
        dns_json='{
    "servers": [
      {
        "tag": "dns-direct",
        "address": "local",
        "detour": "direct"
      },
      {
        "tag": "dns-remote",
        "address": "tls://8.8.8.8",
        "address_resolver": "dns-direct",
        "detour": "direct"
      }
    ],
    "rules": [],
    "strategy": "prefer_ipv4",
    "independent_cache": true
  }'
    fi
    
    cat > ${CONFIG_FILE} << EOFCONFIG
{
  "log": {
    "level": "info",
    "timestamp": true
  },
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
    
    if ! ${INSTALL_DIR}/sing-box check -c ${CONFIG_FILE} 2>&1; then
        print_error "配置验证失败"
        cat ${CONFIG_FILE}
        exit 1
    fi
    
    print_info "启动 sing-box 服务..."
    systemctl restart sing-box
    sleep 2
    
    if systemctl is-active --quiet sing-box; then
        print_success "服务启动成功"
    else
        print_error "服务启动失败，查看日志："
        journalctl -u sing-box -n 10 --no-pager
        exit 1
    fi
}

# ==================== 结果显示 ====================
show_result() {
    clear
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                                                       ║${NC}"
    echo -e "${CYAN}║               ${GREEN}🎉 配置完成！${CYAN}            ║${NC}"
    echo -e "${CYAN}║                                                       ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}服务器信息:${NC}"
    echo -e "  协议: ${GREEN}${PROTO}${NC}"
    echo -e "  IP: ${GREEN}${SERVER_IP}${NC}"
    echo -e "  端口: ${GREEN}${PORT}${NC}"
    echo -e "  出站: ${GREEN}${OUTBOUND_TAG}${NC}"
    echo ""
    
    if [[ -n "$EXTRA_INFO" ]]; then
        echo -e "${YELLOW}协议详情:${NC}"
        echo -e "$EXTRA_INFO" | sed 's/^/  /'
        echo ""
    fi
    
    echo -e "${CYAN}───────────────────────────────────────────────────────${NC}"
    echo -e "${GREEN}📋 节点链接:${NC}"
    echo -e "${CYAN}───────────────────────────────────────────────────────${NC}"
    echo ""
    echo -e "${YELLOW}${LINK}${NC}"
    echo ""
    echo -e "${CYAN}───────────────────────────────────────────────────────${NC}"
}

# ==================== 协议选择菜单 ====================
show_menu() {
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
    
    case $choice in
        1)
            setup_reality
            ;;
        2)
            setup_hysteria2
            ;;
        3)
            setup_socks5
            ;;
        4)
            setup_shadowtls
            ;;
        5)
            setup_https
            ;;
        6)
            setup_anytls
            ;;
        *)
            print_error "无效选项"
            return 1
            ;;
    esac
    
    if [[ -n "$INBOUNDS_JSON" ]]; then
        generate_config || return 1
        start_svc || return 1
        show_result
    fi
}

# ==================== 主菜单 ====================
show_main_menu() {
    show_banner
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║          ${GREEN}Sing-Box 一键管理面板${CYAN}          ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # 显示出入站配置
    echo -e "${YELLOW}当前出入站配置:${NC}"
    if [[ -n "$SERVER_IP" ]]; then
        echo -e "  IPv4 地址: ${GREEN}${SERVER_IP}${NC}"
    fi
    if [[ -n "$SERVER_IPV6" ]]; then
        echo -e "  IPv6 地址: ${GREEN}${SERVER_IPV6}${NC}"
    fi
    echo -e "  ${CYAN}└─${NC} 入站模式: ${GREEN}${INBOUND_IP_MODE}${NC}     出站模式: ${GREEN}${OUTBOUND_IP_MODE}${NC}"
    echo ""
    
    # 统计中转使用情况
    local relay_count=0
    local direct_count=0
    
    # 统计每个中转被使用的次数
    declare -A relay_usage
    
    for relay_tag in "${INBOUND_RELAY_TAGS[@]}"; do
        if [[ "$relay_tag" == "direct" ]]; then
            ((direct_count++))
        else
            ((relay_count++))
            if [[ -n "${relay_usage[$relay_tag]}" ]]; then
                relay_usage[$relay_tag]=$((${relay_usage[$relay_tag]} + 1))
            else
                relay_usage[$relay_tag]=1
            fi
        fi
    done
    
    # 显示出站状态
    local outbound_desc
    if [[ $relay_count -gt 0 ]]; then
        # 统计使用的中转协议类型
        declare -A relay_proto_count
        for relay_tag in "${!relay_usage[@]}"; do
            # 从中转描述中提取协议类型
            for i in "${!RELAY_TAGS[@]}"; do
                if [[ "${RELAY_TAGS[$i]}" == "$relay_tag" ]]; then
                    local proto=$(echo "${RELAY_DESCS[$i]}" | cut -d' ' -f1)
                    if [[ -n "${relay_proto_count[$proto]}" ]]; then
                        relay_proto_count[$proto]=$((${relay_proto_count[$proto]} + ${relay_usage[$relay_tag]}))
                    else
                        relay_proto_count[$proto]=${relay_usage[$relay_tag]}
                    fi
                    break
                fi
            done
        done
        
        # 构建出站描述
        local proto_list=""
        for proto in "${!relay_proto_count[@]}"; do
            [[ -n "$proto_list" ]] && proto_list+=", "
            proto_list+="${proto}:${relay_proto_count[$proto]}"
        done
        
        outbound_desc="中转 (直连:${direct_count} 中转:${relay_count} [${proto_list}])"
    else
        outbound_desc="直连"
    fi
    
    echo -e "  ${YELLOW}当前出站: ${GREEN}${outbound_desc}${NC}"
    
    # 显示中转列表详情
    if [[ ${#RELAY_TAGS[@]} -gt 0 ]]; then
        # 统计各协议中转数量
        declare -A relay_type_count
        for desc in "${RELAY_DESCS[@]}"; do
            local proto=$(echo "$desc" | cut -d' ' -f1)
            if [[ -n "${relay_type_count[$proto]}" ]]; then
                relay_type_count[$proto]=$((${relay_type_count[$proto]} + 1))
            else
                relay_type_count[$proto]=1
            fi
        done
        
        # 构建中转列表描述
        local relay_list=""
        for proto in "${!relay_type_count[@]}"; do
            [[ -n "$relay_list" ]] && relay_list+=", "
            relay_list+="${proto}:${relay_type_count[$proto]}"
        done
        
        echo -e "  ${YELLOW}中转列表: ${GREEN}${#RELAY_TAGS[@]} 个 [${relay_list}]${NC}"
        
        # 显示哪些节点在使用中转
        if [[ $relay_count -gt 0 ]]; then
            local relay_nodes=""
            for i in "${!INBOUND_RELAY_TAGS[@]}"; do
                if [[ "${INBOUND_RELAY_TAGS[$i]}" != "direct" ]]; then
                    [[ -n "$relay_nodes" ]] && relay_nodes+=", "
                    relay_nodes+="${INBOUND_PROTOS[$i]}:${INBOUND_PORTS[$i]}"
                fi
            done
            echo -e "  ${CYAN}  └─ 使用中转: ${relay_nodes}${NC}"
        fi
    fi
    
    # 统计各协议节点数
    local reality_count=0
    local hysteria2_count=0
    local socks5_count=0
    local shadowtls_count=0
    local https_count=0
    local anytls_count=0
    
    for proto in "${INBOUND_PROTOS[@]}"; do
        case "$proto" in
            "Reality") ((reality_count++)) ;;
            "Hysteria2") ((hysteria2_count++)) ;;
            "SOCKS5") ((socks5_count++)) ;;
            "ShadowTLS v3") ((shadowtls_count++)) ;;
            "HTTPS") ((https_count++)) ;;
            "AnyTLS") ((anytls_count++)) ;;
        esac
    done
    
    echo -e "  ${YELLOW}当前节点数: ${GREEN}${#INBOUND_TAGS[@]}${NC}"
    
    if [[ ${#INBOUND_TAGS[@]} -gt 0 ]]; then
        local node_details=""
        [[ $reality_count -gt 0 ]] && node_details="${node_details}Reality:${reality_count} "
        [[ $hysteria2_count -gt 0 ]] && node_details="${node_details}Hysteria2:${hysteria2_count} "
        [[ $socks5_count -gt 0 ]] && node_details="${node_details}SOCKS5:${socks5_count} "
        [[ $shadowtls_count -gt 0 ]] && node_details="${node_details}ShadowTLS:${shadowtls_count} "
        [[ $https_count -gt 0 ]] && node_details="${node_details}HTTPS:${https_count} "
        [[ $anytls_count -gt 0 ]] && node_details="${node_details}AnyTLS:${anytls_count} "
        
        if [[ -n "$node_details" ]]; then
            echo -e "  ${CYAN}  └─ ${node_details}${NC}"
        fi
    fi
    echo ""
    echo -e "  ${GREEN}[1]${NC} 添加/继续添加节点"
    echo ""
    echo -e "  ${GREEN}[2]${NC} 中转配置 (添加/配置/删除)"
    echo ""
    echo -e "  ${GREEN}[3]${NC} 出入站配置 (IPv4/IPv6)"
    echo ""
    echo -e "  ${GREEN}[4]${NC} 配置 / 查看节点"
    echo ""
    echo -e "  ${GREEN}[5]${NC} 重新生成链接文件"
    echo ""
    echo -e "  ${GREEN}[6]${NC} 一键删除脚本并退出"
    echo ""
    echo -e "  ${GREEN}[0]${NC} 退出脚本"
    echo ""
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
                    echo ""
                    echo -e "${CYAN}提示: 可直接复制上方 ss:// 链接导入客户端 (Shadowrocket/NekoBox/v2rayN)${NC}"
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

# ==================== 完整卸载 ====================
delete_self() {
    echo -e "${YELLOW}此操作将卸载 sing-box、删除所有节点配置、证书、快捷命令 sb 和当前脚本，且无法恢复。${NC}"
    echo -e "${RED}警告：这将永久删除所有数据！${NC}"
    echo ""
    echo -e "${CYAN}注意:${NC}"
    echo -e "  1. 此操作与'删除全部节点'不同"
    echo -e "  2. '删除全部节点'只会清空配置，保留服务和脚本"
    echo -e "  3. 此操作会完全卸载 sing-box 和脚本"
    echo ""
    
    read -p "确认完全卸载？(y/N): " CONFIRM_DELETE
    CONFIRM_DELETE=${CONFIRM_DELETE:-N}
    
    if [[ ! "$CONFIRM_DELETE" =~ ^[Yy]$ ]]; then
        print_info "已取消卸载操作"
        return 0
    fi
    
    print_info "停止 sing-box 服务..."
    if systemctl list-unit-files | grep -q '^sing-box\.service'; then
        systemctl stop sing-box 2>/dev/null || true
        systemctl disable sing-box 2>/dev/null || true
    fi
    
    if [[ -f /etc/systemd/system/sing-box.service ]]; then
        print_info "删除 sing-box systemd 服务文件..."
        rm -f /etc/systemd/system/sing-box.service 2>/dev/null || true
        systemctl daemon-reload 2>/dev/null || true
    fi
    
    if [[ -d /run/sing-box ]]; then
        print_info "删除 sing-box 运行时文件..."
        rm -rf /run/sing-box 2>/dev/null || true
    fi
    
    if command -v sing-box &>/dev/null; then
        local sb_bin=$(command -v sing-box)
        print_info "删除 sing-box 二进制: ${sb_bin}"
        rm -f "${sb_bin}" 2>/dev/null || true
    else
        if [[ -f ${INSTALL_DIR}/sing-box ]]; then
            print_info "删除 sing-box 二进制: ${INSTALL_DIR}/sing-box"
            rm -f "${INSTALL_DIR}/sing-box" 2>/dev/null || true
        fi
    fi
    
    if [[ -d /etc/sing-box ]]; then
        print_info "删除 /etc/sing-box 配置目录..."
        rm -rf /etc/sing-box 2>/dev/null || true
    fi
    
    if [[ -d ${CERT_DIR} ]]; then
        print_info "删除证书目录: ${CERT_DIR}"
        rm -rf "${CERT_DIR}" 2>/dev/null || true
    fi
    
    if [[ -d "${LINK_DIR}" ]]; then
        print_info "删除链接文件目录: ${LINK_DIR}"
        rm -rf "${LINK_DIR}" 2>/dev/null || true
    fi
    
    if [[ -f "${KEY_FILE}" ]]; then
        print_info "删除密钥文件: ${KEY_FILE}"
        rm -f "${KEY_FILE}" 2>/dev/null || true
    fi
    
    if [[ -d /var/log/sing-box ]]; then
        print_info "删除 sing-box 日志目录..."
        rm -rf /var/log/sing-box 2>/dev/null || true
    fi
    
    print_info "清理 systemd journal 日志..."
    journalctl --vacuum-time=1s --quiet 2>/dev/null || true
    
    print_info "清理临时文件..."
    rm -f /tmp/sb.tar.gz 2>/dev/null || true
    rm -rf /tmp/sing-box-* 2>/dev/null || true
    
    print_info "删除快捷命令 sb..."
    if command -v sb &>/dev/null; then
        rm -f "$(command -v sb)" 2>/dev/null || true
    elif [[ -f /usr/local/bin/sb ]]; then
        rm -f /usr/local/bin/sb 2>/dev/null || true
    fi
    
    for cmd in /usr/bin/sb /usr/local/sbin/sb /usr/sbin/sb; do
        if [[ -f "$cmd" ]]; then
            print_info "删除快捷命令: $cmd"
            rm -f "$cmd" 2>/dev/null || true
        fi
    done
    
    print_info "删除当前脚本文件: ${SCRIPT_PATH}"
    rm -f "${SCRIPT_PATH}" 2>/dev/null || true
    
    print_success "已完成 sing-box 完整卸载和脚本清理，准备退出。"
    echo ""
    echo -e "${GREEN}✔ 所有文件已清理完成${NC}"
    echo -e "${YELLOW}注意:${NC}"
    echo -e "  1. 如果之前添加了防火墙规则，可能需要手动清理"
    echo -e "  2. 系统日志中可能还有历史记录"
    echo -e "  3. 如需重新安装，请重新下载脚本运行"
    echo ""
    
    exit 0
}

# ==================== 主循环 ====================
main_menu() {
    while true; do
        # 每次显示菜单前，从配置文件重新加载节点信息和中转配置
        if [[ -f "${CONFIG_FILE}" ]]; then
            load_inbounds_from_config
        fi
        load_relays_from_file
        
        show_main_menu
        read -p "请选择 [0-6]: " m_choice
        
        case $m_choice in
            1)
                show_menu
                ;;
            2)
                setup_relay
                ;;
            3)
                ip_config_menu
                ;;
            4)
                config_and_view_menu
                ;;
            5)
                regenerate_all_links
                ;;
            6)
                delete_self
                ;;
            0)
                print_info "已退出"
                exit 0
                ;;
            *)
                print_error "无效选项"
                ;;
        esac
        echo ""
        read -p "按回车返回主菜单..." _
    done
}

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
    print_success "已创建快捷命令: sb (任意位置输入 sb 即可重新进入脚本)"
}

# ==================== 主函数 ====================
main() {
    if [[ $EUID -ne 0 ]]; then
        print_error "需要 root 权限"
        exit 1
    fi
    
    detect_system
    install_singbox
    mkdir -p /etc/sing-box
    gen_keys
    get_ip
    setup_sb_shortcut
    
    # 加载 IP 配置
    load_ip_config
    
    # 从配置文件加载节点信息
    if [[ -f "${CONFIG_FILE}" ]]; then
        load_inbounds_from_config
    fi
    
    # 加载中转配置
    load_relays_from_file
    
    # 从文件加载链接
    load_links_from_files
    
    # 如果配置文件存在但链接文件为空，自动重新生成链接
    if [[ -f "${CONFIG_FILE}" ]] && [[ -z "$ALL_LINKS_TEXT" ]]; then
        print_info "检测到链接文件缺失，正在重新生成..."
        regenerate_links_from_config
    fi
    
    main_menu
}

main
