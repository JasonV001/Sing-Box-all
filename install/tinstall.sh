#!/bin/bash

# Sing-box 一键安装管理脚本
# 支持多协议：Reality, Hysteria2, SOCKS5, ShadowTLS, HTTPS, AnyTLS

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# 全局变量
SERVER_IP=""
CONFIG_FILE="/etc/sing-box/config.json"
INSTALL_DIR="/usr/local/bin"
CERT_DIR="/etc/sing-box/certs"
LINK_DIR="/etc/sing-box/links"
KEY_FILE="/etc/sing-box/keys.txt"

# 链接文件
ALL_LINKS_FILE="${LINK_DIR}/all.txt"
REALITY_LINKS_FILE="${LINK_DIR}/reality.txt"
HYSTERIA2_LINKS_FILE="${LINK_DIR}/hysteria2.txt"
SOCKS5_LINKS_FILE="${LINK_DIR}/socks5.txt"
SHADOWTLS_LINKS_FILE="${LINK_DIR}/shadowtls.txt"
HTTPS_LINKS_FILE="${LINK_DIR}/https.txt"
ANYTLS_LINKS_FILE="${LINK_DIR}/anytls.txt"

# 脚本路径
SCRIPT_PATH=$(readlink -f "$0" 2>/dev/null || realpath "$0" 2>/dev/null || echo "$0")

# 配置变量
INBOUNDS_JSON=""
OUTBOUND_TAG="direct"
RELAY_JSON=""

# 链接变量
ALL_LINKS_TEXT=""
REALITY_LINKS=""
HYSTERIA2_LINKS=""
SOCKS5_LINKS=""
SHADOWTLS_LINKS=""
HTTPS_LINKS=""
ANYTLS_LINKS=""

# 节点数组
INBOUND_TAGS=()
INBOUND_PORTS=()
INBOUND_PROTOS=()
INBOUND_RELAY_FLAGS=()
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

# 打印函数
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 显示横幅
show_banner() {
    clear
    echo ""
    echo -e "${CYAN}================================${NC}"
    echo -e "${GREEN}  Sing-box 一键安装脚本${NC}"
    echo -e "${CYAN}================================${NC}"
    echo ""
}

# 检测系统
detect_system() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
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

# 安装 sing-box
install_singbox() {
    print_info "检查 sing-box 安装状态..."
    
    if ! command -v jq &>/dev/null || ! command -v openssl &>/dev/null; then
        print_info "安装依赖包..."
        apt-get update -qq
        apt-get install -y curl wget jq openssl uuid-runtime >/dev/null 2>&1
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
    
    wget -q --show-progress -O /tmp/sb.tar.gz \
        "https://github.com/SagerNet/sing-box/releases/download/v${LATEST}/sing-box-${LATEST}-linux-${ARCH}.tar.gz"
    
    tar -xzf /tmp/sb.tar.gz -C /tmp
    install -Dm755 /tmp/sing-box-${LATEST}-linux-${ARCH}/sing-box ${INSTALL_DIR}/sing-box
    rm -rf /tmp/sb.tar.gz /tmp/sing-box-*
    
    cat > /etc/systemd/system/sing-box.service << 'EOF'
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
EOF
    
    systemctl daemon-reload
    systemctl enable sing-box >/dev/null 2>&1
    
    print_success "sing-box 安装完成 (版本: ${LATEST})"
}

# 生成证书
gen_cert_for_sni() {
    local sni="$1"
    local node_cert_dir="${CERT_DIR}/${sni}"
    
    mkdir -p "${node_cert_dir}"
    
    openssl genrsa -out "${node_cert_dir}/private.key" 2048 2>/dev/null
    openssl req -new -x509 -days 36500 \
        -key "${node_cert_dir}/private.key" \
        -out "${node_cert_dir}/cert.pem" \
        -subj "/C=US/ST=California/L=Cupertino/O=Apple Inc./CN=${sni}" 2>/dev/null
    
    print_success "证书生成完成 (${sni})"
}

# 生成密钥
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

# 保存密钥到文件
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

# 保存链接到文件
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

# 从文件加载链接
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

# 获取服务器IP
get_ip() {
    print_info "获取服务器 IP..."
    SERVER_IP=$(curl -s4m5 ifconfig.me || curl -s4m5 api.ipify.org || curl -s4m5 ip.sb)
    
    if [[ -z "$SERVER_IP" ]]; then
        print_error "无法获取IP"
        exit 1
    fi
    
    print_success "服务器 IP: ${SERVER_IP}"
}

# 检查端口是否被占用
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

# 读取端口并检查
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

# 配置 Reality
setup_reality() {
    echo ""
    print_info "配置 Reality 节点"
    read_port_with_check 443
    
    echo -e "${YELLOW}请输入伪装域名（建议使用常见HTTPS网站域名）${NC}"
    echo -e "${CYAN}例如: itunes.apple.com, www.bing.com, www.google.com${NC}"
    read -p "伪装域名 [${DEFAULT_SNI}]: " SNI
    SNI=${SNI:-${DEFAULT_SNI}}
    
    print_info "生成配置文件..."
    
    local inbound=$(cat << EOJSON
{
  "type": "vless",
  "tag": "vless-in-${PORT}",
  "listen": "::",
  "listen_port": ${PORT},
  "users": [{"uuid": "${UUID}", "flow": "xtls-rprx-vision"}],
  "tls": {
    "enabled": true,
    "server_name": "${SNI}",
    "reality": {
      "enabled": true,
      "handshake": {"server": "${SNI}", "server_port": 443},
      "private_key": "${REALITY_PRIVATE}",
      "short_id": ["${SHORT_ID}"]
    }
  }
}
EOJSON
)
    
    if [[ -z "$INBOUNDS_JSON" ]]; then
        INBOUNDS_JSON="$inbound"
    else
        INBOUNDS_JSON="${INBOUNDS_JSON},${inbound}"
    fi
    
    LINK="vless://${UUID}@${SERVER_IP}:${PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=chrome&pbk=${REALITY_PUBLIC}&sid=${SHORT_ID}&type=tcp#Reality-${SERVER_IP}"
    
    local line="[Reality] ${SERVER_IP}:${PORT} (SNI: ${SNI})\n${LINK}\n"
    ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}\n"
    REALITY_LINKS="${REALITY_LINKS}${line}\n"
    
    INBOUND_TAGS+=("vless-in-${PORT}")
    INBOUND_PORTS+=("${PORT}")
    INBOUND_PROTOS+=("Reality")
    INBOUND_SNIS+=("${SNI}")
    INBOUND_RELAY_FLAGS+=(0)
    
    print_success "Reality 配置完成 (SNI: ${SNI})"
    save_links_to_files
}

# 配置 Hysteria2
setup_hysteria2() {
    echo ""
    print_info "配置 Hysteria2 节点"
    read_port_with_check 443
    
    echo -e "${YELLOW}请输入伪装域名${NC}"
    read -p "伪装域名 [${DEFAULT_SNI}]: " HY2_SNI
    HY2_SNI=${HY2_SNI:-${DEFAULT_SNI}}
    
    print_info "为 ${HY2_SNI} 生成自签证书..."
    gen_cert_for_sni "${HY2_SNI}"
    
    print_info "生成配置文件..."
    
    local inbound=$(cat << EOJSON
{
  "type": "hysteria2",
  "tag": "hy2-in-${PORT}",
  "listen": "::",
  "listen_port": ${PORT},
  "users": [{"password": "${HY2_PASSWORD}"}],
  "tls": {
    "enabled": true,
    "alpn": ["h3"],
    "server_name": "${HY2_SNI}",
    "certificate_path": "${CERT_DIR}/${HY2_SNI}/cert.pem",
    "key_path": "${CERT_DIR}/${HY2_SNI}/private.key"
  }
}
EOJSON
)
    
    if [[ -z "$INBOUNDS_JSON" ]]; then
        INBOUNDS_JSON="$inbound"
    else
        INBOUNDS_JSON="${INBOUNDS_JSON},${inbound}"
    fi
    
    LINK="hysteria2://${HY2_PASSWORD}@${SERVER_IP}:${PORT}?insecure=1&sni=${HY2_SNI}#Hysteria2-${SERVER_IP}"
    
    local line="[Hysteria2] ${SERVER_IP}:${PORT} (SNI: ${HY2_SNI})\n${LINK}\n"
    ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}\n"
    HYSTERIA2_LINKS="${HYSTERIA2_LINKS}${line}\n"
    
    INBOUND_TAGS+=("hy2-in-${PORT}")
    INBOUND_PORTS+=("${PORT}")
    INBOUND_PROTOS+=("Hysteria2")
    INBOUND_SNIS+=("${HY2_SNI}")
    INBOUND_RELAY_FLAGS+=(0)
    
    print_success "Hysteria2 配置完成 (SNI: ${HY2_SNI})"
    save_links_to_files
}

# 配置 SOCKS5
setup_socks5() {
    echo ""
    print_info "配置 SOCKS5 节点"
    read_port_with_check 1080
    
    read -p "是否启用认证? [Y/n]: " ENABLE_AUTH
    ENABLE_AUTH=${ENABLE_AUTH:-Y}
    
    print_info "生成配置文件..."
    
    if [[ "$ENABLE_AUTH" =~ ^[Yy]$ ]]; then
        local inbound=$(cat << EOJSON
{
  "type": "socks",
  "tag": "socks-in-${PORT}",
  "listen": "::",
  "listen_port": ${PORT},
  "users": [{"username": "${SOCKS_USER}", "password": "${SOCKS_PASS}"}]
}
EOJSON
)
        LINK="socks5://${SOCKS_USER}:${SOCKS_PASS}@${SERVER_IP}:${PORT}#SOCKS5-${SERVER_IP}"
    else
        local inbound=$(cat << EOJSON
{
  "type": "socks",
  "tag": "socks-in-${PORT}",
  "listen": "::",
  "listen_port": ${PORT}
}
EOJSON
)
        LINK="socks5://${SERVER_IP}:${PORT}#SOCKS5-${SERVER_IP}"
    fi
    
    if [[ -z "$INBOUNDS_JSON" ]]; then
        INBOUNDS_JSON="$inbound"
    else
        INBOUNDS_JSON="${INBOUNDS_JSON},${inbound}"
    fi
    
    local line="[SOCKS5] ${SERVER_IP}:${PORT}\n${LINK}\n"
    ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}\n"
    SOCKS5_LINKS="${SOCKS5_LINKS}${line}\n"
    
    INBOUND_TAGS+=("socks-in-${PORT}")
    INBOUND_PORTS+=("${PORT}")
    INBOUND_PROTOS+=("SOCKS5")
    INBOUND_SNIS+=("")
    INBOUND_RELAY_FLAGS+=(0)
    
    print_success "SOCKS5 配置完成"
    save_links_to_files
}

# 生成配置文件
generate_config() {
    print_info "生成最终配置文件..."
    
    if [[ -z "$INBOUNDS_JSON" ]]; then
        print_error "未找到任何入站节点，请先添加节点"
        return 1
    fi
    
    local outbounds='[{"type": "direct", "tag": "direct"}]'
    
    if [[ -n "$RELAY_JSON" ]]; then
        outbounds="[${RELAY_JSON}, {\"type\": \"direct\", \"tag\": \"direct\"}]"
    fi
    
    local route_json='{"final":"direct"}'
    
    if [[ -n "$RELAY_JSON" ]]; then
        local relay_inbounds=()
        for i in "${!INBOUND_TAGS[@]}"; do
            if [[ "${INBOUND_RELAY_FLAGS[$i]}" == "1" ]]; then
                relay_inbounds+=("\"${INBOUND_TAGS[$i]}\"")
            fi
        done
        
        if [[ ${#relay_inbounds[@]} -gt 0 ]]; then
            local inbound_array=$(IFS=,; echo "${relay_inbounds[*]}")
            route_json="{\"rules\":[{\"inbound\":[${inbound_array}],\"outbound\":\"relay\"}],\"final\":\"direct\"}"
        fi
    fi
    
    cat > ${CONFIG_FILE} << EOJSON
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [${INBOUNDS_JSON}],
  "outbounds": ${outbounds},
  "route": ${route_json}
}
EOJSON
    
    print_success "配置文件生成完成"
}

# 启动服务
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
        print_error "服务启动失败"
        journalctl -u sing-box -n 10 --no-pager
        exit 1
    fi
}

# 显示结果
show_result() {
    clear
    echo ""
    echo -e "${CYAN}================================${NC}"
    echo -e "${GREEN}  配置完成！${NC}"
    echo -e "${CYAN}================================${NC}"
    echo ""
    echo -e "${YELLOW}节点链接:${NC}"
    echo ""
    echo -e "${LINK}"
    echo ""
}

# 协议选择菜单
show_protocol_menu() {
    show_banner
    echo -e "${YELLOW}请选择要添加的协议节点:${NC}"
    echo ""
    echo -e "${GREEN}[1]${NC} Reality"
    echo -e "${GREEN}[2]${NC} Hysteria2"
    echo -e "${GREEN}[3]${NC} SOCKS5"
    echo ""
    echo -e "${GREEN}[0]${NC} 返回主菜单"
    echo ""
    
    read -p "请选择 [0-3]: " choice
    
    case $choice in
        1)
            setup_reality
            generate_config
            start_svc
            show_result
            ;;
        2)
            setup_hysteria2
            generate_config
            start_svc
            show_result
            ;;
        3)
            setup_socks5
            generate_config
            start_svc
            show_result
            ;;
        0)
            return
            ;;
        *)
            print_error "无效选项"
            ;;
    esac
}

# 主菜单
main_menu() {
    while true; do
        show_banner
        echo -e "${YELLOW}主菜单:${NC}"
        echo ""
        echo -e "${GREEN}[1]${NC} 添加节点"
        echo -e "${GREEN}[2]${NC} 查看所有链接"
        echo -e "${GREEN}[3]${NC} 重启服务"
        echo ""
        echo -e "${GREEN}[0]${NC} 退出"
        echo ""
        
        read -p "请选择 [0-3]: " choice
        
        case $choice in
            1)
                show_protocol_menu
                ;;
            2)
                clear
                echo -e "${YELLOW}所有节点链接:${NC}"
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
                if [[ -f "${CONFIG_FILE}" ]]; then
                    systemctl restart sing-box
                    print_success "服务已重启"
                else
                    print_error "配置文件不存在"
                fi
                read -p "按回车返回..." _
                ;;
            0)
                print_info "退出脚本"
                exit 0
                ;;
            *)
                print_error "无效选项"
                ;;
        esac
    done
}

# 主函数
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
    load_links_from_files
    
    main_menu
}

main
