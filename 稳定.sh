#!/bin/bash

# 全局配置区
set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'

# 配置文件路径
CONFIG_FILE="/etc/sing-box/config.json"
INSTALL_DIR="/usr/local/bin"
CERT_DIR="/etc/sing-box/certs"
KEY_FILE="/etc/sing-box/keys.txt"
LINK_DIR="/etc/sing-box/links"
ALL_LINKS_FILE="${LINK_DIR}/all.txt"
REALITY_LINKS_FILE="${LINK_DIR}/reality.txt"
HYSTERIA2_LINKS_FILE="${LINK_DIR}/hysteria2.txt"
SOCKS5_LINKS_FILE="${LINK_DIR}/socks5.txt"
SHADOWTLS_LINKS_FILE="${LINK_DIR}/shadowtls.txt"
HTTPS_LINKS_FILE="${LINK_DIR}/https.txt"
ANYTLS_LINKS_FILE="${LINK_DIR}/anytls.txt"

# 密钥管理
REALITY_PRIVATE=""
REALITY_PUBLIC=""
UUID=""
SHORT_ID=""
HY2_PASSWORD=""
SS_PASSWORD=""
SHADOWTLS_PASSWORD=""
ANYTLS_PASSWORD=""
SOCKS_USER=""
SOCKS_PASS=""

# 服务器IP和端口
SERVER_IP=""
DEFAULT_SNI="time.is"

# 系统架构和版本
OS=""
ARCH=""

# 系统初始化
init() {
    SCRIPT_PATH=$(readlink -f "$0" 2>/dev/null || realpath "$0" 2>/dev/null || echo "$0")
    detect_system
    check_dependencies
}

# 系统检测
detect_system() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
    else
        print_error "无法检测系统"
    fi

    OS="${NAME}"
    ARCH=$(uname -m)

    case $ARCH in
        x86_64) ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        *) print_error "不支持的架构: $ARCH" ;;
    esac

    print_info "系统: ${OS} (${ARCH})"
}

# 安装必需的依赖
check_dependencies() {
    if ! command -v jq &>/dev/null || ! command -v openssl &>/dev/null; then
        print_info "安装必需的依赖..."
        apt-get update -qq && apt-get install -y curl wget jq openssl uuid-runtime
    fi
}

# 打印信息函数
print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; exit 1; }

# 安装Sing-box
install_singbox() {
    print_info "安装Sing-box..."

    LATEST=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r '.tag_name' | sed 's/v//')
    [[ -z "$LATEST" ]] && LATEST="1.12.0"
    print_info "目标版本: ${LATEST}"

    wget -q --show-progress -O /tmp/sb.tar.gz "https://github.com/SagerNet/sing-box/releases/download/v${LATEST}/sing-box-${LATEST}-linux-${ARCH}.tar.gz"
    tar -xzf /tmp/sb.tar.gz -C /tmp
    install -Dm755 /tmp/sing-box-${LATEST}-linux-${ARCH}/sing-box ${INSTALL_DIR}/sing-box
    rm -rf /tmp/sb.tar.gz /tmp/sing-box-*

    cat > /etc/systemd/system/sing-box.service << EOFSVC
[Unit]
Description=sing-box service
After=network.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/sing-box run -c ${CONFIG_FILE}
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOFSVC

    systemctl daemon-reload
    systemctl enable sing-box
    print_success "Sing-box 安装完成 (版本: ${LATEST})"
}

# 生成密钥
generate_keys() {
    print_info "生成密钥和UUID..."
    UUID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen)
    SHORT_ID=$(openssl rand -hex 8)
    HY2_PASSWORD=$(openssl rand -hex 16)
    SS_PASSWORD=$(openssl rand -hex 32)
    SHADOWTLS_PASSWORD=$(openssl rand -hex 16)
    ANYTLS_PASSWORD=$(openssl rand -hex 16)
    SOCKS_USER="user_$(openssl rand -hex 4)"
    SOCKS_PASS=$(openssl rand -hex 12)

    save_keys_to_file
    print_success "密钥生成完成"
}

# 保存密钥到文件
save_keys_to_file() {
    mkdir -p "$(dirname "${KEY_FILE}")"
    cat > "${KEY_FILE}" << EOF
# Sing-box 密钥文件
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

# 加载配置文件并生成节点信息
load_and_generate_links() {
    print_info "加载配置文件并生成节点..."

    # 加载配置
    INBOUNDS_JSON=$(jq '.inbounds' "${CONFIG_FILE}")
    OUTBOUNDS_JSON=$(jq '.outbounds' "${CONFIG_FILE}")

    # 生成链接
    generate_links_from_config
}

# 生成配置文件链接
generate_links_from_config() {
    print_info "根据配置文件生成节点链接..."
    ALL_LINKS_TEXT=""
    REALITY_LINKS=""
    HYSTERIA2_LINKS=""
    SOCKS5_LINKS=""
    SHADOWTLS_LINKS=""
    HTTPS_LINKS=""
    ANYTLS_LINKS=""

    # 解析节点配置
    local inbounds_count=$(jq '.inbounds | length' "${CONFIG_FILE}" 2>/dev/null || echo "0")
    for ((i=0; i<inbounds_count; i++)); do
        local inbound=$(jq -c ".inbounds[${i}]" "${CONFIG_FILE}")
        local port=$(echo "$inbound" | jq -r '.listen_port' 2>/dev/null || echo "0")
        local tag=$(echo "$inbound" | jq -r '.tag' 2>/dev/null || echo "unknown")
        local type=$(echo "$inbound" | jq -r '.type' 2>/dev/null || echo "unknown")

        # 基于节点类型生成链接
        case "$type" in
            "vless")
                generate_vless_link "$inbound" "$port" "$tag"
                ;;
            "hysteria2")
                generate_hysteria2_link "$inbound" "$port" "$tag"
                ;;
            "socks")
                generate_socks_link "$inbound" "$port" "$tag"
                ;;
            "shadowtls")
                generate_shadowtls_link "$inbound" "$port" "$tag"
                ;;
            "anytls")
                generate_anytls_link "$inbound" "$port" "$tag"
                ;;
            *)
                print_warning "未知协议类型: ${type}"
                ;;
        esac
    done

    # 保存链接到文件
    save_links_to_files
}

# 各种类型的节点链接生成
generate_vless_link() {
    local inbound="$1"
    local port="$2"
    local tag="$3"

    local uuid=$(echo "$inbound" | jq -r '.users[0].uuid' 2>/dev/null || echo "")
    local sni=$(echo "$inbound" | jq -r '.tls.server_name' 2>/dev/null || echo "$DEFAULT_SNI")
    local link="vless://${uuid}@${SERVER_IP}:${port}?encryption=none&security=tls&sni=${sni}&type=tcp"
    
    ALL_LINKS_TEXT="${ALL_LINKS_TEXT}[Vless] ${SERVER_IP}:${port} (SNI: ${sni})\n${link}\n"
    REALITY_LINKS="${REALITY_LINKS}${link}\n"
}

generate_hysteria2_link() {
    local inbound="$1"
    local port="$2"
    local tag="$3"

    local password=$(echo "$inbound" | jq -r '.users[0].password' 2>/dev/null || echo "")
    local sni=$(echo "$inbound" | jq -r '.tls.server_name' 2>/dev/null || echo "$DEFAULT_SNI")
    local link="hysteria2://${password}@${SERVER_IP}:${port}?insecure=1&sni=${sni}"
    
    ALL_LINKS_TEXT="${ALL_LINKS_TEXT}[Hysteria2] ${SERVER_IP}:${port} (SNI: ${sni})\n${link}\n"
    HYSTERIA2_LINKS="${HYSTERIA2_LINKS}${link}\n"
}

generate_socks_link() {
    local inbound="$1"
    local port="$2"
    local tag="$3"

    local username=$(echo "$inbound" | jq -r '.users[0].username' 2>/dev/null || echo "")
    local password=$(echo "$inbound" | jq -r '.users[0].password' 2>/dev/null || echo "")
    local link="socks5://${username}:${password}@${SERVER_IP}:${port}"
    
    ALL_LINKS_TEXT="${ALL_LINKS_TEXT}[SOCKS5] ${SERVER_IP}:${port}\n${link}\n"
    SOCKS5_LINKS="${SOCKS5_LINKS}${link}\n"
}

generate_shadowtls_link() {
    local inbound="$1"
    local port="$2"
    local tag="$3"

    local password=$(echo "$inbound" | jq -r '.users[0].password' 2>/dev/null || echo "")
    local sni=$(echo "$inbound" | jq -r '.handshake.server' 2>/dev/null || echo "$DEFAULT_SNI")
    local link="ss://${password}@${SERVER_IP}:${port}?shadow-tls=${sni}"

    ALL_LINKS_TEXT="${ALL_LINKS_TEXT}[ShadowTLS] ${SERVER_IP}:${port} (SNI: ${sni})\n${link}\n"
    SHADOWTLS_LINKS="${SHADOWTLS_LINKS}${link}\n"
}

generate_anytls_link() {
    local inbound="$1"
    local port="$2"
    local tag="$3"

    local password=$(echo "$inbound" | jq -r '.users[0].password' 2>/dev/null || echo "")
    local sni=$(echo "$inbound" | jq -r '.tls.server_name' 2>/dev/null || echo "$DEFAULT_SNI")
    local link="anytls://${password}@${SERVER_IP}:${port}?security=tls&sni=${sni}"

    ALL_LINKS_TEXT="${ALL_LINKS_TEXT}[AnyTLS] ${SERVER_IP}:${port} (SNI: ${sni})\n${link}\n"
    ANYTLS_LINKS="${ANYTLS_LINKS}${link}\n"
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
    print_success "链接已保存"
}

# 主执行函数
main() {
    init
    install_singbox
    generate_keys
    load_and_generate_links
}

# 启动主函数
main
