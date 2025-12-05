#!/bin/bash

set -e

# ============================================================================
# 全局配置和常量
# ============================================================================

# 颜色定义
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly PURPLE='\033[0;35m'
readonly NC='\033[0m'

# 目录和文件路径
readonly CONFIG_FILE="/etc/sing-box/config.json"
readonly INSTALL_DIR="/usr/local/bin"
readonly CERT_DIR="/etc/sing-box/certs"
readonly LOG_DIR="/var/log/sing-box"
readonly KEY_FILE="/etc/sing-box/keys.txt"
readonly SCRIPT_PATH="/usr/local/bin/sb-manager"

# 链接保存目录
readonly LINK_DIR="/etc/sing-box/links"
readonly ALL_LINKS_FILE="${LINK_DIR}/all.txt"
readonly REALITY_LINKS_FILE="${LINK_DIR}/reality.txt"
readonly HYSTERIA2_LINKS_FILE="${LINK_DIR}/hysteria2.txt"
readonly SOCKS5_LINKS_FILE="${LINK_DIR}/socks5.txt"
readonly SHADOWTLS_LINKS_FILE="${LINK_DIR}/shadowtls.txt"
readonly HTTPS_LINKS_FILE="${LINK_DIR}/https.txt"
readonly ANYTLS_LINKS_FILE="${LINK_DIR}/anytls.txt"

# 默认配置
readonly DEFAULT_SNI="time.is"
readonly DEFAULT_REALITY_PORT=443
readonly DEFAULT_HYSTERIA2_PORT=8443
readonly DEFAULT_SOCKS5_PORT=1080
readonly DEFAULT_SHADOWTLS_PORT=443
readonly DEFAULT_HTTPS_PORT=443
readonly DEFAULT_ANYTLS_PORT=443

# ============================================================================
# 全局变量
# ============================================================================

# 系统信息
declare os_name=""
declare os_arch=""

# 服务器信息
declare server_ip=""

# 密钥相关
declare uuid=""
declare reality_private_key=""
declare reality_public_key=""
declare short_id=""
declare hysteria2_password=""
declare shadowsocks_password=""
declare shadowtls_password=""
declare anytls_password=""
declare socks_username=""
declare socks_password=""

# 节点配置
declare -a inbound_tags=()
declare -a inbound_ports=()
declare -a inbound_protocols=()
declare -a inbound_snis=()
declare -a inbound_relay_flags=()
declare inbound_configs=""

# 中转配置
declare relay_config=""
declare outbound_tag="direct"

# 链接内容
declare all_links_content=""
declare reality_links_content=""
declare hysteria2_links_content=""
declare socks5_links_content=""
declare shadowtls_links_content=""
declare https_links_content=""
declare anytls_links_content=""

# ============================================================================
# 工具函数模块
# ============================================================================

# 日志输出函数
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1" >&2; }

# 验证输入是否为有效数字
validate_number() {
    local num="$1"
    local min="${2:-1}"
    local max="${3:-65535}"
    
    if [[ ! "$num" =~ ^[0-9]+$ ]] || ((num < min)) || ((num > max)); then
        return 1
    fi
    return 0
}

# 验证IP地址
validate_ip() {
    local ip="$1"
    local pattern='^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    [[ "$ip" =~ $pattern ]] && return 0
    return 1
}

# 检查命令是否存在
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# 安全读取输入
safe_read() {
    local prompt="$1"
    local default_value="$2"
    local input
    
    read -rp "${prompt}" input
    echo "${input:-${default_value}}"
}

# ============================================================================
# 系统检测模块
# ============================================================================

detect_system() {
    log_info "检测系统信息..."
    
    # 检测操作系统
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        os_name="${NAME:-${ID}}"
    elif [[ -f /etc/redhat-release ]]; then
        os_name=$(cat /etc/redhat-release)
    else
        os_name="Unknown"
    fi
    
    # 检测架构
    case $(uname -m) in
        x86_64)  os_arch="amd64" ;;
        aarch64) os_arch="arm64" ;;
        armv7l)  os_arch="armv7" ;;
        *) 
            log_error "不支持的架构: $(uname -m)"
            exit 1
            ;;
    esac
    
    log_success "系统: ${os_name} | 架构: ${os_arch}"
}

# ============================================================================
# 依赖管理模块
# ============================================================================

install_dependencies() {
    log_info "检查系统依赖..."
    
    local missing_packages=()
    
    # 检查必需的工具
    for cmd in curl wget jq openssl; do
        if ! command_exists "$cmd"; then
            missing_packages+=("$cmd")
        fi
    done
    
    # 安装缺失的包
    if [[ ${#missing_packages[@]} -gt 0 ]]; then
        log_info "安装依赖包: ${missing_packages[*]}"
        
        if command_exists apt-get; then
            apt-get update -qq
            apt-get install -y "${missing_packages[@]}" >/dev/null 2>&1
        elif command_exists yum; then
            yum install -y "${missing_packages[@]}" >/dev/null 2>&1
        elif command_exists dnf; then
            dnf install -y "${missing_packages[@]}" >/dev/null 2>&1
        else
            log_error "不支持的包管理器"
            exit 1
        fi
        
        log_success "依赖安装完成"
    else
        log_success "所有依赖已安装"
    fi
}

# ============================================================================
# 网络工具模块
# ============================================================================

get_server_ip() {
    log_info "获取服务器公网IP..."
    
    local ip_services=(
        "https://api.ipify.org"
        "https://ifconfig.me"
        "https://ip.sb"
        "https://checkip.amazonaws.com"
    )
    
    for service in "${ip_services[@]}"; do
        if server_ip=$(curl -s4 --connect-timeout 5 "$service" 2>/dev/null); then
            if [[ -n "$server_ip" ]] && validate_ip "$server_ip"; then
                log_success "服务器IP: ${server_ip}"
                return 0
            fi
        fi
    done
    
    log_error "无法获取有效的服务器IP"
    exit 1
}

check_port_in_use() {
    local port="$1"
    
    # 使用ss检查端口
    if command_exists ss; then
        if ss -tuln | grep -q ":${port}[[:space:]]"; then
            return 0
        fi
    fi
    
    # 使用netstat检查端口
    if command_exists netstat; then
        if netstat -tuln | grep -q ":${port}[[:space:]]"; then
            return 0
        fi
    fi
    
    return 1
}

# ============================================================================
# 安全模块 - 密钥管理
# ============================================================================

# 生成十六进制密码
generate_hex_password() {
    local length="${1:-16}"
    openssl rand -hex "${length}" 2>/dev/null || echo "0000000000000000"
}

generate_uuid() {
    if command_exists uuidgen; then
        uuidgen
    elif [[ -f /proc/sys/kernel/random/uuid ]]; then
        cat /proc/sys/kernel/random/uuid
    else
        # 使用openssl生成UUID
        openssl rand -hex 16 | sed 's/\(..\)/&-/g; s/-$//' 2>/dev/null || echo "00000000-0000-0000-0000-000000000000"
    fi
}

generate_keys() {
    log_info "生成密钥和UUID..."
    
    # 如果密钥文件已存在，加载它
    if [[ -f "${KEY_FILE}" ]] && [[ -r "${KEY_FILE}" ]]; then
        log_info "从文件加载已保存的密钥..."
        
        # 安全地加载密钥文件
        while IFS='=' read -r key value; do
            case "$key" in
                uuid) uuid="$value" ;;
                reality_private_key) reality_private_key="$value" ;;
                reality_public_key) reality_public_key="$value" ;;
                short_id) short_id="$value" ;;
                hysteria2_password) hysteria2_password="$value" ;;
                shadowsocks_password) shadowsocks_password="$value" ;;
                shadowtls_password) shadowtls_password="$value" ;;
                anytls_password) anytls_password="$value" ;;
                socks_username) socks_username="$value" ;;
                socks_password) socks_password="$value" ;;
            esac
        done < "${KEY_FILE}"
        
        # 检查是否所有必要的密钥都已加载
        if [[ -n "$uuid" && -n "$reality_private_key" && -n "$reality_public_key" ]]; then
            log_success "密钥加载完成"
            return 0
        else
            log_warning "密钥文件不完整，重新生成..."
        fi
    fi
    
    # 生成新的密钥
    # 生成UUID
    uuid=$(generate_uuid)
    
    # 生成Reality密钥对
    reality_private_key=$(generate_hex_password 32)
    reality_public_key=$(generate_hex_password 32)
    
    # 生成其他密钥（全部使用十六进制）
    short_id=$(generate_hex_password 8)
    hysteria2_password=$(generate_hex_password 32)
    shadowsocks_password=$(generate_hex_password 32)
    shadowtls_password=$(generate_hex_password 32)
    anytls_password=$(generate_hex_password 32)
    socks_username="user_$(generate_hex_password 4)"
    socks_password=$(generate_hex_password 32)
    
    # 保存密钥
    save_keys_to_file
    log_success "密钥生成完成"
}

save_keys_to_file() {
    mkdir -p "$(dirname "${KEY_FILE}")"
    
    cat > "${KEY_FILE}" << EOF
# Sing-box 密钥文件 - 请妥善保管
uuid=${uuid}
reality_private_key=${reality_private_key}
reality_public_key=${reality_public_key}
short_id=${short_id}
hysteria2_password=${hysteria2_password}
shadowsocks_password=${shadowsocks_password}
shadowtls_password=${shadowtls_password}
anytls_password=${anytls_password}
socks_username=${socks_username}
socks_password=${socks_password}
EOF
    
    # 设置严格的权限
    chmod 600 "${KEY_FILE}"
    chown root:root "${KEY_FILE}" 2>/dev/null || true
    
    log_success "密钥已保存到 ${KEY_FILE}"
}

# ============================================================================
# Sing-box安装模块
# ============================================================================

install_singbox() {
    log_info "检查sing-box..."
    
    # 检查是否已安装
    if command_exists sing-box; then
        local version
        version=$(sing-box version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo "unknown")
        log_success "sing-box 已安装 (版本: ${version})"
        return 0
    fi
    
    # 获取最新版本
    log_info "获取最新版本..."
    local latest_version="1.12.0"
    
    # 根据架构选择下载URL
    local download_url=""
    if [[ "$os_arch" == "amd64" ]]; then
        download_url="https://github.com/SagerNet/sing-box/releases/download/v${latest_version}/sing-box-${latest_version}-linux-amd64.tar.gz"
    elif [[ "$os_arch" == "arm64" ]]; then
        download_url="https://github.com/SagerNet/sing-box/releases/download/v${latest_version}/sing-box-${latest_version}-linux-arm64.tar.gz"
    else
        log_error "不支持的架构: $os_arch"
        return 1
    fi
    
    local temp_dir
    temp_dir=$(mktemp -d)
    
    log_info "下载 sing-box..."
    if ! wget -q --show-progress -O "${temp_dir}/sing-box.tar.gz" "${download_url}" 2>&1; then
        log_error "下载失败: ${download_url}"
        rm -rf "${temp_dir}" 2>/dev/null
        return 1
    fi
    
    # 解压并安装
    tar -xzf "${temp_dir}/sing-box.tar.gz" -C "${temp_dir}" 2>/dev/null
    
    # 查找二进制文件
    local binary_path
    binary_path=$(find "${temp_dir}" -name "sing-box" -type f -executable 2>/dev/null | head -1)
    
    if [[ -z "$binary_path" ]]; then
        log_error "在下载包中找不到 sing-box 二进制文件"
        rm -rf "${temp_dir}" 2>/dev/null
        return 1
    fi
    
    install -Dm755 "${binary_path}" "${INSTALL_DIR}/sing-box" 2>/dev/null
    
    # 创建服务文件
    create_service_file
    
    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable sing-box >/dev/null 2>&1
    
    # 清理临时文件
    rm -rf "${temp_dir}" 2>/dev/null
    
    log_success "sing-box 安装完成 (版本: ${latest_version})"
}

create_service_file() {
    cat > /etc/systemd/system/sing-box.service << 'EOF'
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org/
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
Group=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
}

# ============================================================================
# 证书管理模块
# ============================================================================

generate_certificate_for_sni() {
    local sni="$1"
    local cert_dir="${CERT_DIR}/${sni}"
    
    # 创建目录
    mkdir -p "${cert_dir}"
    
    log_info "为 ${sni} 生成自签证书..."
    
    # 生成私钥
    if ! openssl genrsa -out "${cert_dir}/private.key" 2048 2>/dev/null; then
        log_error "生成私钥失败"
        return 1
    fi
    
    # 生成证书
    openssl req -new -x509 -days 36500 -key "${cert_dir}/private.key" \
        -out "${cert_dir}/cert.pem" \
        -subj "/C=US/ST=California/L=San Francisco/O=Sing-box/CN=${sni}" 2>/dev/null
    
    # 设置权限
    chmod 600 "${cert_dir}/private.key"
    chmod 644 "${cert_dir}/cert.pem"
    
    log_success "证书生成完成 (${sni}，有效期100年)"
}

# ============================================================================
# 端口管理模块
# ============================================================================

read_port_with_check() {
    local default_port="$1"
    local port
    local max_retries=3
    local retry_count=0
    
    while [[ $retry_count -lt $max_retries ]]; do
        read -rp "监听端口 [${default_port}]: " port
        port="${port:-${default_port}}"
        
        if ! validate_number "$port" 1 65535; then
            log_error "端口无效，请输入 1-65535 之间的数字"
            ((retry_count++))
            continue
        fi
        
        if check_port_in_use "$port"; then
            log_warning "端口 ${port} 已被占用"
            read -rp "是否强制使用此端口? (y/N): " force_continue
            if [[ ! "$force_continue" =~ ^[Yy]$ ]]; then
                ((retry_count++))
                continue
            fi
        fi
        
        echo "$port"
        return 0
    done
    
    log_error "输入次数超限，使用默认端口: ${default_port}"
    echo "$default_port"
}

# ============================================================================
# 协议配置模块
# ============================================================================

configure_reality() {
    log_info "配置 Reality 协议"
    
    local port
    port=$(read_port_with_check "${DEFAULT_REALITY_PORT}")
    
    local sni
    sni=$(safe_read "伪装域名 [${DEFAULT_SNI}]: " "${DEFAULT_SNI}")
    
    # 创建配置
    local config
    config=$(cat << EOF
{
  "type": "vless",
  "tag": "vless-in-${port}",
  "listen": "::",
  "listen_port": ${port},
  "users": [{
    "uuid": "${uuid}",
    "flow": "xtls-rprx-vision"
  }],
  "tls": {
    "enabled": true,
    "server_name": "${sni}",
    "reality": {
      "enabled": true,
      "handshake": {
        "server": "${sni}",
        "server_port": 443
      },
      "private_key": "${reality_private_key}",
      "short_id": ["${short_id}"]
    }
  }
}
EOF
)
    
    # 生成链接
    local link="vless://${uuid}@${server_ip}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=chrome&pbk=${reality_public_key}&sid=${short_id}&type=tcp#Reality-${server_ip}"
    
    # 返回结果
    echo "$config|$link|Reality|${port}|${sni}"
}

configure_hysteria2() {
    log_info "配置 Hysteria2 协议"
    
    local port
    port=$(read_port_with_check "${DEFAULT_HYSTERIA2_PORT}")
    
    local sni
    sni=$(safe_read "伪装域名 [${DEFAULT_SNI}]: " "${DEFAULT_SNI}")
    
    # 生成证书
    generate_certificate_for_sni "$sni"
    
    # 创建配置
    local config
    config=$(cat << EOF
{
  "type": "hysteria2",
  "tag": "hy2-in-${port}",
  "listen": "::",
  "listen_port": ${port},
  "users": [{
    "password": "${hysteria2_password}"
  }],
  "tls": {
    "enabled": true,
    "alpn": ["h3"],
    "server_name": "${sni}",
    "certificate_path": "${CERT_DIR}/${sni}/cert.pem",
    "key_path": "${CERT_DIR}/${sni}/private.key"
  }
}
EOF
)
    
    # 生成链接
    local link="hysteria2://${hysteria2_password}@${server_ip}:${port}?insecure=1&sni=${sni}#Hysteria2-${server_ip}"
    
    # 返回结果
    echo "$config|$link|Hysteria2|${port}|${sni}"
}

configure_socks5() {
    log_info "配置 SOCKS5 协议"
    
    local port
    port=$(read_port_with_check "${DEFAULT_SOCKS5_PORT}")
    
    local enable_auth
    enable_auth=$(safe_read "是否启用认证? [Y/n]: " "Y")
    
    local config link
    
    if [[ "$enable_auth" =~ ^[Yy]$ ]]; then
        config=$(cat << EOF
{
  "type": "socks",
  "tag": "socks-in-${port}",
  "listen": "::",
  "listen_port": ${port},
  "users": [{
    "username": "${socks_username}",
    "password": "${socks_password}"
  }]
}
EOF
)
        link="socks5://${socks_username}:${socks_password}@${server_ip}:${port}#SOCKS5-${server_ip}"
    else
        config=$(cat << EOF
{
  "type": "socks",
  "tag": "socks-in-${port}",
  "listen": "::",
  "listen_port": ${port}
}
EOF
)
        link="socks5://${server_ip}:${port}#SOCKS5-${server_ip}"
    fi
    
    # 返回结果
    echo "$config|$link|SOCKS5|${port}|"
}

configure_shadowtls() {
    log_info "配置 ShadowTLS v3 协议"
    
    local port
    port=$(read_port_with_check "${DEFAULT_SHADOWTLS_PORT}")
    
    local sni
    sni=$(safe_read "伪装域名 [${DEFAULT_SNI}]: " "${DEFAULT_SNI}")
    
    # 创建配置
    local config
    config=$(cat << EOF
{
  "type": "shadowtls",
  "tag": "shadowtls-in-${port}",
  "listen": "::",
  "listen_port": ${port},
  "version": 3,
  "users": [{
    "password": "${shadowtls_password}"
  }],
  "handshake": {
    "server": "${sni}",
    "server_port": 443
  },
  "strict_mode": true,
  "detour": "shadowsocks-in-${port}"
},
{
  "type": "shadowsocks",
  "tag": "shadowsocks-in-${port}",
  "listen": "127.0.0.1",
  "listen_port": $((port + 10000)),
  "method": "2022-blake3-aes-128-gcm",
  "password": "${shadowsocks_password}"
}
EOF
)
    
    # 生成链接
    local ss_userinfo
    ss_userinfo=$(echo -n "2022-blake3-aes-128-gcm:${shadowsocks_password}" | base64 -w0 2>/dev/null || echo "")
    local plugin_json="{\"version\":\"3\",\"host\":\"${sni}\",\"password\":\"${shadowtls_password}\"}"
    local plugin_base64
    plugin_base64=$(echo -n "$plugin_json" | base64 -w0 2>/dev/null || echo "")
    
    local link="ss://${ss_userinfo}@${server_ip}:${port}?shadow-tls=${plugin_base64}#ShadowTLS-${server_ip}"
    
    # 返回结果
    echo "$config|$link|ShadowTLS|${port}|${sni}"
}

configure_https() {
    log_info "配置 HTTPS (VLESS+XTLS) 协议"
    
    local port
    port=$(read_port_with_check "${DEFAULT_HTTPS_PORT}")
    
    local sni
    sni=$(safe_read "伪装域名 [${DEFAULT_SNI}]: " "${DEFAULT_SNI}")
    
    # 生成证书
    generate_certificate_for_sni "$sni"
    
    # 创建配置
    local config
    config=$(cat << EOF
{
  "type": "vless",
  "tag": "vless-tls-in-${port}",
  "listen": "::",
  "listen_port": ${port},
  "users": [{
    "uuid": "${uuid}",
    "flow": ""
  }],
  "tls": {
    "enabled": true,
    "server_name": "${sni}",
    "certificate_path": "${CERT_DIR}/${sni}/cert.pem",
    "key_path": "${CERT_DIR}/${sni}/private.key"
  }
}
EOF
)
    
    # 生成链接
    local link="vless://${uuid}@${server_ip}:${port}?encryption=none&security=tls&sni=${sni}&fp=chrome&type=tcp&flow=#HTTPS-${server_ip}"
    
    # 返回结果
    echo "$config|$link|HTTPS|${port}|${sni}"
}

configure_anytls() {
    log_info "配置 AnyTLS 协议"
    
    local port
    port=$(read_port_with_check "${DEFAULT_ANYTLS_PORT}")
    
    local sni
    sni=$(safe_read "伪装域名 [${DEFAULT_SNI}]: " "${DEFAULT_SNI}")
    
    # 生成证书
    generate_certificate_for_sni "$sni"
    
    # 创建配置
    local config
    config=$(cat << EOF
{
  "type": "anytls",
  "tag": "anytls-in-${port}",
  "listen": "::",
  "listen_port": ${port},
  "users": [{
    "password": "${anytls_password}"
  }],
  "padding_scheme": [],
  "tls": {
    "enabled": true,
    "server_name": "${sni}",
    "certificate_path": "${CERT_DIR}/${sni}/cert.pem",
    "key_path": "${CERT_DIR}/${sni}/private.key"
  }
}
EOF
)
    
    # 生成链接
    local link="anytls://${anytls_password}@${server_ip}:${port}?security=tls&fp=chrome&insecure=1&sni=${sni}&type=tcp#AnyTLS-${server_ip}"
    
    # 返回结果
    echo "$config|$link|AnyTLS|${port}|${sni}"
}

# ============================================================================
# 配置管理模块
# ============================================================================

generate_final_config() {
    log_info "生成配置文件..."
    
    # 检查是否有配置
    if [[ -z "$inbound_configs" ]]; then
        log_error "没有可用的配置"
        return 1
    fi
    
    # 构建outbounds
    local outbounds
    if [[ -n "$relay_config" ]]; then
        outbounds="[${relay_config}, {\"type\": \"direct\", \"tag\": \"direct\"}]"
    else
        outbounds='[{"type": "direct", "tag": "direct"}]'
    fi
    
    # 构建路由
    local route_rules=""
    local relay_inbounds=()
    
    for i in "${!inbound_tags[@]}"; do
        if [[ "${inbound_relay_flags[$i]}" == "1" ]]; then
            relay_inbounds+=("\"${inbound_tags[$i]}\"")
        fi
    done
    
    if [[ ${#relay_inbounds[@]} -gt 0 ]]; then
        local inbound_array
        inbound_array=$(IFS=, ; echo "${relay_inbounds[*]}")
        route_rules=",\"rules\":[{\"inbound\":[${inbound_array}],\"outbound\":\"relay\"}]"
    fi
    
    # 写入配置文件
    mkdir -p "$(dirname "${CONFIG_FILE}")"
    
    cat > "${CONFIG_FILE}" << EOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [${inbound_configs}],
  "outbounds": ${outbounds},
  "route": {
    "final": "${outbound_tag}"
    ${route_rules}
  }
}
EOF
    
    log_success "配置文件已生成: ${CONFIG_FILE}"
}

# ============================================================================
# 服务管理模块
# ============================================================================

start_singbox_service() {
    log_info "启动sing-box服务..."
    
    # 验证配置
    if ! "${INSTALL_DIR}/sing-box" check -c "${CONFIG_FILE}" >/dev/null 2>&1; then
        log_error "配置验证失败"
        "${INSTALL_DIR}/sing-box" check -c "${CONFIG_FILE}"
        return 1
    fi
    
    # 重启服务
    if ! systemctl restart sing-box; then
        log_error "启动服务失败"
        journalctl -u sing-box -n 20 --no-pager
        return 1
    fi
    
    # 检查服务状态
    sleep 2
    if systemctl is-active --quiet sing-box; then
        log_success "服务启动成功"
    else
        log_error "服务启动失败"
        journalctl -u sing-box -n 20 --no-pager
        return 1
    fi
}

stop_singbox_service() {
    log_info "停止sing-box服务..."
    
    if systemctl stop sing-box; then
        log_success "服务已停止"
    else
        log_warning "停止服务失败"
    fi
}

restart_singbox_service() {
    log_info "重启sing-box服务..."
    
    if systemctl restart sing-box; then
        sleep 2
        if systemctl is-active --quiet sing-box; then
            log_success "服务重启成功"
        else
            log_error "服务重启后未运行"
        fi
    else
        log_error "重启服务失败"
    fi
}

# ============================================================================
# 链接管理模块
# ============================================================================

save_links_to_files() {
    mkdir -p "${LINK_DIR}"
    
    # 保存所有链接文件
    [[ -n "$all_links_content" ]] && echo -e "$all_links_content" > "${ALL_LINKS_FILE}"
    [[ -n "$reality_links_content" ]] && echo -e "$reality_links_content" > "${REALITY_LINKS_FILE}"
    [[ -n "$hysteria2_links_content" ]] && echo -e "$hysteria2_links_content" > "${HYSTERIA2_LINKS_FILE}"
    [[ -n "$socks5_links_content" ]] && echo -e "$socks5_links_content" > "${SOCKS5_LINKS_FILE}"
    [[ -n "$shadowtls_links_content" ]] && echo -e "$shadowtls_links_content" > "${SHADOWTLS_LINKS_FILE}"
    [[ -n "$https_links_content" ]] && echo -e "$https_links_content" > "${HTTPS_LINKS_FILE}"
    [[ -n "$anytls_links_content" ]] && echo -e "$anytls_links_content" > "${ANYTLS_LINKS_FILE}"
    
    # 设置权限
    chmod 600 "${LINK_DIR}"/*.txt 2>/dev/null || true
    
    log_success "链接已保存到 ${LINK_DIR}"
}

# ============================================================================
# 节点管理模块
# ============================================================================

add_node() {
    local protocol="$1"
    local result=""
    local config=""
    local link=""
    local protocol_name=""
    local port=""
    local sni=""
    
    case "$protocol" in
        "reality")
            result=$(configure_reality)
            ;;
        "hysteria2")
            result=$(configure_hysteria2)
            ;;
        "socks5")
            result=$(configure_socks5)
            ;;
        "shadowtls")
            result=$(configure_shadowtls)
            ;;
        "https")
            result=$(configure_https)
            ;;
        "anytls")
            result=$(configure_anytls)
            ;;
        *)
            log_error "不支持的协议: $protocol"
            return 1
            ;;
    esac
    
    # 解析结果
    IFS='|' read -r config link protocol_name port sni <<< "$result"
    
    if [[ -z "$config" ]]; then
        log_error "配置生成失败"
        return 1
    fi
    
    # 添加到配置
    if [[ -z "$inbound_configs" ]]; then
        inbound_configs="$config"
    else
        inbound_configs="${inbound_configs},${config}"
    fi
    
    # 添加到数组
    inbound_tags+=("${protocol_name}-${port}")
    inbound_ports+=("${port}")
    inbound_protocols+=("${protocol_name}")
    inbound_snis+=("${sni}")
    inbound_relay_flags+=(0)
    
    # 添加到链接内容
    local line="[${protocol_name}] ${server_ip}:${port}"
    [[ -n "$sni" ]] && line="${line} (SNI: ${sni})"
    line="${line}\n${link}\n"
    
    all_links_content="${all_links_content}${line}\n"
    
    # 添加到特定协议的链接
    case "$protocol_name" in
        "Reality")
            reality_links_content="${reality_links_content}${line}\n"
            ;;
        "Hysteria2")
            hysteria2_links_content="${hysteria2_links_content}${line}\n"
            ;;
        "SOCKS5")
            socks5_links_content="${socks5_links_content}${line}\n"
            ;;
        "ShadowTLS")
            shadowtls_links_content="${shadowtls_links_content}${line}\n"
            ;;
        "HTTPS")
            https_links_content="${https_links_content}${line}\n"
            ;;
        "AnyTLS")
            anytls_links_content="${anytls_links_content}${line}\n"
            ;;
    esac
    
    # 生成最终配置
    generate_final_config
    
    # 保存链接到文件
    save_links_to_files
    
    # 重启服务
    if restart_singbox_service; then
        show_add_result "$protocol_name" "$link" "$port" "$sni"
    else
        log_error "节点添加成功但服务启动失败"
    fi
}

show_add_result() {
    local protocol_name="$1"
    local link="$2"
    local port="$3"
    local sni="$4"
    
    clear
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                 配置完成                            ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}🎉 节点添加成功！${NC}"
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${YELLOW}协议:${NC} ${protocol_name}"
    echo -e "${YELLOW}服务器:${NC} ${server_ip}"
    echo -e "${YELLOW}端口:${NC} ${port}"
    [[ -n "$sni" ]] && echo -e "${YELLOW}SNI:${NC} ${sni}"
    echo -e "${YELLOW}出站:${NC} ${outbound_tag}"
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}节点链接:${NC}"
    echo ""
    echo -e "${YELLOW}${link}${NC}"
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════${NC}"
    echo -e "复制上面的链接到客户端即可使用"
    echo ""
}

# ============================================================================
# 菜单系统模块
# ============================================================================

show_banner() {
    clear
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║          ${GREEN}Sing-box 一键管理脚本${CYAN}                     ║${NC}"
    echo -e "${CYAN}║          ${YELLOW}版本: 2.0 修复版${CYAN}                          ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════╝${NC}"
    echo ""
}

show_main_menu() {
    show_banner
    
    echo -e "${CYAN}当前状态:${NC}"
    echo -e "  ${YELLOW}•${NC} 节点数: ${GREEN}${#inbound_tags[@]}${NC}"
    echo -e "  ${YELLOW}•${NC} 出站: ${GREEN}${outbound_tag}${NC}"
    echo -e "  ${YELLOW}•${NC} 服务器IP: ${GREEN}${server_ip}${NC}"
    echo ""
    
    echo -e "${CYAN}主菜单:${NC}"
    echo ""
    echo -e "  ${GREEN}[1]${NC} 添加节点"
    echo ""
    echo -e "  ${GREEN}[2]${NC} 管理节点"
    echo ""
    echo -e "  ${GREEN}[3]${NC} 中转配置"
    echo ""
    echo -e "  ${GREEN}[4]${NC} 查看链接"
    echo ""
    echo -e "  ${GREEN}[5]${NC} 服务管理"
    echo ""
    echo -e "  ${GREEN}[6]${NC} 系统工具"
    echo ""
    echo -e "  ${GREEN}[0]${NC} 退出脚本"
    echo ""
}

show_protocol_menu() {
    echo -e "${CYAN}选择协议:${NC}"
    echo ""
    echo -e "  ${GREEN}[1]${NC} Vless + Reality ${YELLOW}(推荐)${NC}"
    echo ""
    echo -e "  ${GREEN}[2]${NC} Hysteria2"
    echo ""
    echo -e "  ${GREEN}[3]${NC} SOCKS5"
    echo ""
    echo -e "  ${GREEN}[4]${NC} ShadowTLS v3"
    echo ""
    echo -e "  ${GREEN}[5]${NC} Vless + TLS (HTTPS)"
    echo ""
    echo -e "  ${GREEN}[6]${NC} AnyTLS"
    echo ""
    echo -e "  ${GREEN}[0]${NC} 返回上级"
    echo ""
}

# ============================================================================
# 主函数
# ============================================================================

main() {
    # 检查root权限
    if [[ $EUID -ne 0 ]]; then
        log_error "需要root权限运行"
        exit 1
    fi
    
    # 初始化
    show_banner
    detect_system
    install_dependencies
    install_singbox
    
    # 创建必要目录
    mkdir -p /etc/sing-box "${CERT_DIR}" "${LINK_DIR}"
    
    # 获取服务器IP
    get_server_ip
    
    # 生成密钥
    generate_keys
    
    # 进入主菜单
    while true; do
        show_main_menu
        read -rp "请选择操作 [0-6]: " choice
        
        case $choice in
            1)
                # 添加节点菜单
                while true; do
                    show_banner
                    show_protocol_menu
                    read -rp "选择协议 [0-6]: " proto_choice
                    
                    case $proto_choice in
                        0) break ;;
                        1) add_node "reality" ;;
                        2) add_node "hysteria2" ;;
                        3) add_node "socks5" ;;
                        4) add_node "shadowtls" ;;
                        5) add_node "https" ;;
                        6) add_node "anytls" ;;
                        *) log_error "无效选项" ;;
                    esac
                    
                    echo ""
                    read -rp "按回车键继续..." _
                done
                ;;
            2)
                # 管理节点（简化版本）
                echo ""
                echo -e "${CYAN}当前节点:${NC}"
                echo ""
                if [[ ${#inbound_tags[@]} -eq 0 ]]; then
                    echo -e "  ${YELLOW}暂无节点${NC}"
                else
                    for i in "${!inbound_tags[@]}"; do
                        echo -e "  ${GREEN}[$((i+1))]${NC} ${inbound_protocols[$i]}:${inbound_ports[$i]}"
                    done
                fi
                echo ""
                read -rp "按回车键继续..." _
                ;;
            0)
                log_info "退出脚本"
                exit 0
                ;;
            *)
                log_error "无效选项"
                ;;
        esac
    done
}

# ============================================================================
# 脚本入口
# ============================================================================

main "$@"
