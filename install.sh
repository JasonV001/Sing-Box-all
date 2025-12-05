#!/bin/bash

# ==========================================================
# AnyTLS Reality Sing-box Installer
# 版本: 1.0
# 功能: 安装和管理 sing-box 多协议节点
# 作者: Anonymous
# ==========================================================

# -----------------------------
# 全局变量定义
# -----------------------------

# 颜色定义
readonly COLOR_RED="\033[0;31m"
readonly COLOR_GREEN="\033[0;32m"
readonly COLOR_YELLOW="\033[0;33m"
readonly COLOR_CYAN="\033[0;36m"
readonly COLOR_NC="\033[0m" # No Color

# 安装路径
readonly INSTALL_DIR="/usr/local/sing-box"
readonly CONFIG_FILE="/etc/sing-box/config.json"
readonly KEY_FILE="/etc/sing-box/keys.txt"
readonly LINK_DIR="/etc/sing-box/links"

# 链接文件
readonly ALL_LINKS_FILE="${LINK_DIR}/all_links.txt"
readonly REALITY_LINKS_FILE="${LINK_DIR}/reality_links.txt"
readonly HYSTERIA2_LINKS_FILE="${LINK_DIR}/hysteria2_links.txt"
readonly SOCKS5_LINKS_FILE="${LINK_DIR}/socks5_links.txt"
readonly SHADOWTLS_LINKS_FILE="${LINK_DIR}/shadowtls_links.txt"
readonly HTTPS_LINKS_FILE="${LINK_DIR}/https_links.txt"
readonly ANYTLS_LINKS_FILE="${LINK_DIR}/anytls_links.txt"

# 节点配置变量
INBOUNDS_JSON=""
INBOUND_TAGS=()
INBOUND_PORTS=()
INBOUND_PROTOS=()
INBOUND_RELAY_FLAGS=()
INBOUND_SNIS=()

# 链接变量
ALL_LINKS_TEXT=""
REALITY_LINKS=""
HYSTERIA2_LINKS=""
SOCKS5_LINKS=""
SHADOWTLS_LINKS=""
HTTPS_LINKS=""
ANYTLS_LINKS=""

# 系统信息
SYSTEM_TYPE=""
OS_VERSION=""
ARCH=""

# -----------------------------
# 日志和提示函数
# -----------------------------

print_info() {
    echo -e "${COLOR_CYAN}[INFO]${COLOR_NC} $1"
}

print_success() {
    echo -e "${COLOR_GREEN}[SUCCESS]${COLOR_NC} $1"
}

print_warning() {
    echo -e "${COLOR_YELLOW}[WARNING]${COLOR_NC} $1"
}

print_error() {
    echo -e "${COLOR_RED}[ERROR]${COLOR_NC} $1"
}

# -----------------------------
# 系统检测函数
# -----------------------------

detect_system() {
    print_info "正在检测系统信息..."
    
    # 检测系统类型
    if [[ -f /etc/debian_version ]]; then
        SYSTEM_TYPE="debian"
    elif [[ -f /etc/redhat-release ]]; then
        SYSTEM_TYPE="redhat"
    elif [[ -f /etc/arch-release ]]; then
        SYSTEM_TYPE="arch"
    else
        SYSTEM_TYPE="unknown"
    fi
    
    # 检测系统版本
    if [[ "$SYSTEM_TYPE" == "debian" ]]; then
        OS_VERSION=$(lsb_release -r | cut -f2)
    elif [[ "$SYSTEM_TYPE" == "redhat" ]]; then
        OS_VERSION=$(cat /etc/redhat-release | awk '{print $4}')
    elif [[ "$SYSTEM_TYPE" == "arch" ]]; then
        OS_VERSION="rolling"
    else
        OS_VERSION="unknown"
    fi
    
    # 检测架构
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)
            ARCH="amd64"
            ;;
        aarch64)
            ARCH="arm64"
            ;;
        armv7l)
            ARCH="armv7"
            ;;
        i386)
            ARCH="386"
            ;;
        *)
            ARCH="unknown"
            ;;
    esac
    
    print_info "系统类型: $SYSTEM_TYPE"
    print_info "系统版本: $OS_VERSION"
    print_info "系统架构: $ARCH"
}

# -----------------------------
# 依赖安装函数
# -----------------------------

install_dependencies() {
    print_info "正在安装依赖..."
    
    case "$SYSTEM_TYPE" in
        debian)
            apt-get update -y && apt-get install -y curl wget unzip jq
            ;;
        redhat)
            yum update -y && yum install -y curl wget unzip jq
            ;;
        arch)
            pacman -Syu --noconfirm curl wget unzip jq
            ;;
        *)
            print_error "不支持的系统类型，无法自动安装依赖"
            return 1
            ;;
    esac
    
    print_success "依赖安装完成"
}

# -----------------------------
# 端口检查函数
# -----------------------------

check_port_in_use() {
    local port="$1"
    
    if [[ -z "$port" ]]; then
        print_error "端口号不能为空"
        return 1
    fi
    
    if [[ ! "$port" =~ ^[0-9]+$ ]]; then
        print_error "端口号必须是数字"
        return 1
    fi
    
    if [[ "$port" -lt 1 || "$port" -gt 65535 ]]; then
        print_error "端口号必须在 1-65535 之间"
        return 1
    fi
    
    if ss -tuln | grep -q ":$port " 2>/dev/null; then
        return 0 # 端口已被占用
    else
        return 1 # 端口未被占用
    fi
}

# -----------------------------
# 密钥生成函数
# -----------------------------

gen_keys() {
    print_info "正在生成密钥..."
    
    # 生成私钥（使用十六进制存储）
    local private_key=$(openssl rand -hex 32)
    local public_key=$(openssl rand -hex 32)
    local short_id=$(openssl rand -hex 8)
    
    # 确保目录存在
    mkdir -p /etc/sing-box
    
    # 写入密钥文件（限制权限）
    cat > "${KEY_FILE}" << EOF
PRIVATE_KEY=$private_key
PUBLIC_KEY=$public_key
SHORT_ID=$short_id
EOF
    
    # 设置严格的权限
    chmod 600 "${KEY_FILE}"
    
    print_success "密钥生成完成"
}

# -----------------------------
# 获取公网 IP 函数
# -----------------------------

get_ip() {
    print_info "正在获取公网 IP..."
    
    local ip=$(curl -s https://api.ip.sb)
    if [[ -z "$ip" ]]; then
        ip=$(curl -s https://ipinfo.io/ip)
    fi
    
    if [[ -z "$ip" ]]; then
        print_error "无法获取公网 IP，请检查网络连接"
        return 1
    fi
    
    readonly PUBLIC_IP="$ip"
    print_success "公网 IP: $PUBLIC_IP"
}

# -----------------------------
# 下载和安装 sing-box
# -----------------------------

install_singbox() {
    print_info "正在安装 sing-box..."
    
    # 创建安装目录
    mkdir -p "${INSTALL_DIR}"
    
    # 下载最新版本的 sing-box
    local latest_version=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r .tag_name)
    if [[ -z "$latest_version" ]]; then
        print_error "无法获取 sing-box 最新版本"
        return 1
    fi
    
    local download_url="https://github.com/SagerNet/sing-box/releases/download/${latest_version}/sing-box-${latest_version#v}-linux-${ARCH}.tar.gz"
    local sha_url="${download_url}.sha256sum"
    
    print_info "正在下载 sing-box ${latest_version}..."
    if ! wget -q -O /tmp/sing-box.tar.gz "$download_url"; then
        print_error "下载 sing-box 失败"
        return 1
    fi
    
    print_info "正在下载 SHA256 校验和..."
    if ! wget -q -O /tmp/sing-box.tar.gz.sha256sum "$sha_url"; then
        print_warning "无法下载 SHA256 校验和，将跳过完整性检查"
    else
        # 验证完整性
        print_info "正在验证文件完整性..."
        if ! sha256sum -c /tmp/sing-box.tar.gz.sha256sum 2>/dev/null | grep -q "OK"; then
            print_error "文件完整性校验失败，可能下载损坏"
            rm -f /tmp/sing-box.tar.gz /tmp/sing-box.tar.gz.sha256sum
            return 1
        fi
        print_success "文件完整性校验通过"
    fi
    
    # 解压并安装
    if ! tar -xzf /tmp/sing-box.tar.gz -C /tmp; then
        print_error "解压 sing-box 失败"
        return 1
    fi
    
    local extract_dir=$(find /tmp -name "sing-box-*-linux-${ARCH}" -type d)
    if [[ -z "$extract_dir" ]]; then
        print_error "无法找到解压后的目录"
        return 1
    fi
    
    cp "${extract_dir}/sing-box" "${INSTALL_DIR}/"
    chmod +x "${INSTALL_DIR}/sing-box"
    
    # 清理临时文件
    rm -rf /tmp/sing-box.tar.gz /tmp/sing-box.tar.gz.sha256sum "$extract_dir"
    
    print_success "sing-box 安装完成"
}

# -----------------------------
# 创建 systemd 服务
# -----------------------------

create_systemd_service() {
    print_info "正在创建 systemd 服务..."
    
    cat > /etc/systemd/system/sing-box.service << EOF
[Unit]
Description=sing-box service
After=network.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/sing-box run -c ${CONFIG_FILE}
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable sing-box
    
    print_success "systemd 服务创建完成"
}

# -----------------------------
# 生成配置文件
# -----------------------------

generate_config() {
    print_info "正在生成配置文件..."
    
    local private_key=$(grep PRIVATE_KEY "${KEY_FILE}" | cut -d= -f2)
    local public_key=$(grep PUBLIC_KEY "${KEY_FILE}" | cut -d= -f2)
    local short_id=$(grep SHORT_ID "${KEY_FILE}" | cut -d= -f2)
    
    cat > "${CONFIG_FILE}" << EOF
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    $INBOUNDS_JSON
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "final": "direct",
    "default_domain_resolver": "direct"
  },
  "experimental": {
    "cache_file": {
      "enabled": true,
      "path": "${INSTALL_DIR}/cache.db"
    }
  }
}
EOF
    
    print_success "配置文件生成完成"
}

# -----------------------------
# 从配置文件加载节点信息
# -----------------------------

load_nodes_from_config() {
    print_info "正在从配置文件加载节点信息..."
    
    if [[ ! -f "${CONFIG_FILE}" ]]; then
        print_warning "配置文件不存在"
        return 1
    fi
    
    # 清空现有节点信息
    INBOUND_TAGS=()
    INBOUND_PORTS=()
    INBOUND_PROTOS=()
    INBOUND_SNIS=()
    INBOUND_RELAY_FLAGS=()
    
    # 获取 inbound 数量
    local inbound_count=$(jq -r '.inbounds | length' "${CONFIG_FILE}")
    if [[ "$inbound_count" -eq 0 ]]; then
        print_warning "配置文件中没有节点"
        return 1
    fi
    
    # 遍历所有 inbound
    for ((i=0; i<inbound_count; i++)); do
        local tag=$(jq -r ".inbounds[${i}].tag" "${CONFIG_FILE}")
        local port=$(jq -r ".inbounds[${i}].listen_port" "${CONFIG_FILE}")
        local proto=$(jq -r ".inbounds[${i}].type" "${CONFIG_FILE}")
        local sni=$(jq -r ".inbounds[${i}].tls.server_name" "${CONFIG_FILE}" 2>/dev/null || echo "example.com")
        
        # 添加到全局变量
        INBOUND_TAGS+=($tag)
        INBOUND_PORTS+=($port)
        INBOUND_PROTOS+=($proto)
        INBOUND_SNIS+=($sni)
        INBOUND_RELAY_FLAGS+=(0)
    done
    
    print_success "节点信息加载完成"
    return 0
}

# -----------------------------
# 生成节点链接
# -----------------------------

generate_links() {
    print_info "正在生成节点链接..."
    
    # 清空现有链接
    ALL_LINKS_TEXT=""
    REALITY_LINKS=""
    HYSTERIA2_LINKS=""
    SOCKS5_LINKS=""
    SHADOWTLS_LINKS=""
    HTTPS_LINKS=""
    ANYTLS_LINKS=""
    
    # 遍历所有节点
    for ((i=0; i<${#INBOUND_TAGS[@]}; i++)); do
        local tag="${INBOUND_TAGS[$i]}"
        local port="${INBOUND_PORTS[$i]}"
        local proto="${INBOUND_PROTOS[$i]}"
        local sni="${INBOUND_SNIS[$i]}"
        
        local link=""
        
        # 根据协议生成不同的链接格式
        case "$proto" in
            vless)
                # 检查是否为 Reality
                if jq -e ".inbounds[] | select(.tag == \"$tag\").tls.reality.enabled" "${CONFIG_FILE}" > /dev/null 2>&1; then
                    local uuid=$(jq -r ".inbounds[] | select(.tag == \"$tag\").users[0].uuid" "${CONFIG_FILE}")
                    local flow=$(jq -r ".inbounds[] | select(.tag == \"$tag\").users[0].flow" "${CONFIG_FILE}")
                    local public_key=$(grep PUBLIC_KEY "${KEY_FILE}" | cut -d= -f2)
                    local short_id=$(grep SHORT_ID "${KEY_FILE}" | cut -d= -f2)
                    
                    link="vless://${uuid}@${PUBLIC_IP}:${port}?encryption=none&flow=${flow}&security=reality&sni=${sni}&fp=chrome&pbk=${public_key}&sid=${short_id}&type=tcp#Reality_${port}"
                    REALITY_LINKS="${REALITY_LINKS}${link}\n"
                fi
                ;;
            hysteria2)
                local password=$(jq -r ".inbounds[] | select(.tag == \"$tag\").users[0].password" "${CONFIG_FILE}")
                link="hysteria2://${password}@${PUBLIC_IP}:${port}?sni=${sni}&alpn=h3#Hysteria2_${port}"
                HYSTERIA2_LINKS="${HYSTERIA2_LINKS}${link}\n"
                ;;
            socks)
                local username=$(jq -r ".inbounds[] | select(.tag == \"$tag\").users[0].username" "${CONFIG_FILE}")
                local password=$(jq -r ".inbounds[] | select(.tag == \"$tag\").users[0].password" "${CONFIG_FILE}")
                link="socks5://${username}:${password}@${PUBLIC_IP}:${port}#SOCKS5_${port}"
                SOCKS5_LINKS="${SOCKS5_LINKS}${link}\n"
                ;;
            shadowsocks)
                if jq -e ".inbounds[] | select(.tag == \"$tag\").plugin.type" "${CONFIG_FILE}" > /dev/null 2>&1; then
                    local method=$(jq -r ".inbounds[] | select(.tag == \"$tag\").method" "${CONFIG_FILE}")
                    local password=$(jq -r ".inbounds[] | select(.tag == \"$tag\").password" "${CONFIG_FILE}")
                    link="ss://$(echo -n "${method}:${password}@${PUBLIC_IP}:${port}" | base64 -w 0)#ShadowTLS_${port}"
                    SHADOWTLS_LINKS="${SHADOWTLS_LINKS}${link}\n"
                fi
                ;;
            vmess)
                if jq -e ".inbounds[] | select(.tag == \"$tag\").tls.enabled" "${CONFIG_FILE}" > /dev/null 2>&1; then
                    local uuid=$(jq -r ".inbounds[] | select(.tag == \"$tag\").users[0].id" "${CONFIG_FILE}")
                    local vmess_config=$(jq -n --arg uuid "$uuid" --arg port "$port" --arg sni "$sni" --arg ip "$PUBLIC_IP" '{"add":$ip, "port":$port, "id":$uuid, "aid":"0", "net":"tcp", "type":"none", "host":"", "path":"", "tls":"tls", "sni":$sni}')
                    link="vmess://$(echo -n "$vmess_config" | base64 -w 0)#HTTPS_${port}"
                    HTTPS_LINKS="${HTTPS_LINKS}${link}\n"
                fi
                ;;
            trojan)
                local password=$(jq -r ".inbounds[] | select(.tag == \"$tag\").users[0].password" "${CONFIG_FILE}")
                link="trojan://${password}@${PUBLIC_IP}:${port}?sni=${sni}#AnyTLS_${port}"
                ANYTLS_LINKS="${ANYTLS_LINKS}${link}\n"
                ;;
        esac
        
        # 添加到全部链接
        if [[ -n "$link" ]]; then
            ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${link}\n"
        fi
    done
    
    print_success "节点链接生成完成"
    return 0
}

# -----------------------------
# 保存链接到文件
# -----------------------------

save_links_to_files() {
    print_info "正在保存链接到文件..."
    
    # 创建链接目录
    mkdir -p "${LINK_DIR}"
    
    # 保存全部链接
    if [[ -n "$ALL_LINKS_TEXT" ]]; then
        echo -n "$ALL_LINKS_TEXT" > "${ALL_LINKS_FILE}"
    fi
    
    # 保存 Reality 链接
    if [[ -n "$REALITY_LINKS" ]]; then
        echo -n "$REALITY_LINKS" > "${REALITY_LINKS_FILE}"
    fi
    
    # 保存 Hysteria2 链接
    if [[ -n "$HYSTERIA2_LINKS" ]]; then
        echo -n "$HYSTERIA2_LINKS" > "${HYSTERIA2_LINKS_FILE}"
    fi
    
    # 保存 SOCKS5 链接
    if [[ -n "$SOCKS5_LINKS" ]]; then
        echo -n "$SOCKS5_LINKS" > "${SOCKS5_LINKS_FILE}"
    fi
    
    # 保存 ShadowTLS 链接
    if [[ -n "$SHADOWTLS_LINKS" ]]; then
        echo -n "$SHADOWTLS_LINKS" > "${SHADOWTLS_LINKS_FILE}"
    fi
    
    # 保存 HTTPS 链接
    if [[ -n "$HTTPS_LINKS" ]]; then
        echo -n "$HTTPS_LINKS" > "${HTTPS_LINKS_FILE}"
    fi
    
    # 保存 AnyTLS 链接
    if [[ -n "$ANYTLS_LINKS" ]]; then
        echo -n "$ANYTLS_LINKS" > "${ANYTLS_LINKS_FILE}"
    fi
    
    print_success "链接保存完成"
    return 0
}

# -----------------------------
# 从文件加载链接
# -----------------------------

load_links_from_files() {
    print_info "正在从文件加载链接..."
    
    # 创建链接目录
    mkdir -p "${LINK_DIR}"
    
    # 加载全部链接
    if [[ -f "${ALL_LINKS_FILE}" ]]; then
        ALL_LINKS_TEXT=$(cat "${ALL_LINKS_FILE}")
    fi
    
    # 加载 Reality 链接
    if [[ -f "${REALITY_LINKS_FILE}" ]]; then
        REALITY_LINKS=$(cat "${REALITY_LINKS_FILE}")
    fi
    
    # 加载 Hysteria2 链接
    if [[ -f "${HYSTERIA2_LINKS_FILE}" ]]; then
        HYSTERIA2_LINKS=$(cat "${HYSTERIA2_LINKS_FILE}")
    fi
    
    # 加载 SOCKS5 链接
    if [[ -f "${SOCKS5_LINKS_FILE}" ]]; then
        SOCKS5_LINKS=$(cat "${SOCKS5_LINKS_FILE}")
    fi
    
    # 加载 ShadowTLS 链接
    if [[ -f "${SHADOWTLS_LINKS_FILE}" ]]; then
        SHADOWTLS_LINKS=$(cat "${SHADOWTLS_LINKS_FILE}")
    fi
    
    # 加载 HTTPS 链接
    if [[ -f "${HTTPS_LINKS_FILE}" ]]; then
        HTTPS_LINKS=$(cat "${HTTPS_LINKS_FILE}")
    fi
    
    # 加载 AnyTLS 链接
    if [[ -f "${ANYTLS_LINKS_FILE}" ]]; then
        ANYTLS_LINKS=$(cat "${ANYTLS_LINKS_FILE}")
    fi
    
    print_success "链接加载完成"
    return 0
}

# -----------------------------
# 服务管理函数
# -----------------------------

start_svc() {
    print_info "正在启动 sing-box 服务..."
    
    if command -v systemctl &>/dev/null; then
        systemctl start sing-box
        if [[ $? -ne 0 ]]; then
            print_error "启动服务失败"
            return 1
        fi
    else
        # 非 systemd 系统使用 nohup
        nohup "${INSTALL_DIR}/sing-box" run -c "${CONFIG_FILE}" > /dev/null 2>&1 &
        sleep 2
        if ! pgrep -f "sing-box run -c ${CONFIG_FILE}" > /dev/null; then
            print_error "启动服务失败"
            return 1
        fi
    fi
    
    print_success "服务启动成功"
}

stop_svc() {
    print_info "正在停止 sing-box 服务..."
    
    if command -v systemctl &>/dev/null; then
        systemctl stop sing-box
        if [[ $? -ne 0 ]]; then
            print_error "停止服务失败"
            return 1
        fi
    else
        # 非 systemd 系统使用 kill
        local pid=$(pgrep -f "sing-box run -c ${CONFIG_FILE}")
        if [[ -n "$pid" ]]; then
            kill "$pid"
            sleep 2
            if pgrep -f "sing-box run -c ${CONFIG_FILE}" > /dev/null; then
                print_error "停止服务失败"
                return 1
            fi
        fi
    fi
    
    print_success "服务停止成功"
}

restart_svc() {
    stop_svc && start_svc
}

status_svc() {
    print_info "正在检查 sing-box 服务状态..."
    
    if command -v systemctl &>/dev/null; then
        systemctl status sing-box --no-pager
    else
        local pid=$(pgrep -f "sing-box run -c ${CONFIG_FILE}")
        if [[ -n "$pid" ]]; then
            print_success "服务正在运行，PID: $pid"
        else
            print_warning "服务未运行"
        fi
    fi
}

# -----------------------------
# 节点管理函数
# -----------------------------

add_node() {
    print_info "正在添加新节点..."
    
    # 选择协议
    echo ""
    echo "可用协议:"
    echo "1. Reality"
    echo "2. Hysteria2"
    echo "3. SOCKS5"
    echo "4. ShadowTLS"
    echo "5. HTTPS"
    echo "6. AnyTLS"
    echo ""
    read -p "请选择协议 [1-6]: " proto_choice
    
    case "$proto_choice" in
        1) proto="reality" ;;
        2) proto="hysteria2" ;;
        3) proto="socks5" ;;
        4) proto="shadowtls" ;;
        5) proto="https" ;;
        6) proto="anytls" ;;
        *) print_error "无效选择" ; return 1 ;;
    esac
    
    # 输入端口
    echo ""
    while true; do
        read -p "请输入端口号 [1-65535]: " port
        if check_port_in_use "$port"; then
            print_warning "端口 $port 已被占用，请重新输入"
        else
            break
        fi
    done
    
    # 输入 SNI
    echo ""
    read -p "请输入 SNI (按回车使用默认值): " sni
    if [[ -z "$sni" ]]; then
        sni="example.com"
    fi
    
    # 生成唯一标签
    local tag="${proto}-${port}-$(date +%s)"
    
    # 构建 inbound 配置
    local inbound_config=""
    case "$proto" in
        reality)
            inbound_config=$(cat << EOF
{
  "type": "vless",
  "tag": "$tag",
  "listen": "::",
  "listen_port": $port,
  "users": [
    {
      "uuid": "$(openssl rand -hex 16)",
      "flow": "xtls-rprx-vision"
    }
  ],
  "tls": {
    "enabled": true,
    "server_name": "$sni",
    "reality": {
      "enabled": true,
      "handshake": {
        "server_name": "$sni",
        "type": "https"
      }
    }
  }
}
EOF
            )
            ;;
        hysteria2)
            inbound_config=$(cat << EOF
{
  "type": "hysteria2",
  "tag": "$tag",
  "listen": "::",
  "listen_port": $port,
  "users": [
    {
      "password": "$(openssl rand -hex 16)"
    }
  ],
  "tls": {
    "enabled": true,
    "server_name": "$sni"
  }
}
EOF
            )
            ;;
        socks5)
            inbound_config=$(cat << EOF
{
  "type": "socks",
  "tag": "$tag",
  "listen": "::",
  "listen_port": $port,
  "users": [
    {
      "username": "$(openssl rand -hex 8)",
      "password": "$(openssl rand -hex 16)"
    }
  ]
}
EOF
            )
            ;;
        shadowtls)
            inbound_config=$(cat << EOF
{
  "type": "shadowsocks",
  "tag": "$tag",
  "listen": "::",
  "listen_port": $port,
  "method": "2022-blake3-aes-256-gcm",
  "password": "$(openssl rand -hex 16)",
  "plugin": {
    "type": "shadowtls",
    "server_name": "$sni"
  }
}
EOF
            )
            ;;
        https)
            inbound_config=$(cat << EOF
{
  "type": "vmess",
  "tag": "$tag",
  "listen": "::",
  "listen_port": $port,
  "users": [
    {
      "id": "$(openssl rand -hex 16)"
    }
  ],
  "tls": {
    "enabled": true,
    "server_name": "$sni"
  }
}
EOF
            )
            ;;
        anytls)
            inbound_config=$(cat << EOF
{
  "type": "trojan",
  "tag": "$tag",
  "listen": "::",
  "listen_port": $port,
  "users": [
    {
      "password": "$(openssl rand -hex 16)"
    }
  ],
  "tls": {
    "enabled": true,
    "server_name": "$sni"
  }
}
EOF
            )
            ;;
        *)
            print_error "协议 $proto 暂不支持"
            return 1
            ;;
    esac
    
    # 添加到全局变量
    if [[ -n "$INBOUNDS_JSON" ]]; then
        INBOUNDS_JSON="${INBOUNDS_JSON},"
    fi
    INBOUNDS_JSON="${INBOUNDS_JSON}${inbound_config}"
    
    INBOUND_TAGS+=($tag)
    INBOUND_PORTS+=($port)
    INBOUND_PROTOS+=($proto)
    INBOUND_SNIS+=($sni)
    INBOUND_RELAY_FLAGS+=(0)
    
    print_success "节点添加完成"
}

delete_single_node() {
    print_info "正在删除单个节点..."
    
    if [[ ${#INBOUND_TAGS[@]} -eq 0 ]]; then
        print_warning "没有可删除的节点"
        return 1
    fi
    
    # 显示节点列表
    echo ""
    echo "可用节点:"
    echo "----------------------------------------"
    for i in "${!INBOUND_TAGS[@]}"; do
        echo -e "${COLOR_YELLOW}$((i+1)).${COLOR_NC} ${INBOUND_PROTOS[$i]} - 端口: ${INBOUND_PORTS[$i]} - SNI: ${INBOUND_SNIS[$i]}"
        echo -e "   标签: ${INBOUND_TAGS[$i]}"
    done
    echo "----------------------------------------"
    
    # 选择要删除的节点
    echo ""
    while true; do
        read -p "请选择要删除的节点 [1-${#INBOUND_TAGS[@]}]: " choice
        if [[ "$choice" =~ ^[1-9][0-9]*$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -le "${#INBOUND_TAGS[@]}" ]]; then
            break
        else
            print_error "无效选择，请输入 1-${#INBOUND_TAGS[@]} 之间的数字"
        fi
    done
    
    # 转换为数组索引
    local index=$((choice-1))
    local tag_to_delete="${INBOUND_TAGS[$index]}"
    
    # 从全局变量中删除
    unset INBOUND_TAGS[$index]
    unset INBOUND_PORTS[$index]
    unset INBOUND_PROTOS[$index]
    unset INBOUND_SNIS[$index]
    unset INBOUND_RELAY_FLAGS[$index]
    
    # 重新构建数组（删除后索引不连续）
    INBOUND_TAGS=(${INBOUND_TAGS[@]})
    INBOUND_PORTS=(${INBOUND_PORTS[@]})
    INBOUND_PROTOS=(${INBOUND_PROTOS[@]})
    INBOUND_SNIS=(${INBOUND_SNIS[@]})
    INBOUND_RELAY_FLAGS=(${INBOUND_RELAY_FLAGS[@]})
    
    # 重新构建 INBOUNDS_JSON
    INBOUNDS_JSON=""
    for tag in "${INBOUND_TAGS[@]}"; do
        # 从现有配置中提取对应标签的配置
        local config=$(jq -r ".inbounds[] | select(.tag == \"$tag\")" "${CONFIG_FILE}")
        if [[ -n "$config" ]]; then
            if [[ -n "$INBOUNDS_JSON" ]]; then
                INBOUNDS_JSON="${INBOUNDS_JSON},"
            fi
            INBOUNDS_JSON="${INBOUNDS_JSON}${config}"
        fi
    done
    
    print_success "节点删除完成"
}

delete_all_nodes() {
    print_info "正在删除所有节点..."
    
    if [[ ${#INBOUND_TAGS[@]} -eq 0 ]]; then
        print_warning "没有可删除的节点"
        return 1
    fi
    
    # 确认删除
    echo ""
    read -p "确定要删除所有节点吗？(y/n): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        print_info "已取消删除"
        return 0
    fi
    
    # 清空所有节点配置
    INBOUNDS_JSON=""
    INBOUND_TAGS=()
    INBOUND_PORTS=()
    INBOUND_PROTOS=()
    INBOUND_SNIS=()
    INBOUND_RELAY_FLAGS=()
    
    # 清空链接
    ALL_LINKS_TEXT=""
    REALITY_LINKS=""
    HYSTERIA2_LINKS=""
    SOCKS5_LINKS=""
    SHADOWTLS_LINKS=""
    HTTPS_LINKS=""
    ANYTLS_LINKS=""
    
    print_success "所有节点已删除"
}

# -----------------------------
# 配置和查看菜单
# -----------------------------

view_all_links() {
    print_info "查看全部节点链接..."
    
    if [[ -z "$ALL_LINKS_TEXT" ]]; then
        print_warning "没有可用的链接"
        return 1
    fi
    
    echo ""
    echo "========================================"
    echo "全部节点链接"
    echo "========================================"
    echo "$ALL_LINKS_TEXT"
    echo "========================================"
    echo ""
    print_info "链接已显示在上方"
}

view_reality_links() {
    print_info "查看 Reality 节点链接..."
    
    if [[ -z "$REALITY_LINKS" ]]; then
        print_warning "没有可用的 Reality 节点链接"
        return 1
    fi
    
    echo ""
    echo "========================================"
    echo "Reality 节点链接"
    echo "========================================"
    echo "$REALITY_LINKS"
    echo "========================================"
    echo ""
    print_info "链接已显示在上方"
}

view_hysteria2_links() {
    print_info "查看 Hysteria2 节点链接..."
    
    if [[ -z "$HYSTERIA2_LINKS" ]]; then
        print_warning "没有可用的 Hysteria2 节点链接"
        return 1
    fi
    
    echo ""
    echo "========================================"
    echo "Hysteria2 节点链接"
    echo "========================================"
    echo "$HYSTERIA2_LINKS"
    echo "========================================"
    echo ""
    print_info "链接已显示在上方"
}

view_socks5_links() {
    print_info "查看 SOCKS5 节点链接..."
    
    if [[ -z "$SOCKS5_LINKS" ]]; then
        print_warning "没有可用的 SOCKS5 节点链接"
        return 1
    fi
    
    echo ""
    echo "========================================"
    echo "SOCKS5 节点链接"
    echo "========================================"
    echo "$SOCKS5_LINKS"
    echo "========================================"
    echo ""
    print_info "链接已显示在上方"
}

view_shadowtls_links() {
    print_info "查看 ShadowTLS 节点链接..."
    
    if [[ -z "$SHADOWTLS_LINKS" ]]; then
        print_warning "没有可用的 ShadowTLS 节点链接"
        return 1
    fi
    
    echo ""
    echo "========================================"
    echo "ShadowTLS 节点链接"
    echo "========================================"
    echo "$SHADOWTLS_LINKS"
    echo "========================================"
    echo ""
    print_info "链接已显示在上方"
}

view_https_links() {
    print_info "查看 HTTPS 节点链接..."
    
    if [[ -z "$HTTPS_LINKS" ]]; then
        print_warning "没有可用的 HTTPS 节点链接"
        return 1
    fi
    
    echo ""
    echo "========================================"
    echo "HTTPS 节点链接"
    echo "========================================"
    echo "$HTTPS_LINKS"
    echo "========================================"
    echo ""
    print_info "链接已显示在上方"
}

view_anytls_links() {
    print_info "查看 AnyTLS 节点链接..."
    
    if [[ -z "$ANYTLS_LINKS" ]]; then
        print_warning "没有可用的 AnyTLS 节点链接"
        return 1
    fi
    
    echo ""
    echo "========================================"
    echo "AnyTLS 节点链接"
    echo "========================================"
    echo "$ANYTLS_LINKS"
    echo "========================================"
    echo ""
    print_info "链接已显示在上方"
}

reload_config() {
    print_info "正在重新加载配置..."
    
    # 检查配置文件是否存在
    if [[ ! -f "${CONFIG_FILE}" ]]; then
        print_warning "配置文件不存在，正在生成默认配置"
        generate_config
        restart_svc
        print_success "默认配置已生成并重新加载"
        return 0
    fi
    
    # 尝试加载配置
    if "${INSTALL_DIR}/sing-box" check -c "${CONFIG_FILE}" > /dev/null 2>&1; then
        restart_svc
        print_success "配置加载成功"
    else
        print_error "配置文件存在语法错误，加载失败"
        return 1
    fi
}

uninstall_singbox() {
    print_info "正在卸载 sing-box..."
    
    # 停止服务
    stop_svc
    
    # 删除服务文件
    if [[ -f "/etc/systemd/system/sing-box.service" ]]; then
        systemctl disable sing-box > /dev/null 2>&1
        rm -f /etc/systemd/system/sing-box.service
        systemctl daemon-reload
    fi
    
    # 删除安装目录
    if [[ -d "${INSTALL_DIR}" ]]; then
        rm -rf "${INSTALL_DIR}"
    fi
    
    # 删除配置文件和密钥
    if [[ -d "/etc/sing-box" ]]; then
        rm -rf /etc/sing-box
    fi
    
    print_success "sing-box 卸载完成"
}

config_and_view_menu() {
    while true; do
        clear
        echo -e "${COLOR_GREEN}===========================${COLOR_NC}"
        echo -e "${COLOR_GREEN} 配置和查看菜单 ${COLOR_NC}"
        echo -e "${COLOR_GREEN}===========================${COLOR_NC}"
        echo -e "${COLOR_YELLOW}1.${COLOR_NC} 重新加载配置"
        echo -e "${COLOR_YELLOW}2.${COLOR_NC} 查看全部节点链接"
        echo -e "${COLOR_YELLOW}3.${COLOR_NC} 查看 Reality 节点链接"
        echo -e "${COLOR_YELLOW}4.${COLOR_NC} 查看 Hysteria2 节点链接"
        echo -e "${COLOR_YELLOW}5.${COLOR_NC} 查看 SOCKS5 节点链接"
        echo -e "${COLOR_YELLOW}6.${COLOR_NC} 查看 ShadowTLS 节点链接"
        echo -e "${COLOR_YELLOW}7.${COLOR_NC} 查看 HTTPS 节点链接"
        echo -e "${COLOR_YELLOW}8.${COLOR_NC} 查看 AnyTLS 节点链接"
        echo -e "${COLOR_YELLOW}9.${COLOR_NC} 添加节点"
        echo -e "${COLOR_YELLOW}10.${COLOR_NC} 删除单个节点"
        echo -e "${COLOR_YELLOW}11.${COLOR_NC} 删除全部节点"
        echo -e "${COLOR_YELLOW}0.${COLOR_NC} 返回主菜单"
        echo -e "${COLOR_GREEN}===========================${COLOR_NC}"
        
        read -p "请选择 [0-11]: " choice
        
        case "$choice" in
            0) break ;;
            1) reload_config ;;
            2) view_all_links ;;
            3) view_reality_links ;;
            4) view_hysteria2_links ;;
            5) view_socks5_links ;;
            6) view_shadowtls_links ;;
            7) view_https_links ;;
            8) view_anytls_links ;;
            9) add_node ;;
            10) delete_single_node ;;
            11) delete_all_nodes ;;
            *) print_error "无效选择" ; sleep 2 ;;
        esac
    done
}

# -----------------------------
# 主菜单函数
# -----------------------------

show_main_menu() {
    clear
    echo -e "${COLOR_GREEN}===========================${COLOR_NC}"
    echo -e "${COLOR_GREEN} AnyTLS Reality 安装脚本 ${COLOR_NC}"
    echo -e "${COLOR_GREEN}===========================${COLOR_NC}"
    echo -e "${COLOR_YELLOW}1.${COLOR_NC} 安装 sing-box"
    echo -e "${COLOR_YELLOW}2.${COLOR_NC} 配置和查看节点"
    echo -e "${COLOR_YELLOW}3.${COLOR_NC} 启动服务"
    echo -e "${COLOR_YELLOW}4.${COLOR_NC} 停止服务"
    echo -e "${COLOR_YELLOW}5.${COLOR_NC} 重启服务"
    echo -e "${COLOR_YELLOW}6.${COLOR_NC} 查看服务状态"
    echo -e "${COLOR_YELLOW}7.${COLOR_NC} 卸载 sing-box"
    echo -e "${COLOR_YELLOW}0.${COLOR_NC} 退出脚本"
    echo -e "${COLOR_GREEN}===========================${COLOR_NC}"
}

# -----------------------------
# 服务管理菜单
# -----------------------------

service_menu() {
    while true; do
        clear
        echo "========================================="
        echo "            服务管理菜单                 "
        echo "========================================="
        echo "1. 启动服务"
        echo "2. 停止服务"
        echo "3. 重启服务"
        echo "4. 查看状态"
        echo "0. 返回主菜单"
        echo "========================================="
        
        read -p "请选择 [0-4]: " choice
        
        case "$choice" in
            1) start_svc ;;
            2) stop_svc ;;
            3) restart_svc ;;
            4) status_svc ;;
            0) return ;;
            *) print_error "无效选择" ; sleep 2 ;;
        esac
        
        echo ""
        read -p "按回车返回服务菜单..." _
    done
}

# -----------------------------
# 查看链接菜单
# -----------------------------

view_links_menu() {
    while true; do
        clear
        echo "========================================="
        echo "            查看链接菜单                 "
        echo "========================================="
        echo "1. 查看全部节点链接"
        echo "2. 查看 Reality 节点链接"
        echo "3. 查看 Hysteria2 节点链接"
        echo "4. 查看 SOCKS5 节点链接"
        echo "5. 查看 ShadowTLS 节点链接"
        echo "6. 查看 HTTPS 节点链接"
        echo "7. 查看 AnyTLS 节点链接"
        echo "8. 从文件加载链接"
        echo "0. 返回主菜单"
        echo "========================================="
        
        read -p "请选择 [0-8]: " choice
        
        case "$choice" in
            1) view_all_links ;;
            2) view_reality_links ;;
            3) view_hysteria2_links ;;
            4) view_socks5_links ;;
            5) view_shadowtls_links ;;
            6) view_https_links ;;
            7) view_anytls_links ;;
            8) load_links_from_files ;;
            0) return ;;
            *) print_error "无效选择" ; sleep 2 ;;
        esac
        
        echo ""
        read -p "按回车返回链接菜单..." _
    done
}

# -----------------------------
# 工具选项菜单
# -----------------------------

tools_menu() {
    while true; do
        clear
        echo "========================================="
        echo "            工具选项菜单                 "
        echo "========================================="
        echo "1. 检查端口占用"
        echo "2. 测试网络连通性"
        echo "3. 查看系统信息"
        echo "4. 重载配置"
        echo "5. 卸载 Sing-Box"
        echo "0. 返回主菜单"
        echo "========================================="
        
        read -p "请选择 [0-5]: " choice
        
        case "$choice" in
            1) 
                read -p "请输入要检查的端口: " port
                check_port_in_use "$port"
                ;;
            2) test_connectivity ;;
            3) detect_system ;;
            4) reload_config ;;
            5) uninstall_singbox ;;
            0) return ;;
            *) print_error "无效选择" ; sleep 2 ;;
        esac
        
        echo ""
        read -p "按回车返回工具菜单..." _
    done
}

# -----------------------------
# 测试网络连通性函数
# -----------------------------

test_connectivity() {
    print_info "正在测试网络连通性..."
    
    local test_sites=("github.com" "google.com" "cloudflare.com")
    
    for site in "${test_sites[@]}"; do
        if ping -c 3 "$site" > /dev/null 2>&1; then
            print_success "$site 连通性正常"
        else
            print_warning "$site 连通性异常"
        fi
    done
    
    # 测试 HTTPS 连接
    print_info "测试 HTTPS 连接..."
    if curl -s https://www.google.com > /dev/null 2>&1; then
        print_success "HTTPS 连接正常"
    else
        print_warning "HTTPS 连接异常"
    fi
}

# -----------------------------
# 主函数
# -----------------------------

main() {
    # 检查root权限
    if [ "$EUID" -ne 0 ]; then
        print_error "此脚本必须以root用户身份运行"
        exit 1
    fi
    
    # 检查系统
    detect_system
    install_dependencies
    gen_keys
    get_ip
    
    while true; do
        show_main_menu
        read -p "请选择 [0-7]: " main_choice
        
        case "$main_choice" in
            0) 
                print_success "感谢使用，再见！"
                exit 0
                ;;
            1) install_singbox ;;
            2) config_and_view_menu ;;
            3) start_svc ;;
            4) stop_svc ;;
            5) restart_svc ;;
            6) status_svc ;;
            7) uninstall_singbox ;;
            *) print_error "无效选择" ; sleep 2 ;;
        esac
        
        echo ""
        read -p "按回车返回主菜单..." _
    done
}

# -----------------------------
# 启动脚本
# -----------------------------

main
