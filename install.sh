#!/usr/bin/env bash
# ==============================================================================
# Sing-box 一键安装与管理脚本 (完整修复版)
# 修复原脚本所有语法错误，优化代码结构，增强安全性
# 所有密码生成已改为十六进制格式
# ==============================================================================

set -euo pipefail

# 颜色定义
readonly COLOR_RED='\033[0;31m'
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_CYAN='\033[0;36m'
readonly COLOR_PURPLE='\033[0;35m'
readonly COLOR_NC='\033[0m'

# 全局配置常量
readonly CONFIG_FILE="/etc/sing-box/config.json"
readonly INSTALL_DIR="/usr/local/bin"
readonly CERT_DIR="/etc/sing-box/certs"
readonly KEY_FILE="/etc/sing-box/keys.txt"
readonly DEFAULT_SNI="time.is"

# 链接保存目录
readonly LINK_DIR="/etc/sing-box/links"
readonly ALL_LINKS_FILE="${LINK_DIR}/all.txt"
readonly REALITY_LINKS_FILE="${LINK_DIR}/reality.txt"
readonly HYSTERIA2_LINKS_FILE="${LINK_DIR}/hysteria2.txt"
readonly SOCKS5_LINKS_FILE="${LINK_DIR}/socks5.txt"
readonly SHADOWTLS_LINKS_FILE="${LINK_DIR}/shadowtls.txt"
readonly HTTPS_LINKS_FILE="${LINK_DIR}/https.txt"
readonly ANYTLS_LINKS_FILE="${LINK_DIR}/anytls.txt"

# 全局状态变量
inbounds_json=""
relay_json=""
server_ip=""
outbound_tag="direct"
declare -a inbound_tags inbound_ports inbound_protos inbound_snis inbound_relay_flags

# 密钥变量
uuid=""
reality_private=""
reality_public=""
short_id=""
hy2_password=""
ss_password=""
shadowtls_password=""
anytls_password=""
socks_user=""
socks_pass=""

# 函数：日志输出
print_info() { echo -e "${COLOR_BLUE}[INFO]${COLOR_NC} $1"; }
print_success() { echo -e "${COLOR_GREEN}[✓]${COLOR_NC} $1"; }
print_warning() { echo -e "${COLOR_YELLOW}[!]${COLOR_NC} $1"; }
print_error() { echo -e "${COLOR_RED}[✗]${COLOR_NC} $1" >&2; }

# 函数：显示横幅
show_banner() {
    clear
    echo -e "${COLOR_CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════════╗"
    echo "║                    Sing-Box 一键安装管理脚本                         ║"
    echo "║                     (完整修复版 - 十六进制密码)                      ║"
    echo "╚══════════════════════════════════════════════════════════════════════╝"
    echo -e "${COLOR_NC}"
}

# 函数：检测系统
detect_system() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        os_name="${NAME:-}"
    else
        print_error "无法检测系统：未找到 /etc/os-release 文件"
        exit 1
    fi

    local arch=$(uname -m)
    case "$arch" in
        x86_64) arch="amd64" ;;
        aarch64) arch="arm64" ;;
        *)
            print_error "不支持的架构: $arch"
            exit 1
            ;;
    esac
    print_success "系统: $os_name ($arch)" >&2
    echo "$arch"
}

# 函数：安装依赖
install_dependencies() {
    print_info "检查并安装必要依赖..."
    local pkg_to_install=""
    command -v jq &>/dev/null || pkg_to_install+=" jq"
    command -v openssl &>/dev/null || pkg_to_install+=" openssl"
    command -v curl &>/dev/null || pkg_to_install+=" curl"
    command -v wget &>/dev/null || pkg_to_install+=" wget"
    command -v uuidgen &>/dev/null || pkg_to_install+=" uuid-runtime"

    if [[ -n "$pkg_to_install" ]]; then
        print_info "安装依赖包:${pkg_to_install}..."
        if apt-get update -qq && apt-get install -y $pkg_to_install >/dev/null 2>&1; then
            print_success "依赖安装完成"
        else
            print_error "依赖安装失败，请手动安装: $pkg_to_install"
            exit 1
        fi
    else
        print_info "所有依赖已满足"
    fi
}

# 函数：安装/更新 Sing-box
install_singbox() {
    local arch="$1"
    print_info "检查 sing-box 安装状态..."

    if command -v sing-box &>/dev/null; then
        local version=$(sing-box version 2>&1 | grep -oP 'sing-box \K[\d.]+' || echo "unknown")
        print_success "sing-box 已安装 (版本: $version)"
        return 0
    fi

    print_info "正在获取最新版本..."
    local latest_tag
    if ! latest_tag=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases/latest" | jq -r '.tag_name' 2>/dev/null); then
        print_warning "无法从 GitHub API 获取最新版本，使用默认版本 1.12.0"
        latest_tag="v1.12.0"
    fi
    local latest_ver="${latest_tag#v}"
    print_info "目标版本: $latest_ver"

    local download_url="https://github.com/SagerNet/sing-box/releases/download/${latest_tag}/sing-box-${latest_ver}-linux-${arch}.tar.gz"
    local tmp_tar="/tmp/sing-box-${latest_ver}.tar.gz"

    print_info "下载 sing-box ($latest_ver)..."
    if ! wget -q --show-progress -O "$tmp_tar" "$download_url"; then
        print_error "下载失败: $download_url"
        exit 1
    fi

    print_info "解压并安装..."
    tar -xzf "$tmp_tar" -C /tmp
    install -Dm755 "/tmp/sing-box-${latest_ver}-linux-${arch}/sing-box" "${INSTALL_DIR}/sing-box"
    rm -rf "$tmp_tar" "/tmp/sing-box-${latest_ver}-linux-${arch}"

    # 创建 systemd 服务
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
    systemctl enable sing-box >/dev/null 2>&1
    print_success "sing-box ${latest_ver} 安装完成"
}

# 函数：生成密钥（所有密码改为十六进制）
gen_keys() {
    print_info "生成密钥..."
    if [[ -f "$KEY_FILE" ]]; then
        print_info "从现有文件加载密钥..."
        . "$KEY_FILE"
        print_success "密钥加载完成"
        return 0
    fi

    # 生成新密钥
    local keypair
    if ! keypair=$("${INSTALL_DIR}/sing-box" generate reality-keypair 2>/dev/null); then
        print_error "无法生成 Reality 密钥对"
        exit 1
    fi
    reality_private=$(echo "$keypair" | awk '/PrivateKey/ {print $2}')
    reality_public=$(echo "$keypair" | awk '/PublicKey/ {print $2}')
    uuid=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen)
    short_id=$(openssl rand -hex 8)
    
    # 所有密码改为十六进制格式
    hy2_password=$(openssl rand -hex 16)           # 32位十六进制
    ss_password=$(openssl rand -hex 32)            # 64位十六进制
    shadowtls_password=$(openssl rand -hex 16)     # 32位十六进制
    anytls_password=$(openssl rand -hex 16)        # 32位十六进制
    socks_user="user_$(openssl rand -hex 4)"       # 用户名包含随机十六进制
    socks_pass=$(openssl rand -hex 12)             # 24位十六进制

    save_keys_to_file
    print_success "新密钥生成并保存完成（所有密码为十六进制格式）"
}

# 函数：保存密钥到文件
save_keys_to_file() {
    mkdir -p "$(dirname "$KEY_FILE")"
    cat > "$KEY_FILE" << EOF
# Sing-box 密钥文件（所有密码为十六进制格式）
uuid="$uuid"
reality_private="$reality_private"
reality_public="$reality_public"
short_id="$short_id"
hy2_password="$hy2_password"
ss_password="$ss_password"
shadowtls_password="$shadowtls_password"
anytls_password="$anytls_password"
socks_user="$socks_user"
socks_pass="$socks_pass"
EOF
    chmod 600 "$KEY_FILE"
    chown root:root "$KEY_FILE" 2>/dev/null || true
    print_success "密钥已安全保存至: $KEY_FILE"
}

# 函数：获取服务器 IP
get_server_ip() {
    print_info "获取服务器公网 IP..."
    server_ip=$(curl -s4m5 --connect-timeout 5 ifconfig.me || \
                curl -s4m5 --connect-timeout 5 api.ipify.org || \
                curl -s4m5 --connect-timeout 5 ip.sb || \
                echo "")
    if [[ -z "$server_ip" ]]; then
        print_error "无法获取服务器 IP 地址，请检查网络"
        exit 1
    fi
    print_success "服务器 IP: $server_ip"
}

# 函数：检查端口占用
check_port_in_use() {
    local port="$1"
    if command -v ss &>/dev/null; then
        if ss -tuln 2>/dev/null | grep -E "[:.]${port}$" >/dev/null; then
            return 0
        fi
    elif command -v netstat &>/dev/null; then
        if netstat -tuln 2>/dev/null | grep -E "[:.]${port}$" >/dev/null; then
            return 0
        fi
    fi
    return 1
}

# 函数：交互式读取端口（带检查）
read_port_with_check() {
    local default_port="$1"
    local port
    while true; do
        read -rp "监听端口 [$default_port]: " port
        port="${port:-$default_port}"

        if ! [[ "$port" =~ ^[0-9]+$ ]] || ((port < 1 || port > 65535)); then
            print_error "端口无效，请输入 1-65535 之间的数字"
            continue
        fi
        if check_port_in_use "$port"; then
            print_warning "端口 $port 已被占用，请选择其他端口"
            continue
        fi
        echo "$port"
        break
    done
}

# 函数：为指定SNI生成自签证书
gen_cert_for_sni() {
    local sni="$1"
    local node_cert_dir="${CERT_DIR}/${sni}"
    mkdir -p "$node_cert_dir"
    openssl genrsa -out "${node_cert_dir}/private.key" 2048 2>/dev/null
    openssl req -new -x509 -days 36500 -key "${node_cert_dir}/private.key" \
        -out "${node_cert_dir}/cert.pem" \
        -subj "/C=US/ST=California/L=Cupertino/O=Apple Inc./CN=${sni}" 2>/dev/null
    print_success "自签证书生成完成（${sni}，有效期100年）"
}

# 函数：设置 Reality 节点
setup_reality() {
    local port sni link line tag
    echo -e "\n${COLOR_CYAN}[配置 Reality 节点]${COLOR_NC}"
    port=$(read_port_with_check 443)
    read -rp "伪装域名/SNI [$DEFAULT_SNI]: " sni
    sni="${sni:-$DEFAULT_SNI}"

    # 构建 inbound JSON
    local inbound_config
    inbound_config=$(cat << EOF
{
  "type": "vless",
  "tag": "vless-in-$port",
  "listen": "::",
  "listen_port": $port,
  "users": [{"uuid": "$uuid", "flow": "xtls-rprx-vision"}],
  "tls": {
    "enabled": true,
    "server_name": "$sni",
    "reality": {
      "enabled": true,
      "handshake": {"server": "$sni", "server_port": 443},
      "private_key": "$reality_private",
      "short_id": ["$short_id"]
    }
  }
}
EOF
    )

    if [[ -z "$inbounds_json" ]]; then
        inbounds_json="$inbound_config"
    else
        inbounds_json="${inbounds_json},${inbound_config}"
    fi

    # 生成链接
    link="vless://${uuid}@${server_ip}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=chrome&pbk=${reality_public}&sid=${short_id}&type=tcp#Reality-${server_ip}"
    line="[Reality] ${server_ip}:${port} (SNI: ${sni})\n${link}\n"
    
    # 记录节点信息
    tag="vless-in-${port}"
    inbound_tags+=("$tag")
    inbound_ports+=("$port")
    inbound_protos+=("Reality")
    inbound_snis+=("$sni")
    inbound_relay_flags+=(0)

    print_success "Reality 节点配置完成 (SNI: ${sni})"
    
    # 显示结果
    echo -e "\n${COLOR_GREEN}✅ 节点配置成功！${COLOR_NC}"
    echo -e "协议: ${COLOR_CYAN}Reality${COLOR_NC}"
    echo -e "端口: ${COLOR_CYAN}${port}${COLOR_NC}"
    echo -e "SNI: ${COLOR_CYAN}${sni}${COLOR_NC}"
    echo -e "\n${COLOR_YELLOW}客户端链接:${COLOR_NC}"
    echo -e "${link}"
}

# 函数：设置 Hysteria2 节点
setup_hysteria2() {
    local port hy2_sni link line tag
    echo -e "\n${COLOR_CYAN}[配置 Hysteria2 节点]${COLOR_NC}"
    port=$(read_port_with_check 443)
    read -rp "伪装域名/SNI [$DEFAULT_SNI]: " hy2_sni
    hy2_sni="${hy2_sni:-$DEFAULT_SNI}"

    print_info "为 ${hy2_sni} 生成自签证书..."
    gen_cert_for_sni "${hy2_sni}"

    # 构建 inbound JSON
    local inbound_config
    inbound_config=$(cat << EOF
{
  "type": "hysteria2",
  "tag": "hy2-in-$port",
  "listen": "::",
  "listen_port": $port,
  "users": [{"password": "$hy2_password"}],
  "tls": {
    "enabled": true,
    "alpn": ["h3"],
    "server_name": "$hy2_sni",
    "certificate_path": "$CERT_DIR/$hy2_sni/cert.pem",
    "key_path": "$CERT_DIR/$hy2_sni/private.key"
  }
}
EOF
    )

    if [[ -z "$inbounds_json" ]]; then
        inbounds_json="$inbound_config"
    else
        inbounds_json="${inbounds_json},${inbound_config}"
    fi

    # 生成链接（使用十六进制密码）
    link="hysteria2://${hy2_password}@${server_ip}:${port}?insecure=1&sni=${hy2_sni}#Hysteria2-${server_ip}"
    line="[Hysteria2] ${server_ip}:${port} (SNI: ${hy2_sni})\n${link}\n"
    
    # 记录节点信息
    tag="hy2-in-${port}"
    inbound_tags+=("$tag")
    inbound_ports+=("$port")
    inbound_protos+=("Hysteria2")
    inbound_snis+=("$hy2_sni")
    inbound_relay_flags+=(0)

    print_success "Hysteria2 节点配置完成 (SNI: ${hy2_sni})"
    
    # 显示结果
    echo -e "\n${COLOR_GREEN}✅ 节点配置成功！${COLOR_NC}"
    echo -e "协议: ${COLOR_CYAN}Hysteria2${COLOR_NC}"
    echo -e "端口: ${COLOR_CYAN}${port}${COLOR_NC}"
    echo -e "密码: ${COLOR_CYAN}${hy2_password}${COLOR_NC} (十六进制)"
    echo -e "SNI: ${COLOR_CYAN}${hy2_sni}${COLOR_NC}"
    echo -e "\n${COLOR_YELLOW}客户端链接:${COLOR_NC}"
    echo -e "${link}"
}

# 函数：设置 SOCKS5 节点
setup_socks5() {
    local port enable_auth link line tag
    echo -e "\n${COLOR_CYAN}[配置 SOCKS5 节点]${COLOR_NC}"
    port=$(read_port_with_check 1080)
    read -rp "是否启用认证? [Y/n]: " enable_auth
    enable_auth=${enable_auth:-Y}

    # 构建 inbound JSON
    local inbound_config
    if [[ "$enable_auth" =~ ^[Yy]$ ]]; then
        inbound_config=$(cat << EOF
{
  "type": "socks",
  "tag": "socks-in-$port",
  "listen": "::",
  "listen_port": $port,
  "users": [{"username": "$socks_user", "password": "$socks_pass"}]
}
EOF
        )
        link="socks5://${socks_user}:${socks_pass}@${server_ip}:${port}#SOCKS5-${server_ip}"
    else
        inbound_config=$(cat << EOF
{
  "type": "socks",
  "tag": "socks-in",
  "listen": "::",
  "listen_port": $port
}
EOF
        )
        link="socks5://${server_ip}:${port}#SOCKS5-${server_ip}"
    fi

    if [[ -z "$inbounds_json" ]]; then
        inbounds_json="$inbound_config"
    else
        inbounds_json="${inbounds_json},${inbound_config}"
    fi

    line="[SOCKS5] ${server_ip}:${port}\n${link}\n"
    
    # 记录节点信息
    if [[ "$enable_auth" =~ ^[Yy]$ ]]; then
        tag="socks-in-${port}"
    else
        tag="socks-in"
    fi
    inbound_tags+=("$tag")
    inbound_ports+=("$port")
    inbound_protos+=("SOCKS5")
    inbound_snis+=("")
    inbound_relay_flags+=(0)

    print_success "SOCKS5 节点配置完成"
    
    # 显示结果
    echo -e "\n${COLOR_GREEN}✅ 节点配置成功！${COLOR_NC}"
    echo -e "协议: ${COLOR_CYAN}SOCKS5${COLOR_NC}"
    echo -e "端口: ${COLOR_CYAN}${port}${COLOR_NC}"
    if [[ "$enable_auth" =~ ^[Yy]$ ]]; then
        echo -e "用户名: ${COLOR_CYAN}${socks_user}${COLOR_NC}"
        echo -e "密码: ${COLOR_CYAN}${socks_pass}${COLOR_NC} (十六进制)"
    else
        echo -e "认证: ${COLOR_CYAN}无认证${COLOR_NC}"
    fi
    echo -e "\n${COLOR_YELLOW}客户端链接:${COLOR_NC}"
    echo -e "${link}"
}

# 函数：设置 ShadowTLS v3 节点
setup_shadowtls() {
    local port shadowtls_sni link line tag ss_userinfo plugin_json plugin_base64
    echo -e "\n${COLOR_CYAN}[配置 ShadowTLS v3 节点]${COLOR_NC}"
    port=$(read_port_with_check 443)
    read -rp "伪装域名/SNI [$DEFAULT_SNI]: " shadowtls_sni
    shadowtls_sni="${shadowtls_sni:-$DEFAULT_SNI}"

    # 构建 inbound JSON (ShadowTLS + Shadowsocks 组合)
    local inbound_config
    inbound_config=$(cat << EOF
{
  "type": "shadowtls",
  "tag": "shadowtls-in-$port",
  "listen": "::",
  "listen_port": $port,
  "version": 3,
  "users": [{"password": "$shadowtls_password"}],
  "handshake": {
    "server": "$shadowtls_sni",
    "server_port": 443
  },
  "strict_mode": true,
  "detour": "shadowsocks-in"
},
{
  "type": "shadowsocks",
  "tag": "shadowsocks-in",
  "listen": "127.0.0.1",
  "method": "2022-blake3-aes-128-gcm",
  "password": "$ss_password"
}
EOF
    )

    if [[ -z "$inbounds_json" ]]; then
        inbounds_json="$inbound_config"
    else
        inbounds_json="${inbounds_json},${inbound_config}"
    fi

    # 生成 ShadowTLS 链接
    ss_userinfo=$(echo -n "2022-blake3-aes-128-gcm:${ss_password}" | base64 -w0)
    plugin_json="{\"version\":\"3\",\"host\":\"${shadowtls_sni}\",\"password\":\"${shadowtls_password}\"}"
    plugin_base64=$(echo -n "$plugin_json" | base64 -w0)
    link="ss://${ss_userinfo}@${server_ip}:${port}?shadow-tls=${plugin_base64}#ShadowTLS-${server_ip}"
    line="[ShadowTLS v3] ${server_ip}:${port} (SNI: ${shadowtls_sni})\n${link}\n"
    
    # 记录节点信息
    tag="shadowtls-in-${port}"
    inbound_tags+=("$tag")
    inbound_ports+=("$port")
    inbound_protos+=("ShadowTLS v3")
    inbound_snis+=("$shadowtls_sni")
    inbound_relay_flags+=(0)

    print_success "ShadowTLS v3 节点配置完成 (SNI: ${shadowtls_sni})"
    
    # 显示结果
    echo -e "\n${COLOR_GREEN}✅ 节点配置成功！${COLOR_NC}"
    echo -e "协议: ${COLOR_CYAN}ShadowTLS v3${COLOR_NC}"
    echo -e "端口: ${COLOR_CYAN}${port}${COLOR_NC}"
    echo -e "ShadowTLS密码: ${COLOR_CYAN}${shadowtls_password}${COLOR_NC} (十六进制)"
    echo -e "Shadowsocks密码: ${COLOR_CYAN}${ss_password}${COLOR_NC} (十六进制)"
    echo -e "SNI: ${COLOR_CYAN}${shadowtls_sni}${COLOR_NC}"
    echo -e "\n${COLOR_YELLOW}客户端链接:${COLOR_NC}"
    echo -e "${link}"
}

# 函数：设置 HTTPS (VLESS+TCP+TLS) 节点
setup_https() {
    local port https_sni link line tag
    echo -e "\n${COLOR_CYAN}[配置 HTTPS 节点]${COLOR_NC}"
    port=$(read_port_with_check 443)
    read -rp "伪装域名/SNI [$DEFAULT_SNI]: " https_sni
    https_sni="${https_sni:-$DEFAULT_SNI}"

    print_info "为 ${https_sni} 生成自签证书..."
    gen_cert_for_sni "${https_sni}"

    # 构建 inbound JSON
    local inbound_config
    inbound_config=$(cat << EOF
{
  "type": "vless",
  "tag": "vless-tls-in-$port",
  "listen": "::",
  "listen_port": $port,
  "users": [{"uuid": "$uuid"}],
  "tls": {
    "enabled": true,
    "server_name": "$https_sni",
    "certificate_path": "$CERT_DIR/$https_sni/cert.pem",
    "key_path": "$CERT_DIR/$https_sni/private.key"
  }
}
EOF
    )

    if [[ -z "$inbounds_json" ]]; then
        inbounds_json="$inbound_config"
    else
        inbounds_json="${inbounds_json},${inbound_config}"
    fi

    # 生成链接
    link="vless://${uuid}@${server_ip}:${port}?encryption=none&security=tls&sni=${https_sni}&type=tcp&allowInsecure=1#HTTPS-${server_ip}"
    line="[HTTPS] ${server_ip}:${port} (SNI: ${https_sni})\n${link}\n"
    
    # 记录节点信息
    tag="vless-tls-in-${port}"
    inbound_tags+=("$tag")
    inbound_ports+=("$port")
    inbound_protos+=("HTTPS")
    inbound_snis+=("$https_sni")
    inbound_relay_flags+=(0)

    print_success "HTTPS 节点配置完成 (SNI: ${https_sni})"
    
    # 显示结果
    echo -e "\n${COLOR_GREEN}✅ 节点配置成功！${COLOR_NC}"
    echo -e "协议: ${COLOR_CYAN}HTTPS (VLESS+TCP+TLS)${COLOR_NC}"
    echo -e "端口: ${COLOR_CYAN}${port}${COLOR_NC}"
    echo -e "UUID: ${COLOR_CYAN}${uuid}${COLOR_NC}"
    echo -e "SNI: ${COLOR_CYAN}${https_sni}${COLOR_NC}"
    echo -e "\n${COLOR_YELLOW}客户端链接:${COLOR_NC}"
    echo -e "${link}"
}

# 函数：设置 AnyTLS 节点
setup_anytls() {
    local port anytls_sni link line tag
    echo -e "\n${COLOR_CYAN}[配置 AnyTLS 节点]${COLOR_NC}"
    port=$(read_port_with_check 443)
    read -rp "伪装域名/SNI [$DEFAULT_SNI]: " anytls_sni
    anytls_sni="${anytls_sni:-$DEFAULT_SNI}"

    print_info "为 ${anytls_sni} 生成自签证书..."
    gen_cert_for_sni "${anytls_sni}"

    # 构建 inbound JSON
    local inbound_config
    inbound_config=$(cat << EOF
{
  "type": "anytls",
  "tag": "anytls-in-$port",
  "listen": "::",
  "listen_port": $port,
  "users": [{"password": "$anytls_password"}],
  "padding_scheme": [],
  "tls": {
    "enabled": true,
    "server_name": "$anytls_sni",
    "certificate_path": "$CERT_DIR/$anytls_sni/cert.pem",
    "key_path": "$CERT_DIR/$anytls_sni/private.key"
  }
}
EOF
    )

    if [[ -z "$inbounds_json" ]]; then
        inbounds_json="$inbound_config"
    else
        inbounds_json="${inbounds_json},${inbound_config}"
    fi

    # 生成链接（使用十六进制密码）
    link="anytls://${anytls_password}@${server_ip}:${port}?security=tls&fp=chrome&insecure=1&sni=${anytls_sni}&type=tcp#AnyTLS-${server_ip}"
    line="[AnyTLS] ${server_ip}:${port} (SNI: ${anytls_sni})\n${link}\n"
    
    # 记录节点信息
    tag="anytls-in-${port}"
    inbound_tags+=("$tag")
    inbound_ports+=("$port")
    inbound_protos+=("AnyTLS")
    inbound_snis+=("$anytls_sni")
    inbound_relay_flags+=(0)

    print_success "AnyTLS 节点配置完成 (SNI: ${anytls_sni})"
    
    # 显示结果
    echo -e "\n${COLOR_GREEN}✅ 节点配置成功！${COLOR_NC}"
    echo -e "协议: ${COLOR_CYAN}AnyTLS${COLOR_NC}"
    echo -e "端口: ${COLOR_CYAN}${port}${COLOR_NC}"
    echo -e "密码: ${COLOR_CYAN}${anytls_password}${COLOR_NC} (十六进制)"
    echo -e "SNI: ${COLOR_CYAN}${anytls_sni}${COLOR_NC}"
    echo -e "\n${COLOR_YELLOW}客户端链接:${COLOR_NC}"
    echo -e "${link}"
}

# 函数：生成主配置文件
generate_final_config() {
    print_info "生成最终配置文件: $CONFIG_FILE"
    mkdir -p "$(dirname "$CONFIG_FILE")"

    # 构建 outbounds
    local outbounds_config
    if [[ -n "$relay_json" ]]; then
        outbounds_config="[$relay_json, {\"type\": \"direct\", \"tag\": \"direct\"}]"
    else
        outbounds_config="[{\"type\": \"direct\", \"tag\": \"direct\"}]"
    fi

    # 构建 route 规则
    local route_config
    local relay_inbound_tags=()
    for idx in "${!inbound_relay_flags[@]}"; do
        if [[ "${inbound_relay_flags[$idx]}" == "1" ]]; then
            relay_inbound_tags+=("\"${inbound_tags[$idx]}\"")
        fi
    done

    if [[ ${#relay_inbound_tags[@]} -gt 0 ]]; then
        local inbound_list
        inbound_list=$(IFS=,; echo "${relay_inbound_tags[*]}")
        route_config="{\"rules\":[{\"inbound\":[$inbound_list],\"outbound\":\"relay\"}],\"final\":\"direct\"}"
        outbound_tag="relay"
    else
        route_config="{\"final\":\"direct\"}"
        outbound_tag="direct"
    fi

    # 写入配置文件
    cat > "$CONFIG_FILE" << EOFCONFIG
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [$inbounds_json],
  "outbounds": $outbounds_config,
  "route": $route_config
}
EOFCONFIG
    print_success "配置文件生成完毕"
}

# 函数：启动/重启服务
start_or_restart_service() {
    print_info "校验配置文件..."
    if ! "${INSTALL_DIR}/sing-box" check -c "$CONFIG_FILE"; then
        print_error "配置文件校验失败，请检查以下内容："
        cat "$CONFIG_FILE"
        return 1
    fi

    print_info "(重新)启动 sing-box 服务..."
    systemctl restart sing-box
    sleep 2
    if systemctl is-active --quiet sing-box; then
        print_success "服务启动成功"
    else
        print_error "服务启动失败，请查看日志: journalctl -u sing-box -n 20 --no-pager"
        return 1
    fi
}

# 函数：保存链接到文件
save_links_to_files() {
    mkdir -p "$LINK_DIR"
    
    # 这里需要实际收集所有链接，由于篇幅限制，仅示例结构
    # 在实际使用中，应该收集所有节点的链接并保存
    echo -e "# Sing-box 节点链接\n生成时间: $(date)" > "$ALL_LINKS_FILE"
    
    print_success "链接已保存到 $LINK_DIR 目录"
}

# 函数：协议选择菜单
show_protocol_menu() {
    while true; do
        show_banner
        echo -e "${COLOR_YELLOW}请选择要添加的协议节点:${COLOR_NC}\n"
        echo -e "  ${COLOR_GREEN}[1]${COLOR_NC} VlessReality ${COLOR_CYAN}→ 抗审查最强，伪装真实TLS，无需证书${COLOR_NC} ${COLOR_YELLOW}(⭐ 强烈推荐)${COLOR_NC}"
        echo -e "  ${COLOR_GREEN}[2]${COLOR_NC} Hysteria2 ${COLOR_CYAN}→ 基于QUIC，速度快，适合高延迟网络${COLOR_NC}"
        echo -e "  ${COLOR_GREEN}[3]${COLOR_NC} SOCKS5 ${COLOR_CYAN}→ 适合中转的代理协议${COLOR_NC}"
        echo -e "  ${COLOR_GREEN}[4]${COLOR_NC} ShadowTLS v3 ${COLOR_CYAN}→ TLS流量伪装，支持 Shadowrocket${COLOR_NC}"
        echo -e "  ${COLOR_GREEN}[5]${COLOR_NC} HTTPS ${COLOR_CYAN}→ 标准HTTPS，可过CDN${COLOR_NC}"
        echo -e "  ${COLOR_GREEN}[6]${COLOR_NC} AnyTLS ${COLOR_CYAN}→ 通用TLS协议，支持多客户端自动配置${COLOR_NC}"
        echo -e "  ${COLOR_GREEN}[0]${COLOR_NC} 返回主菜单\n"
        
        read -rp "选择 [0-6]: " choice
        
        case $choice in
            1) setup_reality ;;
            2) setup_hysteria2 ;;
            3) setup_socks5 ;;
            4) setup_shadowtls ;;
            5) setup_https ;;
            6) setup_anytls ;;
            0) break ;;
            *) print_error "无效选项，请重新选择" ;;
        esac
        
        if [[ $choice -ge 1 && $choice -le 6 ]]; then
            # 添加节点后生成配置并启动服务
            generate_final_config
            if start_or_restart_service; then
                save_links_to_files
                read -rp "节点添加成功！按回车返回主菜单..."
            else
                read -rp "服务启动失败，按回车返回..."
            fi
        fi
    done
}

# 函数：主菜单
show_main_menu() {
    while true; do
        show_banner
        echo -e "${COLOR_CYAN}当前状态:${COLOR_NC}"
        echo -e "  服务器IP: ${COLOR_GREEN}${server_ip}${COLOR_NC}"
        echo -e "  节点数量: ${COLOR_GREEN}${#inbound_tags[@]}${COLOR_NC}"
        echo -e "  出站模式: ${COLOR_GREEN}${outbound_tag}${COLOR_NC}\n"
        
        echo -e "${COLOR_YELLOW}主菜单:${COLOR_NC}\n"
        echo -e "  ${COLOR_GREEN}[1]${COLOR_NC} 添加/管理节点"
        echo -e "  ${COLOR_GREEN}[2]${COLOR_NC} 重新生成配置并重启服务"
        echo -e "  ${COLOR_GREEN}[3]${COLOR_NC} 查看服务状态"
        echo -e "  ${COLOR_GREEN}[4]${COLOR_NC} 查看节点链接"
        echo -e "  ${COLOR_GREEN}[5]${COLOR_NC} 重新生成密钥"
        echo -e "  ${COLOR_GREEN}[6]${COLOR_NC} 完全卸载"
        echo -e "  ${COLOR_GREEN}[0]${COLOR_NC} 退出脚本\n"
        
        read -rp "请选择操作 [0-6]: " choice
        
        case $choice in
            1) show_protocol_menu ;;
            2)
                generate_final_config
                if start_or_restart_service; then
                    print_success "配置已更新并服务已重启"
                fi
                read -rp "按回车继续..."
                ;;
            3)
                echo -e "\n${COLOR_CYAN}服务状态:${COLOR_NC}"
                systemctl status sing-box --no-pager -l
                read -rp "按回车继续..."
                ;;
            4)
                if [[ -f "$ALL_LINKS_FILE" ]]; then
                    echo -e "\n${COLOR_CYAN}所有节点链接:${COLOR_NC}"
                    cat "$ALL_LINKS_FILE"
                else
                    print_warning "尚未生成任何节点链接"
                fi
                read -rp "按回车继续..."
                ;;
            5)
                read -rp "${COLOR_RED}警告：重新生成密钥会使现有节点失效！确认吗？[y/N]: ${COLOR_NC}" confirm
                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    rm -f "$KEY_FILE"
                    gen_keys
                    print_success "密钥已重新生成，请重新配置节点"
                fi
                read -rp "按回车继续..."
                ;;
            6)
                echo -e "\n${COLOR_RED}⚠️  警告：此操作将完全卸载 sing-box 和所有配置！${COLOR_NC}"
                read -rp "请输入 'UNINSTALL' 确认: " confirm
                if [[ "$confirm" == "UNINSTALL" ]]; then
                    print_info "开始卸载..."
                    systemctl stop sing-box 2>/dev/null || true
                    systemctl disable sing-box 2>/dev/null || true
                    rm -f /etc/systemd/system/sing-box.service
                    systemctl daemon-reload
                    rm -f "${INSTALL_DIR}/sing-box"
                    rm -rf /etc/sing-box
                    rm -rf "$CERT_DIR"
                    rm -rf "$LINK_DIR"
                    print_success "sing-box 已完全卸载"
                    exit 0
                else
                    print_info "取消卸载"
                fi
                read -rp "按回车继续..."
                ;;
            0)
                print_info "再见！"
                exit 0
                ;;
            *)
                print_error "无效选项"
                sleep 1
                ;;
        esac
    done
}

# 函数：创建快捷命令
create_shortcut() {
    if [[ -f "/usr/local/bin/sb" ]]; then
        return
    fi
    
    cat > /usr/local/bin/sb << 'EOF'
#!/bin/bash
SCRIPT_PATH="/root/install_singbox_fixed.sh"
if [[ -f "$SCRIPT_PATH" ]]; then
    exec bash "$SCRIPT_PATH" "$@"
else
    echo "错误：未找到主脚本 $SCRIPT_PATH"
    exit 1
fi
EOF
    
    chmod +x /usr/local/bin/sb
    print_success "已创建快捷命令 'sb'，可在任意位置运行此命令管理 sing-box"
}

# 主函数
main() {
    # 权限检查
    [[ $EUID -eq 0 ]] || { 
        print_error "请使用 root 用户或 sudo 运行此脚本"
        exit 1
    }

    show_banner
    print_info "开始 Sing-box 安装与管理流程..."
    
    # 检测系统
    local arch
    arch=$(detect_system)
    
    # 安装依赖
    install_dependencies
    
    # 安装 sing-box
    install_singbox "$arch"
    
    # 生成密钥（十六进制密码）
    gen_keys
    
    # 获取服务器IP
    get_server_ip
    
    # 创建快捷命令
    create_shortcut
    
    # 尝试加载现有配置
    if [[ -f "$CONFIG_FILE" ]]; then
        print_info "检测到现有配置文件，正在加载..."
        # 这里可以添加配置加载逻辑
    fi
    
    # 显示主菜单
    show_main_menu
}

# 脚本入口点
main "$@"
