#!/bin/sh
# POSIX sh 引导：检测 bash 是否可用，不可用则安装后用 bash 重新执行
if [ -z "$BASH_VERSION" ]; then
    if ! command -v bash >/dev/null 2>&1; then
        if command -v apk >/dev/null 2>&1; then
            echo "[引导] Alpine 系统，正在安装 bash ..."
            apk add --no-cache bash gcompat libexecinfo >/dev/null 2>&1
        elif command -v apt-get >/dev/null 2>&1; then
            echo "[引导] 正在安装 bash ..."
            apt-get update -qq && apt-get install -y bash >/dev/null 2>&1
        elif command -v yum >/dev/null 2>&1; then
            yum install -y bash >/dev/null 2>&1
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y bash >/dev/null 2>&1
        fi
    fi
    if command -v bash >/dev/null 2>&1; then
        exec bash "$0" "$@"
    fi
    echo "错误: 需要 bash，请先安装 (Alpine: apk add bash; Debian: apt install bash)"
    exit 1
fi

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
INBOUND_IP_MODE="dual"   # ipv4, ipv6 或 dual，控制入站监听地址（默认双栈）
OUTBOUND_IP_MODE="dual"  # ipv4, ipv6, ipv6_only 或 dual，控制出站连接（默认双栈）
IP_CONFIG_FILE="/etc/sing-box/ip_config.conf"

# 中转配置数组
RELAY_TAGS=()        # 中转标签数组
RELAY_JSONS=()       # 中转JSON配置数组
RELAY_DESCS=()       # 中转描述数组
RELAY_FILE="/etc/sing-box/relays.conf"

# 分流规则配置
DOMAIN_ROUTES=()     # 分流规则数组: 入站标签|匹配类型|匹配值|中转标签|描述
DOMAIN_ROUTE_FILE="/etc/sing-box/domain_routes.conf"

# 节点数组
INBOUND_TAGS=()
INBOUND_PORTS=()
INBOUND_PROTOS=()
INBOUND_RELAY_TAGS=()  # 存储每个节点使用的中转标签，"direct" 表示直连
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
DEFAULT_SNI="www.oracle.com"
DEFAULT_SNI1="www.oracle.com,www.mozilla.org"

# Alpine 标记
ALPINE=0

# 临时文件清理
TEMP_FILES=()
cleanup_temp_files() {
    for f in "${TEMP_FILES[@]}"; do
        rm -rf "$f" 2>/dev/null
    done
}
trap cleanup_temp_files EXIT INT TERM

# ==================== jq 配置文件原子更新 ====================
# 用法: jq_update_config <jq参数...>
# 功能: 原子性更新配置文件，先写临时文件再替换，失败时保留原文件
jq_update_config() {
    local tmp_file
    tmp_file=$(mktemp) || { print_error "创建临时文件失败"; return 1; }
    if jq "$@" "${CONFIG_FILE}" > "$tmp_file"; then
        mv "$tmp_file" "${CONFIG_FILE}"
        return 0
    else
        rm -f "$tmp_file"
        print_error "配置修改失败"
        return 1
    fi
}

# ==================== 交互辅助函数 ====================
# 暂停等待用户按回车
pause() {
    local msg="${1:-按回车继续...}"
    read -p "$msg" _
}

# 确认操作 (y/N)，返回 0=确认, 1=取消
confirm() {
    local prompt="${1:-确认? (y/N): }"
    local ans
    read -p "$prompt" ans
    [[ "$ans" =~ ^[Yy]$ ]]
}

# 显示菜单标题分隔线
menu_header() {
    local title="$1"
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}  ${title}${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo ""
}

# 按协议分组显示节点链接
show_protocol_links() {
    local proto="$1"
    local links="$2"
    local color="$3"

    if [[ -z "$links" ]]; then
        return 0
    fi

    echo -e "${color}【${proto}】${NC}"
    echo "$links"
    echo ""
}

# 统一追加节点链接（自动追加 #协议-IP 后缀）
# 用法: add_node_links <link_template> <proto> <ip> <port> [sni]
# link_template 中的 __IP__ 会被替换为实际 IP
add_node_links() {
    local template="$1"
    local proto="$2"
    local ip="$3"
    local port="$4"

    # 替换 __IP__ 占位符
    local link="${template//__IP__/$ip}"
    # 追加协议-IP 后缀
    link="${link}#${proto}-${ip}"

    add_link "$link" "$proto" "" "$ip" "$port" ""
}

# 生成 ShadowTLS 客户端配置文件
# 用法: generate_shadowtls_client_config <output_file> <server> <port> <sni> <stls_password> <ss_method> <ss_password>
generate_shadowtls_client_config() {
    local output_file="$1"
    local server="$2"
    local port="$3"
    local sni="$4"
    local stls_password="$5"
    local ss_method="$6"
    local ss_password="$7"

    cat > "${output_file}" << EOFCLIENT
{
  "log": {"level": "info"},
  "dns": {"servers": [{"tag": "google", "type": "udp", "server": "8.8.8.8"}]},
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "127.0.0.1",
      "listen_port": 1080,
      "sniff": true
    }
  ],
  "outbounds": [
    {
      "type": "selector",
      "tag": "proxy",
      "outbounds": ["ShadowTLS-${port}"],
      "default": "ShadowTLS-${port}"
    },
    {
      "type": "shadowsocks",
      "tag": "ShadowTLS-${port}",
      "method": "${ss_method}",
      "password": "${ss_password}",
      "detour": "shadowtls-out-${port}"
    },
    {
      "type": "shadowtls",
      "tag": "shadowtls-out-${port}",
      "server": "${server}",
      "server_port": ${port},
      "version": 3,
      "password": "${stls_password}",
      "tls": {
        "enabled": true,
        "server_name": "${sni}",
        "utls": {"enabled": true, "fingerprint": "chrome"}
      }
    },
    {"type": "direct", "tag": "direct"},
    {"type": "block", "tag": "block"}
  ],
  "route": {
    "rules": [
      {"geosite": "cn", "outbound": "direct"},
      {"geoip": "cn", "outbound": "direct"}
    ],
    "final": "proxy"
  }
}
EOFCLIENT
}

# ==================== 修改端口封装 ====================
# 用法: modify_port <old_tag> <new_tag_prefix> <new_port> [extra_jq_update]
# 自动更新 inbound tag/port 和 route rules 中的引用
modify_port() {
    local old_tag="$1"
    local new_tag_prefix="$2"
    local new_port="$3"
    local new_tag="${new_tag_prefix}${new_port}"

    jq_update_config --arg old_tag "$old_tag" --arg new_tag "$new_tag" --argjson new_port "$new_port" \
        '(.inbounds[] | select(.tag == $old_tag)) |= (.tag = $new_tag | .listen_port = $new_port)'

    if jq -e '.route.rules' "${CONFIG_FILE}" >/dev/null 2>&1; then
        jq_update_config --arg old_tag "$old_tag" --arg new_tag "$new_tag" \
            '(.route.rules[] | select(.inbound[]? == $old_tag)) |= (.inbound = [.inbound[] | if . == $old_tag then $new_tag else . end])'
    fi

    echo "$new_tag"
}

# ==================== 重新生成密钥/密码封装 ====================
# 用法: regenerate_secret <type> <tag> [extra_arg]
# type: uuid | password | sid | obfs_password | ss_password | stls_password | socks_user
regenerate_secret() {
    local type="$1"
    local tag="$2"
    local new_value=""

    case "$type" in
        uuid)
            new_value=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid 2>/dev/null)
            if [[ -z "$new_value" ]]; then
                print_error "UUID 生成失败"; return 1
            fi
            jq_update_config --arg tag "$tag" --arg uuid "$new_value" \
                '(.inbounds[] | select(.tag == $tag)) |= (.users[0].uuid = $uuid)'
            print_success "UUID 已重新生成: ${new_value}"
            ;;
        password)
            new_value=$(openssl rand -hex 16)
            jq_update_config --arg tag "$tag" --arg password "$new_value" \
                '(.inbounds[] | select(.tag == $tag)) |= (.users[0].password = $password)'
            print_success "密码已重新生成: ${new_value}"
            ;;
        sid)
            new_value=$(openssl rand -hex 8)
            jq_update_config --arg tag "$tag" --arg sid "$new_value" \
                '(.inbounds[] | select(.tag == $tag)) |= (.tls.reality.short_id = [$sid])'
            print_success "Short ID 已重新生成: ${new_value}"
            ;;
        obfs_password)
            new_value=$(openssl rand -hex 16)
            jq_update_config --arg tag "$tag" --arg password "$new_value" \
                '(.inbounds[] | select(.tag == $tag)) |= (.obfs.password = $password)'
            print_success "混淆密码已重新生成: ${new_value}"
            ;;
        ss_password)
            new_value=$(openssl rand -base64 16)
            jq_update_config --arg tag "$tag" --arg password "$new_value" \
                '(.inbounds[] | select(.tag == $tag)) |= (.password = $password)'
            print_success "SS 密码已重新生成: ${new_value}"
            ;;
        stls_password)
            new_value=$(openssl rand -hex 16)
            jq_update_config --arg tag "$tag" --arg password "$new_value" \
                '(.inbounds[] | select(.tag == $tag)) |= (.users[0].password = $password)'
            print_success "ShadowTLS 密码已重新生成: ${new_value}"
            ;;
        socks_password)
            new_value=$(openssl rand -hex 16)
            jq_update_config --arg tag "$tag" --arg password "$new_value" \
                '(.inbounds[] | select(.tag == $tag)) |= (.users[0].password = $password)'
            print_success "密码已重新生成: ${new_value}"
            ;;
        *)
            print_error "未知的密钥类型: $type"; return 1
            ;;
    esac
    return 0
}

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
        # 标记是否为 Alpine
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
# ==================== 服务控制（兼容 systemd / OpenRC） ====================
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
# ==================== 日志自动清理配置（首次安装时生效） ====================
LOGROTATE_FLAG="/etc/sing-box/.logrotate_setup"

setup_log_cleanup() {
    [[ -f "${LOGROTATE_FLAG}" ]] && return 0

    print_info "配置日志自动清理（7天 / 100M）..."

    if [[ $ALPINE -eq 1 ]]; then
        # 安装 logrotate 和 dcron，打印错误以便排错
        apk add --no-cache logrotate dcron || {
            print_error "安装 logrotate/dcron 失败，请检查网络或 apk 源"
            return 1
        }

        # 创建 logrotate 配置
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

        # 确保 dcron 在默认运行级别并启动
        rc-update add dcron default 2>/dev/null
        rc-service dcron start 2>/dev/null

        # 等待服务启动，然后检查状态
        sleep 1
        if ! rc-service dcron status | grep -q started; then
            print_error "dcron 服务启动失败，请手动检查"
            return 1
        fi

        print_success "Alpine 日志清理已配置（logrotate + dcron）"
    else
        mkdir -p /etc/systemd/journald.conf.d
        cat > /etc/systemd/journald.conf.d/sing-box-log.conf << 'EOF'
[Journal]
SystemMaxUse=100M
MaxRetentionSec=7day
EOF
        systemctl restart systemd-journald
        print_success "systemd journald 日志限制已生效"
    fi

    # 仅在全部成功后创建标记文件
    mkdir -p "$(dirname "${LOGROTATE_FLAG}")"
    touch "${LOGROTATE_FLAG}"
}
# ==================== 安装 sing-box ====================
install_singbox() {
    print_info "检查 sing-box 安装状态（支持断点续装）..."

    # ---------- 1. 安装系统依赖（检查 jq 即可代表基础工具） ----------
    if ! command -v jq &>/dev/null; then
        print_info "缺少基础依赖，开始安装..."
        if [[ $ALPINE -eq 1 ]]; then
            # Alpine 低内存：逐个安装
            for pkg in curl wget jq openssl util-linux coreutils gcompat libexecinfo; do
                apk add --no-cache "$pkg" >/dev/null 2>&1
                sleep 0.5
            done
        else
            apt-get update -qq && apt-get install -y curl wget jq openssl uuid-runtime >/dev/null 2>&1
        fi
        print_success "依赖安装完成"
    else
        print_success "基础依赖已就绪"
    fi

    # ---------- 2. 检查 sing-box 二进制是否可执行 ----------
    local need_download=1
    if [[ -x "${INSTALL_DIR}/sing-box" ]]; then
        # 尝试运行版本检查，若返回正常则认为可用
        if ${INSTALL_DIR}/sing-box version >/dev/null 2>&1; then
            local version=$(${INSTALL_DIR}/sing-box version 2>&1 | grep -oP 'sing-box version \K[0-9.]+' || echo "unknown")
            print_success "sing-box 已安装且可执行 (版本: ${version})"
            need_download=0
        else
            print_warning "检测到损坏的 sing-box，将重新下载安装"
            rm -f "${INSTALL_DIR}/sing-box"
        fi
    fi

    # ---------- 3. 下载、解压、安装二进制（如需要） ----------
    if [[ $need_download -eq 1 ]]; then
        local retry=0
        local max_retries=3
        while [[ $retry -lt $max_retries ]]; do
            LATEST=$(curl -s --connect-timeout 10 "https://api.github.com/repos/SagerNet/sing-box/releases/latest" | jq -r '.tag_name' | sed 's/v//')
            [[ -n "$LATEST" ]] && break
            ((retry++))
            [[ $retry -lt $max_retries ]] && sleep 2
        done
        [[ -z "$LATEST" ]] && LATEST="1.12.0"
        print_info "目标版本: ${LATEST}"

        # 清理可能残留的半成品
        rm -rf /tmp/sb.tar.gz /tmp/sing-box-${LATEST}-linux-${ARCH}
        TEMP_FILES+=("/tmp/sb.tar.gz" "/tmp/sing-box-${LATEST}-linux-${ARCH}")

        print_info "下载 sing-box (${LATEST} linux-${ARCH}) ..."
        wget -q --show-progress -O /tmp/sb.tar.gz \
            "https://github.com/SagerNet/sing-box/releases/download/v${LATEST}/sing-box-${LATEST}-linux-${ARCH}.tar.gz" 2>&1
        if [[ ! -f /tmp/sb.tar.gz ]]; then
            print_error "下载失败，请检查网络后重新运行脚本"
            return 1
        fi

        # 小内存机器解压时很可能被杀，解压前确保文件完整
        print_info "解压 sing-box ..."
        if tar -xzf /tmp/sb.tar.gz -C /tmp 2>/dev/null; then
            rm -f /tmp/sb.tar.gz
        else
            print_error "解压失败（可能内存不足被 kill），请增加 swap 后重新运行脚本"
            rm -f /tmp/sb.tar.gz
            return 1
        fi

        # 安装二进制
        if [[ -f "/tmp/sing-box-${LATEST}-linux-${ARCH}/sing-box" ]]; then
            install -Dm755 "/tmp/sing-box-${LATEST}-linux-${ARCH}/sing-box" "${INSTALL_DIR}/sing-box"
            rm -rf "/tmp/sing-box-${LATEST}-linux-${ARCH}"
            print_success "sing-box 二进制安装完成"
        else
            print_error "解压后未找到 sing-box 二进制，请检查"
            return 1
        fi
    fi

    # ---------- 4. 创建或修复服务文件 ----------
    local need_service=0
    if [[ $ALPINE -eq 1 ]]; then
        if [[ ! -f /etc/init.d/sing-box ]]; then
            need_service=1
        else
            # 如果服务文件不含预期的日志重定向命令，则重写
            if ! grep -q "/var/log/sing-box.log" /etc/init.d/sing-box; then
                need_service=1
            fi
        fi
    else
        if [[ ! -f /etc/systemd/system/sing-box.service ]]; then
            need_service=1
        fi
    fi

    if [[ $need_service -eq 1 ]]; then
        print_info "创建/更新服务文件..."
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

depend() {
    need net
    after firewall
}
EOF
            chmod +x /etc/init.d/sing-box
            print_success "OpenRC 服务已创建"
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

[Install]
WantedBy=multi-user.target
EOFSVC
            systemctl daemon-reload
            print_success "systemd 服务已创建"
        fi
    else
        print_success "服务文件已就绪"
    fi

    # ---------- 5. 开机自启 ----------
    svc_enable

    # ---------- 6. 配置日志清理（首次安装自动设置） ----------
    setup_log_cleanup

    print_success "sing-box 安装/修复完成"
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
    print_info "生成 Reality 密钥对..."
    
    if [[ -f "${KEY_FILE}" ]] && [[ -r "${KEY_FILE}" ]]; then
        print_info "从文件加载已保存的密钥..."
        while IFS='=' read -r key value; do
            value="${value#\"}"
            value="${value%\"}"
            [[ -z "$key" || "$key" =~ ^[[:space:]]*# ]] && continue
            case "$key" in
                REALITY_PRIVATE) REALITY_PRIVATE="$value" ;;
                REALITY_PUBLIC) REALITY_PUBLIC="$value" ;;
                SHORT_ID) SHORT_ID="$value" ;;
            esac
        done < "${KEY_FILE}"
        print_success "密钥加载完成"
        return 0
    fi
    
    KEYS=$(${INSTALL_DIR}/sing-box generate reality-keypair 2>/dev/null)
    REALITY_PRIVATE=$(echo "$KEYS" | grep "PrivateKey" | awk '{print $2}')
    REALITY_PUBLIC=$(echo "$KEYS" | grep "PublicKey" | awk '{print $2}')
    
    SHORT_ID=$(openssl rand -hex 8)
    print_info "Reality Short ID 已自动生成: ${SHORT_ID}"
    print_info "如需修改 Short ID，可在添加节点时自定义"
    save_keys_to_file
    print_success "密钥生成完成"
}

save_keys_to_file() {
    mkdir -p "$(dirname "${KEY_FILE}")"
    
    cat > "${KEY_FILE}" << EOF
REALITY_PRIVATE="${REALITY_PRIVATE}"
REALITY_PUBLIC="${REALITY_PUBLIC}"
SHORT_ID="${SHORT_ID}"
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
    
    chmod 600 "${LINK_DIR}"/*.txt 2>/dev/null || true
    chmod 700 "${LINK_DIR}" 2>/dev/null || true
    print_success "链接已保存到 ${LINK_DIR}"
}

# ==================== 从配置文件加载节点信息 ====================
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
        
        # 跳过 shadowsocks-in-* (ShadowTLS 的内部组件)
        if [[ "$tag" == "shadowsocks-in-"* ]]; then
            continue
        fi
        
        # 判断协议类型
        local proto="unknown"
        local sni=""
        
        if [[ "$tag" == *"vless-in-"* ]]; then
            proto="Reality"
            sni=$(echo "$inbound" | jq -r '.tls.server_name // ""' 2>/dev/null)
        elif [[ "$tag" == *"hy2-in-"* ]]; then
            proto="Hysteria2"
            sni=$(echo "$inbound" | jq -r '.tls.server_name // ""' 2>/dev/null)
        elif [[ "$tag" == *"shadowtls-in-"* ]]; then
            proto="ShadowTLS v3"
            sni=$(echo "$inbound" | jq -r '.handshake.server // ""' 2>/dev/null)
        elif [[ "$tag" == *"socks-in"* ]]; then
            proto="SOCKS5"
        elif [[ "$tag" == *"vless-tls-in-"* ]]; then
            proto="HTTPS"
            sni=$(echo "$inbound" | jq -r '.tls.server_name // ""' 2>/dev/null)
        elif [[ "$tag" == *"anytls-in-"* ]]; then
            proto="AnyTLS"
            sni=$(echo "$inbound" | jq -r '.tls.server_name // ""' 2>/dev/null)
        elif [[ "$tag" == *"anytls-reality-"* ]]; then
            proto="AnyTLS+REALITY"
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
    
    # 从路由规则中恢复每个节点的默认中转（查找针对该入站且没有域名/IP条件的规则）
    # 注意：路由规则中可能有多个匹配该入站，需要找到最后一条没有域名/IP的规则作为默认
    local route_rules=$(jq -c '.route.rules[]? // empty' "${CONFIG_FILE}" 2>/dev/null)
    if [[ -n "$route_rules" ]]; then
        # 先收集所有入站对应的默认中转（无域名/IP条件）
        declare -A default_relay
        while IFS= read -r rule; do
            # 检查是否包含 inbound 字段
            local has_inbound=$(echo "$rule" | jq -e '.inbound // empty' 2>/dev/null)
            if [[ -z "$has_inbound" ]]; then
                continue
            fi
            # 检查是否包含域名或IP条件（如果包含，则是分流规则，跳过）
            local has_domain=$(echo "$rule" | jq -e '.domain // .domain_suffix // .domain_keyword // .domain_regex // empty' 2>/dev/null)
            local has_ip=$(echo "$rule" | jq -e '.ip_cidr // .ip // empty' 2>/dev/null)
            if [[ -n "$has_domain" || -n "$has_ip" ]]; then
                continue
            fi
            # 这是一个默认路由规则
            local inbound_array=$(echo "$rule" | jq -r '.inbound[]? // empty' 2>/dev/null)
            local outbound=$(echo "$rule" | jq -r '.outbound // ""' 2>/dev/null)
            if [[ -n "$outbound" && "$outbound" != "direct" ]]; then
                while IFS= read -r inbound_tag; do
                    default_relay["$inbound_tag"]="$outbound"
                done <<< "$inbound_array"
            fi
        done <<< "$route_rules"
        
        # 应用到 INBOUND_RELAY_TAGS
        for i in "${!INBOUND_TAGS[@]}"; do
            local tag="${INBOUND_TAGS[$i]}"
            if [[ -n "${default_relay[$tag]}" ]]; then
                INBOUND_RELAY_TAGS[$i]="${default_relay[$tag]}"
            fi
        done
    fi
    
    return 0
}
# ==================== 从配置文件重新生成链接 ====================
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
    
    # 加载密钥文件（安全读取，避免代码注入）
    if [[ -f "${KEY_FILE}" ]]; then
        while IFS='=' read -r key value; do
            [[ "$key" =~ ^#.*$ || -z "$key" ]] && continue
            value="${value#\"}"
            value="${value%\"}"
            case "$key" in
                REALITY_PRIVATE) REALITY_PRIVATE="$value" ;;
                REALITY_PUBLIC) REALITY_PUBLIC="$value" ;;
                SHORT_ID) SHORT_ID="$value" ;;
            esac
        done < "${KEY_FILE}"
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
    
    # 加载 IP 配置
    load_ip_config
    
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
                        
                        [[ -z "$pbk" && -n "${REALITY_PUBLIC}" ]] && pbk="${REALITY_PUBLIC}"
                        [[ -z "$sid" && -n "${SHORT_ID}" ]] && sid="${SHORT_ID}"
                        [[ -z "$sni" ]] && sni="${DEFAULT_SNI}"
                        
                        if [[ -n "$uuid" && -n "$pbk" ]]; then
                            # IPv4 链接
                            local link_ipv4="vless://${uuid}@${SERVER_IP}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=chrome&pbk=${pbk}&sid=${sid}&type=tcp#Reality-${SERVER_IP}"
                            add_link "$link_ipv4" "Reality" "" "${SERVER_IP}" "${port}" "${sni}"
                            
                            # IPv6 链接（如果有）
                            if [[ -n "${SERVER_IPV6}" ]]; then
                                local link_ipv6="vless://${uuid}@[${SERVER_IPV6}]:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=chrome&pbk=${pbk}&sid=${sid}&type=tcp#Reality-[${SERVER_IPV6}]"
                                add_link "$link_ipv6" "Reality" "" "[${SERVER_IPV6}]" "${port}" "${sni}"
                            fi
                        fi
                    else
                        # HTTPS
                        local uuid=$(echo "$inbound" | jq -r '.users[0].uuid // ""' 2>/dev/null)
                        local sni=$(echo "$inbound" | jq -r '.tls.server_name // ""' 2>/dev/null)
                        
                        [[ -z "$sni" ]] && sni="${DEFAULT_SNI}"
                        
                        if [[ -n "$uuid" ]]; then
                            # IPv4 链接
                            local link_ipv4="vless://${uuid}@${SERVER_IP}:${port}?encryption=none&security=tls&sni=${sni}&type=tcp&allowInsecure=1#HTTPS-${SERVER_IP}"
                            add_link "$link_ipv4" "HTTPS" "" "${SERVER_IP}" "${port}" "${sni}"
                            
                            # IPv6 链接（如果有）
                            if [[ -n "${SERVER_IPV6}" ]]; then
                                local link_ipv6="vless://${uuid}@[${SERVER_IPV6}]:${port}?encryption=none&security=tls&sni=${sni}&type=tcp&allowInsecure=1#HTTPS-[${SERVER_IPV6}]"
                                add_link "$link_ipv6" "HTTPS" "" "[${SERVER_IPV6}]" "${port}" "${sni}"
                            fi
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
                        # 端口跳跃
                        local end_port=$(( listen_port + port_range_num - 1 ))
                        port_part="${listen_port}-${end_port}"
                    fi
                    
                    # IPv4 链接
                    local link_ipv4="hysteria2://${password}@${SERVER_IP}:${port_part}?insecure=1&sni=${sni}"
                    if [[ "$obfs_type" == "salamander" && -n "$obfs_password" ]]; then
                        link_ipv4="${link_ipv4}&obfs=salamander&obfs-password=${obfs_password}"
                    fi
                    link_ipv4="${link_ipv4}#Hysteria2-${SERVER_IP}"
                    add_link "$link_ipv4" "Hysteria2" "" "${SERVER_IP}" "${port_part}" "${sni}"
                    
                    # IPv6 链接（如果有）
                    if [[ -n "${SERVER_IPV6}" ]]; then
                        local link_ipv6="hysteria2://${password}@[${SERVER_IPV6}]:${port_part}?insecure=1&sni=${sni}"
                        if [[ "$obfs_type" == "salamander" && -n "$obfs_password" ]]; then
                            link_ipv6="${link_ipv6}&obfs=salamander&obfs-password=${obfs_password}"
                        fi
                        link_ipv6="${link_ipv6}#Hysteria2-[${SERVER_IPV6}]"
                        add_link "$link_ipv6" "Hysteria2" "" "[${SERVER_IPV6}]" "${port_part}" "${sni}"
                    fi
                fi
                ;;
            "socks")
                local username=$(echo "$inbound" | jq -r '.users[0].username // ""' 2>/dev/null)
                local password=$(echo "$inbound" | jq -r '.users[0].password // ""' 2>/dev/null)
                
                # IPv4 链接
                local link_ipv4=""
                if [[ -n "$username" && -n "$password" ]]; then
                    link_ipv4="socks5://${username}:${password}@${SERVER_IP}:${port}#SOCKS5-${SERVER_IP}"
                else
                    link_ipv4="socks5://${SERVER_IP}:${port}#SOCKS5-${SERVER_IP}"
                fi
                add_link "$link_ipv4" "SOCKS5" "" "${SERVER_IP}" "${port}" ""
                
                # IPv6 链接（如果有）
                if [[ -n "${SERVER_IPV6}" ]]; then
                    local link_ipv6=""
                    if [[ -n "$username" && -n "$password" ]]; then
                        link_ipv6="socks5://${username}:${password}@[${SERVER_IPV6}]:${port}#SOCKS5-[${SERVER_IPV6}]"
                    else
                        link_ipv6="socks5://[${SERVER_IPV6}]:${port}#SOCKS5-[${SERVER_IPV6}]"
                    fi
                    add_link "$link_ipv6" "SOCKS5" "" "[${SERVER_IPV6}]" "${port}" ""
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
                        
                        # IPv4 链接
                        local plugin_json_ipv4="{\"version\":\"3\",\"password\":\"${shadowtls_password}\",\"host\":\"${sni}\",\"port\":\"${port}\",\"address\":\"${SERVER_IP}\"}"
                        local plugin_base64_ipv4=$(echo -n "$plugin_json_ipv4" | base64 -w0 | sed 's/+/-/g; s/\//_/g; s/=//g')
                        local link_ipv4="ss://${ss_userinfo}@${SERVER_IP}:${port}?shadow-tls=${plugin_base64_ipv4}#ShadowTLS-${SERVER_IP}"
                        add_link "$link_ipv4" "ShadowTLS v3" "" "${SERVER_IP}" "${port}" "${sni}"
                        
                        # 生成 IPv4 客户端配置文件
                        local client_config_file_ipv4="${LINK_DIR}/shadowtls_client_${port}_ipv4.json"
                        generate_shadowtls_client_config "${client_config_file_ipv4}" "${SERVER_IP}" "${port}" "${sni}" "${shadowtls_password}" "${ss_method}" "${ss_password}"
                        
                        # IPv6 链接（如果有）
                        if [[ -n "${SERVER_IPV6}" ]]; then
                            local plugin_json_ipv6="{\"version\":\"3\",\"password\":\"${shadowtls_password}\",\"host\":\"${sni}\",\"port\":\"${port}\",\"address\":\"${SERVER_IPV6}\"}"
                            local plugin_base64_ipv6=$(echo -n "$plugin_json_ipv6" | base64 -w0 | sed 's/+/-/g; s/\//_/g; s/=//g')
                            local link_ipv6="ss://${ss_userinfo}@[${SERVER_IPV6}]:${port}?shadow-tls=${plugin_base64_ipv6}#ShadowTLS-[${SERVER_IPV6}]"
                            add_link "$link_ipv6" "ShadowTLS v3" "" "[${SERVER_IPV6}]" "${port}" "${sni}"
                            
                            # 生成 IPv6 客户端配置文件
                            local client_config_file_ipv6="${LINK_DIR}/shadowtls_client_${port}_ipv6.json"
                            generate_shadowtls_client_config "${client_config_file_ipv6}" "${SERVER_IPV6}" "${port}" "${sni}" "${shadowtls_password}" "${ss_method}" "${ss_password}"
                        fi
                    fi
                fi
                ;;
            "anytls")
                local password=$(echo "$inbound" | jq -r '.users[0].password // ""' 2>/dev/null)
                local sni=$(echo "$inbound" | jq -r '.tls.server_name // ""' 2>/dev/null)
                local reality_enabled=$(echo "$inbound" | jq -r '.tls.reality.enabled // false' 2>/dev/null)
                
                [[ -z "$sni" ]] && sni="${DEFAULT_SNI}"
                
                if [[ -n "$password" ]]; then
                    if [[ "$reality_enabled" == "true" ]]; then
                        # AnyTLS+REALITY 不生成标准链接，提示使用客户端配置
                        local link_text="[AnyTLS+REALITY] ${SERVER_IP}:${port} (SNI: ${sni})\n请使用 sing-box 客户端配置文件\n----------------------------------------\n\n"
                        ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${link_text}"
                        ANYTLS_LINKS="${ANYTLS_LINKS}${link_text}"
                    else
                        # IPv4 链接
                        local link_ipv4="anytls://${password}@${SERVER_IP}:${port}?security=tls&fp=chrome&insecure=1&sni=${sni}&type=tcp#AnyTLS-${SERVER_IP}"
                        add_link "$link_ipv4" "AnyTLS" "" "${SERVER_IP}" "${port}" "${sni}"
                        
                        # IPv6 链接（如果有）
                        if [[ -n "${SERVER_IPV6}" ]]; then
                            local link_ipv6="anytls://${password}@[${SERVER_IPV6}]:${port}?security=tls&fp=chrome&insecure=1&sni=${sni}&type=tcp#AnyTLS-[${SERVER_IPV6}]"
                            add_link "$link_ipv6" "AnyTLS" "" "[${SERVER_IPV6}]" "${port}" "${sni}"
                        fi
                    fi
                fi
                ;;
        esac
    done
    
    print_success "链接重新生成完成"
    save_links_to_files
}

# ==================== 链接生成辅助函数 ====================
add_link() {
    local link="$1"
    local proto="$2"
    local extra_info="$3"
    local ip="$4"
    local port="$5"
    local sni="$6"
    
    # 生成链接文本
    local line="[${proto}] ${ip}:${port}"
    [[ -n "$sni" ]] && line="${line} (SNI: ${sni})"
    line="${line}\n${link}\n----------------------------------------\n\n"
    
    # 添加到所有链接
    ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}"
    
    # 添加到对应的协议链接
    case "$proto" in
        "Reality") REALITY_LINKS="${REALITY_LINKS}${line}" ;;
        "Hysteria2") HYSTERIA2_LINKS="${HYSTERIA2_LINKS}${line}" ;;
        "SOCKS5") SOCKS5_LINKS="${SOCKS5_LINKS}${line}" ;;
        "ShadowTLS v3") SHADOWTLS_LINKS="${SHADOWTLS_LINKS}${line}" ;;
        "HTTPS") HTTPS_LINKS="${HTTPS_LINKS}${line}" ;;
        "AnyTLS") ANYTLS_LINKS="${ANYTLS_LINKS}${line}" ;;
    esac
}

# ==================== 监听地址获取 ====================
get_listen_address() {
    case "${INBOUND_IP_MODE}" in
        "ipv4")
            echo "0.0.0.0"
            ;;
        "ipv6")
            echo "::"
            ;;
        "dual"|*)
            echo "::"
            ;;
    esac
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
    if [[ -f "${IP_CONFIG_FILE}" ]] && [[ -r "${IP_CONFIG_FILE}" ]]; then
        while IFS='=' read -r key value; do
            # 跳过注释和空行
            [[ "$key" =~ ^#.*$ || -z "$key" ]] && continue
            # 去除值两端的引号
            value="${value#\"}"
            value="${value%\"}"
            case "$key" in
                SERVER_IP) SERVER_IP="$value" ;;
                SERVER_IPV6) SERVER_IPV6="$value" ;;
                INBOUND_IP_MODE) INBOUND_IP_MODE="$value" ;;
                OUTBOUND_IP_MODE) OUTBOUND_IP_MODE="$value" ;;
            esac
        done < "${IP_CONFIG_FILE}"
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

# ==================== 分流规则管理 ====================
save_domain_routes_to_file() {
    mkdir -p "$(dirname "${DOMAIN_ROUTE_FILE}")"
    
    cat > "${DOMAIN_ROUTE_FILE}" << EOF
# Sing-box 分流规则配置文件
# 格式: INBOUND_TAG|MATCH_TYPE|MATCH_VALUE|RELAY_TAG|DESCRIPTION
# MATCH_TYPE: domain_suffix(域名后缀), domain(完整域名), domain_keyword(关键词), ip_cidr(IP/CIDR)
EOF
    
    for route in "${DOMAIN_ROUTES[@]}"; do
        echo "$route" >> "${DOMAIN_ROUTE_FILE}"
    done
}

load_domain_routes_from_file() {
    DOMAIN_ROUTES=()
    
    if [[ ! -f "${DOMAIN_ROUTE_FILE}" ]]; then
        return 0
    fi
    
    while IFS= read -r line; do
        # 跳过注释和空行
        [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
        DOMAIN_ROUTES+=("$line")
    done < "${DOMAIN_ROUTE_FILE}"
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
    local old_ip="${SERVER_IP}"
    local old_ipv6="${SERVER_IPV6}"
    
    local ipv4=""
    local ipv6=""

    for service in "ifconfig.me" "api.ipify.org" "ip.sb"; do
        ipv4=$(curl -s4 --connect-timeout 5 "https://${service}" 2>/dev/null)
        [[ -n "$ipv4" && "$ipv4" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && break
        ipv4=""
    done

    for service in "ifconfig.me" "api6.ipify.org" "ip.sb"; do
        ipv6=$(curl -s6 --connect-timeout 5 "https://${service}" 2>/dev/null)
        [[ -n "$ipv6" && "$ipv6" =~ ^[0-9a-fA-F:]+$ ]] && break
        ipv6=""
    done
    
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
        SERVER_IP=""
        SERVER_IPV6="$ipv6"
        INBOUND_IP_MODE="ipv6"
        [[ -z "$OUTBOUND_IP_MODE" || "$OUTBOUND_IP_MODE" == "dual" ]] && OUTBOUND_IP_MODE="dual"
        print_success "仅 IPv6 网络: ${SERVER_IPV6}"
        print_info "已自动设置入站为 IPv6，出站为双栈模式"
    fi
    
    if [[ -n "$old_ip" && "$old_ip" != "$SERVER_IP" ]]; then
        print_warning "服务器 IPv4 已从 ${old_ip} 变更为 ${SERVER_IP}"
        print_info "建议使用主菜单 [5] 重新生成链接文件"
    fi
    if [[ -n "$old_ipv6" && "$old_ipv6" != "$SERVER_IPV6" ]]; then
        print_warning "服务器 IPv6 已从 ${old_ipv6} 变更为 ${SERVER_IPV6}"
        print_info "建议使用主菜单 [5] 重新生成链接文件"
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

get_port_process() {
    local port="$1"
    if command -v ss &>/dev/null; then
        ss -tulnp 2>/dev/null | grep -E "[:.]${port}$" | awk '{print $NF}'
    elif command -v netstat &>/dev/null; then
        netstat -tulnp 2>/dev/null | grep -E "[:.]${port}$" | awk '{print $NF}'
    fi
}

# 获取随机可用端口
get_random_free_port() {
    local port
    local max_attempts=100
    local attempt=0
    while (( attempt < max_attempts )); do
        port=$((RANDOM % 55536 + 10000))  # 10000-65535
        if ! check_port_in_use "$port"; then
            echo "$port"
            return 0
        fi
        ((attempt++))
    done
    return 1
}

# 从 DEFAULT_SNI1 随机选择 SNI
get_random_sni() {
    local -a _sni_array
    IFS=',' read -ra _sni_array <<< "${DEFAULT_SNI1}"
    if [[ ${#_sni_array[@]} -eq 0 ]]; then
        echo "${DEFAULT_SNI}"
        return
    fi
    echo "${_sni_array[$((RANDOM % ${#_sni_array[@]}))]}"
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
            local proc_info=$(get_port_process "$PORT")
            print_warning "端口 ${PORT} 已被占用"
            [[ -n "$proc_info" ]] && print_info "占用进程: ${proc_info}"
            continue
        fi
        
        break
    done
}
# ==================== Reality 配置 ====================
setup_reality() {
    echo ""
    read_port_with_check 443
    
    echo -e "${YELLOW}请输入SNI域名（建议使用常见HTTPS网站域名）${NC}"
    echo -e "${CYAN}例如: ${DEFAULT_SNI1}${NC}"
    read -p "SNI域名 [${DEFAULT_SNI}]: " SNI
    SNI=${SNI:-${DEFAULT_SNI}}
    
    # 每个节点使用独立UUID
    local NODE_UUID=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid 2>/dev/null)
    if [[ -z "$NODE_UUID" ]]; then
        print_error "UUID 生成失败，请检查系统环境"
        return 1
    fi
    print_info "节点 UUID: ${NODE_UUID}"
    
    print_info "生成配置文件..."
    
    local listen_addr=$(get_listen_address)
    local inbound="{
  \"type\": \"vless\",
  \"tag\": \"vless-in-${PORT}\",
  \"listen\": \"${listen_addr}\",
  \"listen_port\": ${PORT},
  \"users\": [{\"uuid\": \"${NODE_UUID}\", \"flow\": \"xtls-rprx-vision\"}],
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
    
    # 生成 Reality 链接 - 同时支持 IPv4 和 IPv6
    PROTO="Reality"
    EXTRA_INFO="UUID: ${NODE_UUID}\nPublic Key: ${REALITY_PUBLIC}\nShort ID: ${SHORT_ID}\nSNI: ${SNI}"
    
    # 保存新添加节点的链接（只用于显示）
    CURRENT_NEW_LINKS=""
    
    # IPv4 链接
    local link_ipv4="vless://${NODE_UUID}@${SERVER_IP}:${PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=chrome&pbk=${REALITY_PUBLIC}&sid=${SHORT_ID}&type=tcp#Reality-${SERVER_IP}"
    add_link "$link_ipv4" "Reality" "$EXTRA_INFO" "${SERVER_IP}" "${PORT}" "${SNI}"
    LINK="$link_ipv4"  # 默认链接
    
    # 添加到新链接显示
    CURRENT_NEW_LINKS="${CURRENT_NEW_LINKS}[Reality] ${SERVER_IP}:${PORT} (SNI: ${SNI})\n${link_ipv4}\n----------------------------------------\n\n"
    
    # IPv6 链接（如果有）
    if [[ -n "${SERVER_IPV6}" ]]; then
        local link_ipv6="vless://${NODE_UUID}@[${SERVER_IPV6}]:${PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=chrome&pbk=${REALITY_PUBLIC}&sid=${SHORT_ID}&type=tcp#Reality-[${SERVER_IPV6}]"
        add_link "$link_ipv6" "Reality" "$EXTRA_INFO" "[${SERVER_IPV6}]" "${PORT}" "${SNI}"
        CURRENT_NEW_LINKS="${CURRENT_NEW_LINKS}[Reality] [${SERVER_IPV6}]:${PORT} (SNI: ${SNI})\n${link_ipv6}\n----------------------------------------\n\n"
    fi
    
    INBOUND_TAGS+=("vless-in-${PORT}")
    INBOUND_PORTS+=("${PORT}")
    INBOUND_PROTOS+=("${PROTO}")
    INBOUND_SNIS+=("${SNI}")
    INBOUND_RELAY_TAGS+=("direct")
    
    print_success "Reality 配置完成 (SNI: ${SNI})"
    save_links_to_files
}

# ==================== Hysteria2 配置（已升级，含混淆） ====================
setup_hysteria2() {
    echo ""
    read_port_with_check 443
    
    echo -e "${YELLOW}请输入SNI域名（建议使用常见HTTPS网站域名）${NC}"
    echo -e "${CYAN}例如: ${DEFAULT_SNI1}${NC}"
    read -p "SNI域名 [${DEFAULT_SNI}]: " HY2_SNI
    HY2_SNI=${HY2_SNI:-${DEFAULT_SNI}}
    
    # 是否启用 Salamander 混淆
    read -p "是否启用 Salamander 混淆？(y/N): " ENABLE_OBFS
    ENABLE_OBFS=${ENABLE_OBFS:-N}
    OBFS_PASSWORD=""
    if [[ "$ENABLE_OBFS" =~ ^[Yy]$ ]]; then
        read -p "混淆密码 (留空随机生成16位hex): " OBFS_PASSWORD
        if [[ -z "$OBFS_PASSWORD" ]]; then
            OBFS_PASSWORD=$(openssl rand -hex 16)
        fi
        print_info "混淆密码: ${OBFS_PASSWORD}"
    fi
    
    print_info "为 ${HY2_SNI} 生成自签证书..."
    gen_cert_for_sni "${HY2_SNI}"
    
    print_info "生成配置文件..."
    
    # 每个节点使用独立密码
    local NODE_HY2_PASSWORD=$(openssl rand -hex 16)
    print_info "节点密码: ${NODE_HY2_PASSWORD}"
    
    # 构建 obfs 配置
    local obfs_config=""
    if [[ "$ENABLE_OBFS" =~ ^[Yy]$ ]]; then
        obfs_config=",
    \"obfs\": {
      \"type\": \"salamander\",
      \"password\": \"${OBFS_PASSWORD}\"
    }"
    fi
    
    local listen_addr=$(get_listen_address)
    local inbound="{
  \"type\": \"hysteria2\",
  \"tag\": \"hy2-in-${PORT}\",
  \"listen\": \"${listen_addr}\",
  \"listen_port\": ${PORT},
  \"users\": [{\"password\": \"${NODE_HY2_PASSWORD}\"}],
  \"tls\": {
    \"enabled\": true,
    \"alpn\": [\"h3\"],
    \"server_name\": \"${HY2_SNI}\",
    \"certificate_path\": \"${CERT_DIR}/${HY2_SNI}/cert.pem\",
    \"key_path\": \"${CERT_DIR}/${HY2_SNI}/private.key\"
  }${obfs_config}
}"
    
    if [[ -z "$INBOUNDS_JSON" ]]; then
        INBOUNDS_JSON="$inbound"
    else
        INBOUNDS_JSON="${INBOUNDS_JSON},${inbound}"
    fi
    
    PROTO="Hysteria2"
    EXTRA_INFO="密码: ${NODE_HY2_PASSWORD}\n证书: 自签证书(${HY2_SNI})\nSNI: ${HY2_SNI}"
    if [[ "$ENABLE_OBFS" =~ ^[Yy]$ ]]; then
        EXTRA_INFO="${EXTRA_INFO}\nSalamander混淆: 已启用 (密码: ${OBFS_PASSWORD})"
    fi
    
    # 保存新添加节点的链接（只用于显示）
    CURRENT_NEW_LINKS=""
    
    # IPv4 链接
    local link_ipv4="hysteria2://${NODE_HY2_PASSWORD}@${SERVER_IP}:${PORT}?insecure=1&sni=${HY2_SNI}"
    if [[ "$ENABLE_OBFS" =~ ^[Yy]$ ]]; then
        link_ipv4="${link_ipv4}&obfs=salamander&obfs-password=${OBFS_PASSWORD}"
    fi
    link_ipv4="${link_ipv4}#Hysteria2-${SERVER_IP}"
    add_link "$link_ipv4" "Hysteria2" "$EXTRA_INFO" "${SERVER_IP}" "${PORT}" "${HY2_SNI}"
    LINK="$link_ipv4"  # 默认链接
    
    # 添加到新链接显示
    CURRENT_NEW_LINKS="${CURRENT_NEW_LINKS}[Hysteria2] ${SERVER_IP}:${PORT} (SNI: ${HY2_SNI})\n${link_ipv4}\n----------------------------------------\n\n"
    
    # IPv6 链接（如果有）
    if [[ -n "${SERVER_IPV6}" ]]; then
        local link_ipv6="hysteria2://${NODE_HY2_PASSWORD}@[${SERVER_IPV6}]:${PORT}?insecure=1&sni=${HY2_SNI}"
        if [[ "$ENABLE_OBFS" =~ ^[Yy]$ ]]; then
            link_ipv6="${link_ipv6}&obfs=salamander&obfs-password=${OBFS_PASSWORD}"
        fi
        link_ipv6="${link_ipv6}#Hysteria2-[${SERVER_IPV6}]"
        add_link "$link_ipv6" "Hysteria2" "$EXTRA_INFO" "[${SERVER_IPV6}]" "${PORT}" "${HY2_SNI}"
        CURRENT_NEW_LINKS="${CURRENT_NEW_LINKS}[Hysteria2] [${SERVER_IPV6}]:${PORT} (SNI: ${HY2_SNI})\n${link_ipv6}\n----------------------------------------\n\n"
    fi
    
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
    
    # 每个节点使用独立凭据
    local NODE_SOCKS_USER="user_$(openssl rand -hex 4)"
    local NODE_SOCKS_PASS=$(openssl rand -hex 16)
    
    local listen_addr=$(get_listen_address)
    
    if [[ "$ENABLE_AUTH" =~ ^[Yy]$ ]]; then
        local inbound="{
  \"type\": \"socks\",
  \"tag\": \"socks-in-${PORT}\",
  \"listen\": \"${listen_addr}\",
  \"listen_port\": ${PORT},
  \"users\": [{\"username\": \"${NODE_SOCKS_USER}\", \"password\": \"${NODE_SOCKS_PASS}\"}]
}"
        EXTRA_INFO="用户名: ${NODE_SOCKS_USER}\n密码: ${NODE_SOCKS_PASS}"
    else
        local inbound="{
  \"type\": \"socks\",
  \"tag\": \"socks-in-${PORT}\",
  \"listen\": \"${listen_addr}\",
  \"listen_port\": ${PORT}
}"
        EXTRA_INFO="无认证"
    fi
    
    if [[ -z "$INBOUNDS_JSON" ]]; then
        INBOUNDS_JSON="$inbound"
    else
        INBOUNDS_JSON="${INBOUNDS_JSON},${inbound}"
    fi
    
    PROTO="SOCKS5"
    
    # 保存新添加节点的链接（只用于显示）
    CURRENT_NEW_LINKS=""
    
    # IPv4 链接
    local link_ipv4=""
    if [[ "$ENABLE_AUTH" =~ ^[Yy]$ ]]; then
        link_ipv4="socks5://${NODE_SOCKS_USER}:${NODE_SOCKS_PASS}@${SERVER_IP}:${PORT}#SOCKS5-${SERVER_IP}"
    else
        link_ipv4="socks5://${SERVER_IP}:${PORT}#SOCKS5-${SERVER_IP}"
    fi
    add_link "$link_ipv4" "SOCKS5" "$EXTRA_INFO" "${SERVER_IP}" "${PORT}" ""
    LINK="$link_ipv4"  # 默认链接
    
    # 添加到新链接显示
    CURRENT_NEW_LINKS="${CURRENT_NEW_LINKS}[SOCKS5] ${SERVER_IP}:${PORT}\n${link_ipv4}\n----------------------------------------\n\n"
    
    # IPv6 链接（如果有）
    if [[ -n "${SERVER_IPV6}" ]]; then
        local link_ipv6=""
        if [[ "$ENABLE_AUTH" =~ ^[Yy]$ ]]; then
            link_ipv6="socks5://${NODE_SOCKS_USER}:${NODE_SOCKS_PASS}@[${SERVER_IPV6}]:${PORT}#SOCKS5-[${SERVER_IPV6}]"
        else
            link_ipv6="socks5://[${SERVER_IPV6}]:${PORT}#SOCKS5-[${SERVER_IPV6}]"
        fi
        add_link "$link_ipv6" "SOCKS5" "$EXTRA_INFO" "[${SERVER_IPV6}]" "${PORT}" ""
        CURRENT_NEW_LINKS="${CURRENT_NEW_LINKS}[SOCKS5] [${SERVER_IPV6}]:${PORT}\n${link_ipv6}\n----------------------------------------\n\n"
    fi
    
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
    
    echo -e "${YELLOW}请输入SNI域名（建议使用常见HTTPS网站域名）${NC}"
    echo -e "${CYAN}例如: ${DEFAULT_SNI1}${NC}"
    read -p "SNI域名 [${DEFAULT_SNI}]: " SHADOWTLS_SNI
    SHADOWTLS_SNI=${SHADOWTLS_SNI:-${DEFAULT_SNI}}
    
    print_info "生成配置文件..."
    print_warning "ShadowTLS 通过伪装真实域名的TLS握手工作"
    
    # 每个节点使用独立密码
    local NODE_SHADOWTLS_PASSWORD=$(openssl rand -hex 16)
    local NODE_SS_PASSWORD=$(openssl rand -base64 16)
    print_info "ShadowTLS密码: ${NODE_SHADOWTLS_PASSWORD}"
    print_info "Shadowsocks密码: ${NODE_SS_PASSWORD}"
    
    local listen_addr=$(get_listen_address)
    local inbound="{
  \"type\": \"shadowtls\",
  \"tag\": \"shadowtls-in-${PORT}\",
  \"listen\": \"${listen_addr}\",
  \"listen_port\": ${PORT},
  \"version\": 3,
  \"users\": [{\"password\": \"${NODE_SHADOWTLS_PASSWORD}\"}],
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
  \"password\": \"${NODE_SS_PASSWORD}\"
}"
    
    local ss_userinfo=$(echo -n "2022-blake3-aes-128-gcm:${NODE_SS_PASSWORD}" | base64 -w0 | sed 's/+/-/g; s/\//_/g; s/=//g')
    
    if [[ -z "$INBOUNDS_JSON" ]]; then
        INBOUNDS_JSON="$inbound"
    else
        INBOUNDS_JSON="${INBOUNDS_JSON},${inbound}"
    fi
    
    PROTO="ShadowTLS v3"
    EXTRA_INFO="Shadowsocks方法: 2022-blake3-aes-128-gcm\nShadowsocks密码: ${NODE_SS_PASSWORD}\nShadowTLS密码: ${NODE_SHADOWTLS_PASSWORD}\n伪装域名: ${SHADOWTLS_SNI}\n\n${RED}重要: ShadowTLS 不支持链接格式！${NC}\n${YELLOW}请使用客户端配置文件${NC}"
    
    # 保存新添加节点的链接（只用于显示）
    CURRENT_NEW_LINKS=""
    
    # IPv4 链接
    local plugin_json_ipv4="{\"version\":\"3\",\"password\":\"${NODE_SHADOWTLS_PASSWORD}\",\"host\":\"${SHADOWTLS_SNI}\",\"port\":\"${PORT}\",\"address\":\"${SERVER_IP}\"}"
    local plugin_base64_ipv4=$(echo -n "$plugin_json_ipv4" | base64 -w0 | sed 's/+/-/g; s/\//_/g; s/=//g')
    local link_ipv4="ss://${ss_userinfo}@${SERVER_IP}:${PORT}?shadow-tls=${plugin_base64_ipv4}#ShadowTLS-${SERVER_IP}"
    add_link "$link_ipv4" "ShadowTLS v3" "$EXTRA_INFO" "${SERVER_IP}" "${PORT}" "${SHADOWTLS_SNI}"
    LINK="$link_ipv4"  # 默认链接
    
    # 添加到新链接显示
    CURRENT_NEW_LINKS="${CURRENT_NEW_LINKS}[ShadowTLS v3] ${SERVER_IP}:${PORT} (SNI: ${SHADOWTLS_SNI})\n${link_ipv4}\n----------------------------------------\n\n"
    
    # 生成 IPv4 客户端配置文件
    local client_config_file_ipv4="${LINK_DIR}/shadowtls_client_${PORT}_ipv4.json"
    generate_shadowtls_client_config "${client_config_file_ipv4}" "${SERVER_IP}" "${PORT}" "${SHADOWTLS_SNI}" "${NODE_SHADOWTLS_PASSWORD}" "2022-blake3-aes-128-gcm" "${NODE_SS_PASSWORD}"
    
    # IPv6 链接（如果有）
    if [[ -n "${SERVER_IPV6}" ]]; then
        local plugin_json_ipv6="{\"version\":\"3\",\"password\":\"${NODE_SHADOWTLS_PASSWORD}\",\"host\":\"${SHADOWTLS_SNI}\",\"port\":\"${PORT}\",\"address\":\"${SERVER_IPV6}\"}"
        local plugin_base64_ipv6=$(echo -n "$plugin_json_ipv6" | base64 -w0 | sed 's/+/-/g; s/\//_/g; s/=//g')
        local link_ipv6="ss://${ss_userinfo}@[${SERVER_IPV6}]:${PORT}?shadow-tls=${plugin_base64_ipv6}#ShadowTLS-[${SERVER_IPV6}]"
        add_link "$link_ipv6" "ShadowTLS v3" "$EXTRA_INFO" "[${SERVER_IPV6}]" "${PORT}" "${SHADOWTLS_SNI}"
        CURRENT_NEW_LINKS="${CURRENT_NEW_LINKS}[ShadowTLS v3] [${SERVER_IPV6}]:${PORT} (SNI: ${SHADOWTLS_SNI})\n${link_ipv6}\n----------------------------------------\n\n"
        
        # 生成 IPv6 客户端配置文件
        local client_config_file_ipv6="${LINK_DIR}/shadowtls_client_${PORT}_ipv6.json"
        generate_shadowtls_client_config "${client_config_file_ipv6}" "${SERVER_IPV6}" "${PORT}" "${SHADOWTLS_SNI}" "${NODE_SHADOWTLS_PASSWORD}" "2022-blake3-aes-128-gcm" "${NODE_SS_PASSWORD}"
    fi
    
    INBOUND_TAGS+=("shadowtls-in-${PORT}")
    INBOUND_PORTS+=("${PORT}")
    INBOUND_PROTOS+=("${PROTO}")
    INBOUND_SNIS+=("${SHADOWTLS_SNI}")
    INBOUND_RELAY_TAGS+=("direct")
    
    print_success "ShadowTLS v3 配置完成 (SNI: ${SHADOWTLS_SNI})"
    print_info "IPv4 客户端配置文件已保存: ${client_config_file_ipv4}"
    if [[ -n "${SERVER_IPV6}" ]]; then
        print_info "IPv6 客户端配置文件已保存: ${client_config_file_ipv6}"
    fi
    save_links_to_files
}

# ==================== HTTPS 配置 ====================
setup_https() {
    echo ""
    read_port_with_check 443
    
    echo -e "${YELLOW}请输入SNI域名（建议使用常见HTTPS网站域名）${NC}"
    echo -e "${CYAN}例如: ${DEFAULT_SNI1}${NC}"
    read -p "SNI域名 [${DEFAULT_SNI}]: " HTTPS_SNI
    HTTPS_SNI=${HTTPS_SNI:-${DEFAULT_SNI}}
    
    print_info "为 ${HTTPS_SNI} 生成自签证书..."
    gen_cert_for_sni "${HTTPS_SNI}"
    
    # 每个节点使用独立UUID
    local NODE_UUID=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid 2>/dev/null)
    if [[ -z "$NODE_UUID" ]]; then
        print_error "UUID 生成失败，请检查系统环境"
        return 1
    fi
    print_info "节点 UUID: ${NODE_UUID}"
    
    print_info "生成配置文件..."
    
    local listen_addr=$(get_listen_address)
    local inbound="{
  \"type\": \"vless\",
  \"tag\": \"vless-tls-in-${PORT}\",
  \"listen\": \"${listen_addr}\",
  \"listen_port\": ${PORT},
  \"users\": [{\"uuid\": \"${NODE_UUID}\"}],
  \"tls\": {
    \"enabled\": true,
    \"server_name\": \"${HTTPS_SNI}\",
    \"certificate_path\": \"${CERT_DIR}/${HTTPS_SNI}/cert.pem\",
    \"key_path\": \"${CERT_DIR}/${HTTPS_SNI}/private.key\"
  }
}"
    
    if [[ -z "$INBOUNDS_JSON" ]]; then
        INBOUNDS_JSON="$inbound"
    else
        INBOUNDS_JSON="${INBOUNDS_JSON},${inbound}"
    fi
    
    PROTO="HTTPS"
    EXTRA_INFO="UUID: ${NODE_UUID}\n证书: 自签证书(${HTTPS_SNI})\nSNI: ${HTTPS_SNI}"
    
    # 保存新添加节点的链接（只用于显示）
    CURRENT_NEW_LINKS=""
    
    # IPv4 链接
    local link_ipv4="vless://${NODE_UUID}@${SERVER_IP}:${PORT}?encryption=none&security=tls&sni=${HTTPS_SNI}&type=tcp&allowInsecure=1#HTTPS-${SERVER_IP}"
    add_link "$link_ipv4" "HTTPS" "$EXTRA_INFO" "${SERVER_IP}" "${PORT}" "${HTTPS_SNI}"
    LINK="$link_ipv4"  # 默认链接
    
    # 添加到新链接显示
    CURRENT_NEW_LINKS="${CURRENT_NEW_LINKS}[HTTPS] ${SERVER_IP}:${PORT} (SNI: ${HTTPS_SNI})\n${link_ipv4}\n----------------------------------------\n\n"
    
    # IPv6 链接（如果有）
    if [[ -n "${SERVER_IPV6}" ]]; then
        local link_ipv6="vless://${NODE_UUID}@[${SERVER_IPV6}]:${PORT}?encryption=none&security=tls&sni=${HTTPS_SNI}&type=tcp&allowInsecure=1#HTTPS-[${SERVER_IPV6}]"
        add_link "$link_ipv6" "HTTPS" "$EXTRA_INFO" "[${SERVER_IPV6}]" "${PORT}" "${HTTPS_SNI}"
        CURRENT_NEW_LINKS="${CURRENT_NEW_LINKS}[HTTPS] [${SERVER_IPV6}]:${PORT} (SNI: ${HTTPS_SNI})\n${link_ipv6}\n----------------------------------------\n\n"
    fi
    
    INBOUND_TAGS+=("vless-tls-in-${PORT}")
    INBOUND_PORTS+=("${PORT}")
    INBOUND_PROTOS+=("${PROTO}")
    INBOUND_SNIS+=("${HTTPS_SNI}")
    INBOUND_RELAY_TAGS+=("direct")
    
    print_success "HTTPS 配置完成 (SNI: ${HTTPS_SNI})"
    save_links_to_files
}

# ==================== AnyTLS 配置（支持内嵌 REALITY，修正版） ====================
setup_anytls() {
    echo ""
    read_port_with_check 443

    echo -e "${YELLOW}是否启用 REALITY 伪装？(y/N)${NC}"
    echo -e "${CYAN}启用后，服务端使用 AnyTLS+REALITY，客户端需使用 sing-box 并导入 JSON 配置${NC}"
    read -p "启用 REALITY? [y/N]: " ENABLE_REALITY
    ENABLE_REALITY=${ENABLE_REALITY:-N}

    echo -e "${YELLOW}请输入 SNI 域名（用于 TLS 及 REALITY handshake）${NC}"
    echo -e "${CYAN}例如: ${DEFAULT_SNI1}${NC}"
    read -p "SNI 域名 [${DEFAULT_SNI}]: " ANYTLS_SNI
    ANYTLS_SNI=${ANYTLS_SNI:-${DEFAULT_SNI}}

    # 每个节点使用独立密码
    local NODE_ANYTLS_PASSWORD=$(openssl rand -hex 16)
    print_info "节点密码: ${NODE_ANYTLS_PASSWORD}"

    # 如果启用 REALITY，确保 REALITY 密钥对存在
    if [[ "$ENABLE_REALITY" =~ ^[Yy]$ ]]; then
        if [[ -z "$REALITY_PRIVATE" ]]; then
            KEYS=$(${INSTALL_DIR}/sing-box generate reality-keypair 2>/dev/null)
            REALITY_PRIVATE=$(echo "$KEYS" | grep "PrivateKey" | awk '{print $2}')
            REALITY_PUBLIC=$(echo "$KEYS" | grep "PublicKey" | awk '{print $2}')
            SHORT_ID=$(openssl rand -hex 8)
            save_keys_to_file
        fi
        print_info "REALITY 公钥: ${REALITY_PUBLIC}"
        print_info "Short ID: ${SHORT_ID}"
    else
        # 纯 AnyTLS 需要自签证书
        gen_cert_for_sni "${ANYTLS_SNI}"
        # 询问是否允许不安全连接
        echo -e "${YELLOW}是否允许跳过证书验证（insecure）？${NC}"
        echo -e "${CYAN}允许可以简化客户端配置，但会降低安全性（中间人攻击风险）${NC}"
        read -p "允许 insecure? [y/N]: " ALLOW_INSECURE
        ALLOW_INSECURE=${ALLOW_INSECURE:-N}
    fi

    # 询问 uTLS 指纹（可选）
    echo -e "${YELLOW}请输入 uTLS 指纹（默认 chrome，可选: firefox, safari, ios, android）${NC}"
    read -p "指纹 [chrome]: " UTLS_FINGERPRINT
    UTLS_FINGERPRINT=${UTLS_FINGERPRINT:-chrome}

    # 构建 padding_scheme（默认启用随机填充）
    local padding_config="[
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

    local listen_addr=$(get_listen_address)
    local inbound=""
    local PROTO=""
    local EXTRA_INFO=""
    local LINK=""
    local CLIENT_JSON_PATH=""

    if [[ "$ENABLE_REALITY" =~ ^[Yy]$ ]]; then
        # AnyTLS + REALITY 入站（无需证书）
        inbound="{
  \"type\": \"anytls\",
  \"tag\": \"anytls-reality-${PORT}\",
  \"listen\": \"${listen_addr}\",
  \"listen_port\": ${PORT},
  \"users\": [{\"password\": \"${NODE_ANYTLS_PASSWORD}\"}],
  \"padding_scheme\": ${padding_config},
  \"tls\": {
    \"enabled\": true,
    \"server_name\": \"${ANYTLS_SNI}\",
    \"reality\": {
      \"enabled\": true,
      \"handshake\": {
        \"server\": \"${ANYTLS_SNI}\",
        \"server_port\": 443
      },
      \"private_key\": \"${REALITY_PRIVATE}\",
      \"short_id\": [\"${SHORT_ID}\"]
    }
  }
}"
        PROTO="AnyTLS+REALITY"
        EXTRA_INFO="密码: ${NODE_ANYTLS_PASSWORD}\nREALITY 公钥: ${REALITY_PUBLIC}\nShort ID: ${SHORT_ID}\nSNI: ${ANYTLS_SNI}"

        # 生成客户端 JSON 配置文件（sing-box 格式），并根据系统选择 TUN 栈
        local tun_stack="system"
        if [[ "$OSTYPE" == "darwin"* ]] || [[ "$OSTYPE" == "msys"* ]] || [[ "$OSTYPE" == "cygwin"* ]]; then
            tun_stack="gvisor"
        fi
        CLIENT_JSON_PATH="${LINK_DIR}/anytls_reality_client_${PORT}.json"
        cat > "${CLIENT_JSON_PATH}" << EOF
{
  "log": { "level": "info" },
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "interface_name": "sing-box0",
      "address": ["172.19.0.1/30", "fd00::1/126"],
      "auto_route": true,
      "stack": "${tun_stack}"
    }
  ],
  "outbounds": [
    {
      "type": "anytls",
      "tag": "AnyTLS+REALITY",
      "server": "${SERVER_IP}",
      "server_port": ${PORT},
      "password": "${NODE_ANYTLS_PASSWORD}",
      "tls": {
        "enabled": true,
        "server_name": "${ANYTLS_SNI}",
        "utls": { "enabled": true, "fingerprint": "${UTLS_FINGERPRINT}" },
        "reality": {
          "enabled": true,
          "public_key": "${REALITY_PUBLIC}",
          "short_id": "${SHORT_ID}"
        }
      }
    },
    { "type": "direct", "tag": "direct" },
    { "type": "block", "tag": "block" }
  ],
  "route": {
    "final": "AnyTLS+REALITY",
    "auto_detect_interface": true
  }
}
EOF
        chmod 644 "${CLIENT_JSON_PATH}"
        LINK="请使用 sing-box 客户端，配置文件已保存到: ${CLIENT_JSON_PATH}"
    else
        # 纯 AnyTLS 入站（需要证书）
        local insecure_bool="false"
        if [[ "$ALLOW_INSECURE" =~ ^[Yy]$ ]]; then
            insecure_bool="true"
        fi
        inbound="{
  \"type\": \"anytls\",
  \"tag\": \"anytls-in-${PORT}\",
  \"listen\": \"${listen_addr}\",
  \"listen_port\": ${PORT},
  \"users\": [{\"password\": \"${NODE_ANYTLS_PASSWORD}\"}],
  \"padding_scheme\": ${padding_config},
  \"tls\": {
    \"enabled\": true,
    \"server_name\": \"${ANYTLS_SNI}\",
    \"certificate_path\": \"${CERT_DIR}/${ANYTLS_SNI}/cert.pem\",
    \"key_path\": \"${CERT_DIR}/${ANYTLS_SNI}/private.key\"
  }
}"
        PROTO="AnyTLS"
        EXTRA_INFO="密码: ${NODE_ANYTLS_PASSWORD}\n证书: 自签证书 (${ANYTLS_SNI})"
        # 生成 anytls:// 链接，insecure 根据用户选择
        LINK="anytls://${NODE_ANYTLS_PASSWORD}@${SERVER_IP}:${PORT}?security=tls&fp=${UTLS_FINGERPRINT}&insecure=${insecure_bool}&sni=${ANYTLS_SNI}&type=tcp#AnyTLS-${SERVER_IP}"
    fi

    # 并入全局 inbound JSON
    if [[ -z "$INBOUNDS_JSON" ]]; then
        INBOUNDS_JSON="$inbound"
    else
        INBOUNDS_JSON="${INBOUNDS_JSON},${inbound}"
    fi

    # 记录节点信息
    if [[ "$ENABLE_REALITY" =~ ^[Yy]$ ]]; then
        INBOUND_TAGS+=("anytls-reality-${PORT}")
    else
        INBOUND_TAGS+=("anytls-in-${PORT}")
    fi
    INBOUND_PORTS+=("${PORT}")
    INBOUND_PROTOS+=("${PROTO}")
    INBOUND_SNIS+=("${ANYTLS_SNI}")
    INBOUND_RELAY_TAGS+=("direct")

    # 显示新添加节点的信息（不再调用 add_link 传入无效链接）
    CURRENT_NEW_LINKS=""
    if [[ "$ENABLE_REALITY" =~ ^[Yy]$ ]]; then
        CURRENT_NEW_LINKS="${CURRENT_NEW_LINKS}[${PROTO}] ${SERVER_IP}:${PORT} (SNI: ${ANYTLS_SNI})\n客户端配置文件: ${CLIENT_JSON_PATH}\n----------------------------------------\n\n"
        # 不调用 add_link，因为 JSON 不是标准 URI
    else
        CURRENT_NEW_LINKS="${CURRENT_NEW_LINKS}[${PROTO}] ${SERVER_IP}:${PORT} (SNI: ${ANYTLS_SNI})\n${LINK}\n----------------------------------------\n\n"
        add_link "$LINK" "${PROTO}" "$EXTRA_INFO" "${SERVER_IP}" "${PORT}" "${ANYTLS_SNI}"
    fi

    print_success "AnyTLS 节点添加完成 (REALITY: ${ENABLE_REALITY})"
    if [[ "$ENABLE_REALITY" =~ ^[Yy]$ ]]; then
        echo -e "${CYAN}客户端配置 JSON 已保存到: ${CLIENT_JSON_PATH}${NC}"
        echo -e "${CYAN}请使用 sing-box 客户端运行: sing-box run -c ${CLIENT_JSON_PATH}${NC}"
    fi
    save_links_to_files
}
# ==================== 服务器地址解析（兼容 IPv6） ====================
# 用法: parse_server_port <server:port字符串>
# 输出: 两行 —— 第一行 server，第二行 port
# 支持: 1.2.3.4:443 / [2a0f:1cc6:b120::12]:443 / example.com:443
parse_server_port() {
    local input="$1"
    # 清理尾部 / # 等杂质
    input="${input%%/*}"
    input="${input%%#*}"
    if [[ "$input" =~ ^\[([^\]]+)\]:([0-9]+) ]]; then
        # IPv6 格式: [addr]:port
        echo "${BASH_REMATCH[1]}"
        echo "${BASH_REMATCH[2]}"
    else
        # IPv4 / 域名格式: addr:port
        echo "${input%:*}"
        echo "${input##*:}"
    fi
}

# ==================== 中转链接解析 ====================
parse_socks_link() {
    local link="$1"
    local custom_desc="$2"
    
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
        local _sp=($(parse_server_port "$server_port"))
        local server="${_sp[0]}"
        local port="${_sp[1]}"

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
        if [[ -n "$custom_desc" ]]; then
            relay_desc="$custom_desc"
        else
            relay_desc="SOCKS5 ${server}:${port} (认证)"
        fi
    else
        local _sp=($(parse_server_port "$data"))
        local server="${_sp[0]}"
        local port="${_sp[1]}"
        
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
        if [[ -n "$custom_desc" ]]; then
            relay_desc="$custom_desc"
        else
            relay_desc="SOCKS5 ${server}:${port}"
        fi
    fi
    
    RELAY_TAGS+=("$tag")
    RELAY_JSONS+=("$relay_json")
    RELAY_DESCS+=("$relay_desc")
    
    save_relays_to_file
    print_success "SOCKS5 中转已添加: ${relay_desc}"
}

parse_http_link() {
    local link="$1"
    local custom_desc="$2"
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
        local server_port=$(echo "$data" | cut -d'@' -f2 | cut -d'/' -f1 | cut -d'#' -f1 | cut -d'?' -f1)
        local _sp=($(parse_server_port "$server_port"))
        local server="${_sp[0]}"
        local port="${_sp[1]}"
        
        relay_json="{
  \"type\": \"http\",
  \"tag\": \"${tag}\",
  \"server\": \"${server}\",
  \"server_port\": ${port},
  \"username\": \"${username}\",
  \"password\": \"${password}\",
  \"tls\": {\"enabled\": ${tls}}
}"
        if [[ -n "$custom_desc" ]]; then
            relay_desc="$custom_desc"
        else
            relay_desc="${protocol^^} ${server}:${port} (认证)"
        fi
    else
        local server_port=$(echo "$data" | cut -d'/' -f1 | cut -d'#' -f1 | cut -d'?' -f1)
        local _sp=($(parse_server_port "$server_port"))
        local server="${_sp[0]}"
        local port="${_sp[1]}"
        
        relay_json="{
  \"type\": \"http\",
  \"tag\": \"${tag}\",
  \"server\": \"${server}\",
  \"server_port\": ${port},
  \"tls\": {\"enabled\": ${tls}}
}"
        if [[ -n "$custom_desc" ]]; then
            relay_desc="$custom_desc"
        else
            relay_desc="${protocol^^} ${server}:${port}"
        fi
    fi
    
    RELAY_TAGS+=("$tag")
    RELAY_JSONS+=("$relay_json")
    RELAY_DESCS+=("$relay_desc")
    
    save_relays_to_file
    print_success "HTTP(S) 中转已添加: ${relay_desc}"
}

parse_ss_link() {
    local link="$1"
    local custom_desc="$2"
    local data=$(echo "$link" | sed 's|ss://||' | cut -d'#' -f1)
    
    if [[ "$data" =~ @ ]]; then
        local userinfo=$(echo "$data" | cut -d'@' -f1)
        local server_port=$(echo "$data" | cut -d'@' -f2 | cut -d'?' -f1)
        local _sp=($(parse_server_port "$server_port"))
        local server="${_sp[0]}"
        local port="${_sp[1]}"
        
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
        local relay_desc
        if [[ -n "$custom_desc" ]]; then
            relay_desc="$custom_desc"
        else
            relay_desc="Shadowsocks ${server}:${port}"
        fi
        
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
    local custom_desc="$2"
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
    local relay_desc
    if [[ -n "$custom_desc" ]]; then
        relay_desc="$custom_desc"
    else
        relay_desc="VMess ${server}:${port}"
    fi
    
    RELAY_TAGS+=("$tag")
    RELAY_JSONS+=("$relay_json")
    RELAY_DESCS+=("$relay_desc")
    
    save_relays_to_file
    print_success "VMess 中转已添加: ${relay_desc}"
}

parse_vless_link() {
    local link="$1"
    local custom_desc="$2"
    local data=$(echo "$link" | sed 's|vless://||')
    local uuid=$(echo "$data" | cut -d'@' -f1)
    local server_port_params=$(echo "$data" | cut -d'@' -f2)
    local server_port_part=$(echo "$server_port_params" | cut -d'?' -f1 | cut -d'#' -f1)
    local _sp=($(parse_server_port "$server_port_part"))
    local server="${_sp[0]}"
    local port="${_sp[1]}"
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        print_error "端口无效: ${port}"
        return 1
    fi

    local params=$(echo "$server_port_params" | grep -o '?.*' | sed 's|?||' | cut -d'#' -f1)

    local security="none"
    local sni=""
    local flow=""
    local pbk=""
    local sid=""
    local encryption="none"

    if [[ -n "$params" ]]; then
        IFS='&' read -ra param_pairs <<< "$params"
        for pair in "${param_pairs[@]}"; do
            key="${pair%%=*}"
            value="${pair#*=}"
            case "$key" in
                security) security="$value" ;;
                sni) sni="$value" ;;
                flow) flow="$value" ;;
                pbk) pbk="$value" ;;
                sid) sid="$value" ;;
                encryption) encryption="$value" ;;
            esac
        done
    fi

    local tls_config=""
    local reality_config=""
    if [[ "$security" == "tls" ]]; then
        tls_config=",
  \"tls\": {
    \"enabled\": true,
    \"server_name\": \"${sni}\",
    \"utls\": {\"enabled\": true, \"fingerprint\": \"chrome\"}
  }"
    elif [[ "$security" == "reality" ]]; then
        if [[ -z "$pbk" ]]; then
            print_error "REALITY 链接缺少公钥 (pbk)"
            return 1
        fi
        reality_config=",
  \"tls\": {
    \"enabled\": true,
    \"server_name\": \"${sni}\",
    \"utls\": {\"enabled\": true, \"fingerprint\": \"chrome\"},
    \"reality\": {
      \"enabled\": true,
      \"public_key\": \"${pbk}\",
      \"short_id\": \"${sid}\"
    }
  }"
    fi

    local flow_config=""
    [[ -n "$flow" ]] && flow_config=",
  \"flow\": \"${flow}\""

    local encryption_config=""
    [[ "$encryption" != "none" ]] && encryption_config=",
  \"encryption\": \"${encryption}\""

    local tag="relay-vless-${#RELAY_TAGS[@]}"
    local relay_json="{
  \"type\": \"vless\",
  \"tag\": \"${tag}\",
  \"server\": \"${server}\",
  \"server_port\": ${port},
  \"uuid\": \"${uuid}\"${encryption_config}${flow_config}${tls_config}${reality_config}
}"

    local relay_desc
    if [[ -n "$custom_desc" ]]; then
        relay_desc="$custom_desc"
    else
        if [[ "$security" == "reality" ]]; then
            relay_desc="VLESS+REALITY ${server}:${port} (SNI: ${sni})"
        else
            relay_desc="VLESS ${server}:${port}"
        fi
    fi

    RELAY_TAGS+=("$tag")
    RELAY_JSONS+=("$relay_json")
    RELAY_DESCS+=("$relay_desc")

    save_relays_to_file
    print_success "VLESS 中转已添加: ${relay_desc}"
}

parse_trojan_link() {
    local link="$1"
    local custom_desc="$2"
    local data=$(echo "$link" | sed 's|trojan://||')
    local password=$(echo "$data" | cut -d'@' -f1)
    local server_port_params=$(echo "$data" | cut -d'@' -f2)
    local server_port_part=$(echo "$server_port_params" | cut -d'?' -f1 | cut -d'#' -f1)
    local _sp=($(parse_server_port "$server_port_part"))
    local server="${_sp[0]}"
    local port="${_sp[1]}"

    local params=$(echo "$server_port_params" | grep -o '?.*' | sed 's|?||' | cut -d'#' -f1)
    
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
    local relay_desc
    if [[ -n "$custom_desc" ]]; then
        relay_desc="$custom_desc"
    else
        relay_desc="Trojan ${server}:${port}"
    fi
    
    RELAY_TAGS+=("$tag")
    RELAY_JSONS+=("$relay_json")
    RELAY_DESCS+=("$relay_desc")
    
    save_relays_to_file
    print_success "Trojan 中转已添加: ${relay_desc}"
}

parse_hysteria2_link() {
    local link="$1"
    local custom_desc="$2"

    # 去除协议前缀 (hy2:// 或 hysteria2://)
    local data="${link#*://}"
    # 提取密码 (第一个 @ 之前)
    local userinfo="${data%%@*}"
    local rest="${data#*@}"
    # 提取服务器和端口
    local server_port_part=$(echo "$rest" | cut -d'?' -f1 | cut -d'#' -f1 | sed 's|/$||')
    local _sp=($(parse_server_port "$server_port_part"))
    local server="${_sp[0]}"
    local port="${_sp[1]}"
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        print_error "端口无效: ${port}"
        return 1
    fi

    # 提取参数部分
    local params=""
    if [[ "$rest" == *"?"* ]]; then
        params="${rest#*\?}"
        params="${params%%#*}"  # 去除可能的 # 备注
    fi

    # 默认值
    local password="$userinfo"
    local sni=""
    local insecure="false"
    local obfs_type=""
    local obfs_password=""

    # 解析参数
    if [[ -n "$params" ]]; then
        # 按 & 分割
        IFS='&' read -ra param_pairs <<< "$params"
        for pair in "${param_pairs[@]}"; do
            key="${pair%%=*}"
            value="${pair#*=}"
            case "$key" in
                sni) sni="$value" ;;
                insecure) insecure="$value" ;;
                obfs) obfs_type="$value" ;;
                obfs-password) obfs_password="$value" ;;
            esac
        done
    fi

    # 转换 insecure 为布尔值
    local insecure_bool="false"
    [[ "$insecure" == "1" || "$insecure" == "true" ]] && insecure_bool="true"

    # 构建 tls 配置
    local tls_config="{
    \"enabled\": true,
    \"server_name\": \"${sni}\",
    \"insecure\": ${insecure_bool}
  }"
    local obfs_config=""
    if [[ "$obfs_type" == "salamander" && -n "$obfs_password" ]]; then
        obfs_config=",
  \"obfs\": {
    \"type\": \"salamander\",
    \"password\": \"${obfs_password}\"
  }"
    fi

    local tag="relay-hysteria2-${#RELAY_TAGS[@]}"
    local relay_json="{
  \"type\": \"hysteria2\",
  \"tag\": \"${tag}\",
  \"server\": \"${server}\",
  \"server_port\": ${port},
  \"password\": \"${password}\",
  \"tls\": ${tls_config}${obfs_config}
}"

    local relay_desc
    if [[ -n "$custom_desc" ]]; then
        relay_desc="$custom_desc"
    else
        relay_desc="Hysteria2 ${server}:${port} (SNI: ${sni})"
    fi

    RELAY_TAGS+=("$tag")
    RELAY_JSONS+=("$relay_json")
    RELAY_DESCS+=("$relay_desc")

    save_relays_to_file
    print_success "Hysteria2 中转已添加: ${relay_desc}"
}

parse_anytls_link() {
    local link="$1"
    local custom_desc="$2"
    local data=$(echo "$link" | sed 's|anytls://||')
    local userinfo=$(echo "$data" | cut -d'@' -f1)
    local server_port_params=$(echo "$data" | cut -d'@' -f2)
    local server_port_part=$(echo "$server_port_params" | cut -d'?' -f1 | cut -d'#' -f1)
    local _sp=($(parse_server_port "$server_port_part"))
    local server="${_sp[0]}"
    local port="${_sp[1]}"
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        print_error "端口无效: ${port}"
        return 1
    fi

    local params=$(echo "$server_port_params" | grep -o '?.*' | sed 's|?||' | cut -d'#' -f1)
    local password="$userinfo"
    local sni=""
    local insecure="false"

    if [[ -n "$params" ]]; then
        IFS='&' read -ra param_pairs <<< "$params"
        for pair in "${param_pairs[@]}"; do
            key="${pair%%=*}"
            value="${pair#*=}"
            case "$key" in
                sni) sni="$value" ;;
                insecure) insecure="$value" ;;
            esac
        done
    fi

    # 转换为布尔值
    local insecure_bool="false"
    [[ "$insecure" == "1" || "$insecure" == "true" ]] && insecure_bool="true"

    local tag="relay-anytls-${#RELAY_TAGS[@]}"
    local relay_json="{
  \"type\": \"anytls\",
  \"tag\": \"${tag}\",
  \"server\": \"${server}\",
  \"server_port\": ${port},
  \"password\": \"${password}\",
  \"tls\": {
    \"enabled\": true,
    \"server_name\": \"${sni}\",
    \"insecure\": ${insecure_bool}
  }
}"

    local relay_desc
    if [[ -n "$custom_desc" ]]; then
        relay_desc="$custom_desc"
    else
        relay_desc="AnyTLS ${server}:${port} (SNI: ${sni})"
    fi

    RELAY_TAGS+=("$tag")
    RELAY_JSONS+=("$relay_json")
    RELAY_DESCS+=("$relay_desc")

    save_relays_to_file
    print_success "AnyTLS 中转已添加: ${relay_desc}"
}

setup_relay() {
    # 加载中转配置和分流规则
    load_relays_from_file
    load_domain_routes_from_file
    
    while true; do
        echo ""
        menu_header "中转配置菜单"
        
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
        echo -e "  ${GREEN}[4]${NC} 域名分流配置"
        echo -e "  ${GREEN}[5]${NC} 修改中转链接"
        echo -e "  ${GREEN}[0]${NC} 返回主菜单"
        echo ""
        read -p "请选择 [0-5]: " r_choice
        
        case $r_choice in
            1)
                echo ""
                menu_header "支持的中转协议格式"
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
                echo -e "${GREEN}7. Hysteria2${NC}"
                echo -e "   ${YELLOW}格式:${NC} hysteria2://密码@服务器:端口?参数"
                echo -e "   ${CYAN}示例:${NC}"
                echo -e "     hysteria2://password@1.2.3.4:443?insecure=1&sni=example.com&obfs=salamander&obfs-password=xxx"
                echo ""
                echo -e "${GREEN}8. AnyTLS${NC}"
                echo -e "   ${YELLOW}格式:${NC} anytls://密码@服务器:端口?参数"
                echo -e "   ${CYAN}示例:${NC}"
                echo -e "     anytls://password@1.2.3.4:443?insecure=1&sni=example.com"
                echo ""
                echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                echo -e "${YELLOW}提示:${NC} 直接粘贴完整的节点分享链接即可，脚本会自动识别协议类型"
                echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                echo ""
                read -p "粘贴中转链接: " RELAY_LINK
                
                if [[ -z "$RELAY_LINK" ]]; then
                    print_warning "未提供链接，中转配置保持不变"
                else
                    echo ""
                    read -p "请输入此节点的描述信息 (如：香港-电信-1x 或 日本-软银-2x，留空则自动生成): " custom_desc
                    
                    if [[ "$RELAY_LINK" =~ ^socks ]]; then
                        parse_socks_link "$RELAY_LINK" "$custom_desc"
                    elif [[ "$RELAY_LINK" =~ ^https? ]]; then
                        parse_http_link "$RELAY_LINK" "$custom_desc"
                    elif [[ "$RELAY_LINK" =~ ^ss:// ]]; then
                        parse_ss_link "$RELAY_LINK" "$custom_desc"
                    elif [[ "$RELAY_LINK" =~ ^vmess:// ]]; then
                        parse_vmess_link "$RELAY_LINK" "$custom_desc"
                    elif [[ "$RELAY_LINK" =~ ^vless:// ]]; then
                        parse_vless_link "$RELAY_LINK" "$custom_desc"
                    elif [[ "$RELAY_LINK" =~ ^trojan:// ]]; then
                        parse_trojan_link "$RELAY_LINK" "$custom_desc"
                    elif [[ "$RELAY_LINK" =~ ^(hy2|hysteria2):// ]]; then
                        parse_hysteria2_link "$RELAY_LINK" "$custom_desc"
                    elif [[ "$RELAY_LINK" =~ ^anytls:// ]]; then
                        parse_anytls_link "$RELAY_LINK" "$custom_desc"
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
                    if confirm "确认删除全部中转? (y/N): "; then
                        RELAY_TAGS=()
                        RELAY_JSONS=()
                        RELAY_DESCS=()
                        rm -f "${RELAY_FILE}"
                        
                        # 将所有节点设置为直连
                        for i in "${!INBOUND_RELAY_TAGS[@]}"; do
                            INBOUND_RELAY_TAGS[$i]="direct"
                        done
                        
                        # 同时删除所有相关的分流规则
                        DOMAIN_ROUTES=()
                        rm -f "${DOMAIN_ROUTE_FILE}"
                        
                        print_success "已删除全部中转配置和相关分流规则"
                        
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
                    if confirm "确认删除中转: ${del_desc}? (y/N): "; then
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
                        
                        # 同时删除所有相关的分流规则
                        local new_routes=()
                        for route in "${DOMAIN_ROUTES[@]}"; do
                            IFS='|' read -r in_tag match_type match_val relay_tag desc <<< "$route"
                            if [[ "$relay_tag" != "$del_tag" ]]; then
                                new_routes+=("$route")
                            fi
                        done
                        DOMAIN_ROUTES=("${new_routes[@]}")
                        save_domain_routes_to_file
                        
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
            4)
                domain_route_menu
                ;;
            5)
                if [[ ${#RELAY_TAGS[@]} -eq 0 ]]; then
                    print_warning "当前没有中转链接"
                    continue
                fi
                
                echo ""
                echo -e "${CYAN}修改中转链接:${NC}"
                for i in "${!RELAY_TAGS[@]}"; do
                    idx=$((i+1))
                    echo -e "  ${GREEN}[${idx}]${NC} ${RELAY_DESCS[$i]}"
                done
                echo ""
                read -p "请选择要修改的中转 (输入 -1 取消): " edit_idx
                
                if [[ "$edit_idx" == "-1" ]]; then
                    continue
                fi
                
                if ! [[ "$edit_idx" =~ ^[0-9]+$ ]] || (( edit_idx < 1 || edit_idx > ${#RELAY_TAGS[@]} )); then
                    print_error "无效选择"
                    continue
                fi
                
                local e=$((edit_idx-1))
                local old_tag="${RELAY_TAGS[$e]}"
                local old_desc="${RELAY_DESCS[$e]}"
                
                echo ""
                echo -e "${YELLOW}当前中转: ${old_desc}${NC}"
                echo -e "${CYAN}请输入新的中转链接 (保留原tag，分流和中转配置不受影响):${NC}"
                echo ""
                read -p "粘贴新的中转链接: " NEW_RELAY_LINK
                
                if [[ -z "$NEW_RELAY_LINK" ]]; then
                    print_warning "未提供链接，修改取消"
                    continue
                fi
                
                echo ""
                read -p "请输入新的描述信息 (留空则自动生成): " new_custom_desc
                
                # 临时保存当前数组状态（解析失败时恢复）
                local saved_tags=("${RELAY_TAGS[@]}")
                local saved_jsons=("${RELAY_JSONS[@]}")
                local saved_descs=("${RELAY_DESCS[@]}")
                
                # 临时清空数组，解析新链接以获取JSON结构
                local tmp_tags=("${RELAY_TAGS[@]}")
                local tmp_jsons=("${RELAY_JSONS[@]}")
                local tmp_descs=("${RELAY_DESCS[@]}")
                RELAY_TAGS=()
                RELAY_JSONS=()
                RELAY_DESCS=()
                
                # 解析新链接
                local parse_ok=0
                if [[ "$NEW_RELAY_LINK" =~ ^socks ]]; then
                    parse_socks_link "$NEW_RELAY_LINK" "$new_custom_desc" && parse_ok=1
                elif [[ "$NEW_RELAY_LINK" =~ ^https? ]]; then
                    parse_http_link "$NEW_RELAY_LINK" "$new_custom_desc" && parse_ok=1
                elif [[ "$NEW_RELAY_LINK" =~ ^ss:// ]]; then
                    parse_ss_link "$NEW_RELAY_LINK" "$new_custom_desc" && parse_ok=1
                elif [[ "$NEW_RELAY_LINK" =~ ^vmess:// ]]; then
                    parse_vmess_link "$NEW_RELAY_LINK" "$new_custom_desc" && parse_ok=1
                elif [[ "$NEW_RELAY_LINK" =~ ^vless:// ]]; then
                    parse_vless_link "$NEW_RELAY_LINK" "$new_custom_desc" && parse_ok=1
                elif [[ "$NEW_RELAY_LINK" =~ ^trojan:// ]]; then
                    parse_trojan_link "$NEW_RELAY_LINK" "$new_custom_desc" && parse_ok=1
                elif [[ "$NEW_RELAY_LINK" =~ ^(hy2|hysteria2):// ]]; then
                    parse_hysteria2_link "$NEW_RELAY_LINK" "$new_custom_desc" && parse_ok=1
                elif [[ "$NEW_RELAY_LINK" =~ ^anytls:// ]]; then
                    parse_anytls_link "$NEW_RELAY_LINK" "$new_custom_desc" && parse_ok=1
                else
                    print_error "不支持的链接格式"
                fi
                
                if [[ $parse_ok -eq 1 ]]; then
                    # 从解析结果中提取新JSON和新描述
                    local new_json="${RELAY_JSONS[0]}"
                    local new_desc="${RELAY_DESCS[0]}"
                    
                    # 将新JSON中的tag替换为原tag
                    local new_tag="${RELAY_TAGS[0]}"
                    new_json=$(echo "$new_json" | sed "s/\"${new_tag}\"/\"${old_tag}\"/g")
                    
                    # 恢复原数组，替换指定位置
                    RELAY_TAGS=("${tmp_tags[@]}")
                    RELAY_JSONS=("${tmp_jsons[@]}")
                    RELAY_DESCS=("${tmp_descs[@]}")
                    
                    RELAY_JSONS[$e]="$new_json"
                    RELAY_DESCS[$e]="$new_desc"
                    
                    save_relays_to_file
                    print_success "中转已修改: ${old_desc} → ${new_desc}"
                    
                    # 重新生成配置
                    if [[ -n "$INBOUNDS_JSON" ]]; then
                        generate_config && start_svc
                    fi
                else
                    # 解析失败，恢复原数组
                    RELAY_TAGS=("${saved_tags[@]}")
                    RELAY_JSONS=("${saved_jsons[@]}")
                    RELAY_DESCS=("${saved_descs[@]}")
                    print_error "新链接解析失败，中转配置未修改"
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
        menu_header "出入站 IP 配置"
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
        echo -e "  ${GREEN}[3]${NC} 设置入站为双栈 (IPv4+IPv6)"
        echo -e "  ${GREEN}[4]${NC} 设置出站为 IPv4"
        echo -e "  ${GREEN}[5]${NC} 设置出站为 IPv6 (优先)"
        echo -e "  ${GREEN}[6]${NC} 设置出站为仅 IPv6 (IPv4不出站)"
        echo -e "  ${GREEN}[7]${NC} 设置出站为双栈 (IPv4+IPv6)"
        echo -e "  ${GREEN}[8]${NC} 手动修改 IPv4 地址"
        echo -e "  ${GREEN}[9]${NC} 手动修改 IPv6 地址"
        echo -e "  ${GREEN}[0]${NC} 返回主菜单"
        echo ""
        read -p "请选择 [0-9]: " ip_choice
        
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
                    pause
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
                INBOUND_IP_MODE="dual"
                save_ip_config
                print_success "入站已设置为双栈 (IPv4+IPv6)"
                echo -e "${YELLOW}提示: 双栈模式将同时监听 IPv4 和 IPv6${NC}"
                echo -e "${YELLOW}提示: 需要重新生成配置才能生效${NC}"
                read -p "是否立即重新生成配置? (y/N): " regen
                if [[ "$regen" =~ ^[Yy]$ ]] && [[ -n "$INBOUNDS_JSON" ]]; then
                    generate_config && start_svc
                fi
                ;;
            4)
                OUTBOUND_IP_MODE="ipv4"
                save_ip_config
                print_success "出站已设置为 IPv4"
                echo -e "${YELLOW}提示: 需要重新生成配置才能生效${NC}"
                read -p "是否立即重新生成配置? (y/N): " regen
                if [[ "$regen" =~ ^[Yy]$ ]] && [[ -n "$INBOUNDS_JSON" ]]; then
                    generate_config && start_svc
                fi
                ;;
            5)
                if [[ -z "$SERVER_IPV6" ]]; then
                    print_error "未检测到 IPv6 地址，请先手动设置"
                    pause
                    continue
                fi
                OUTBOUND_IP_MODE="ipv6"
                save_ip_config
                print_success "出站已设置为 IPv6 优先"
                echo -e "${YELLOW}提示: IPv6 优先出站，IPv6 不可用时回退到 IPv4${NC}"
                echo -e "${YELLOW}提示: 需要重新生成配置才能生效${NC}"
                read -p "是否立即重新生成配置? (y/N): " regen
                if [[ "$regen" =~ ^[Yy]$ ]] && [[ -n "$INBOUNDS_JSON" ]]; then
                    generate_config && start_svc
                fi
                ;;
            6)
                if [[ -z "$SERVER_IPV6" ]]; then
                    print_error "未检测到 IPv6 地址，请先手动设置"
                    pause
                    continue
                fi
                OUTBOUND_IP_MODE="ipv6_only"
                save_ip_config
                print_success "出站已设置为仅 IPv6"
                echo -e "${YELLOW}提示: 仅使用 IPv6 出站，IPv4 将无法出站${NC}"
                echo -e "${YELLOW}提示: 需要重新生成配置才能生效${NC}"
                read -p "是否立即重新生成配置? (y/N): " regen
                if [[ "$regen" =~ ^[Yy]$ ]] && [[ -n "$INBOUNDS_JSON" ]]; then
                    generate_config && start_svc
                fi
                ;;
            7)
                OUTBOUND_IP_MODE="dual"
                save_ip_config
                print_success "出站已设置为双栈 (IPv4+IPv6)"
                echo -e "${YELLOW}提示: 双栈模式将同时使用 IPv4 和 IPv6，由系统自动选择${NC}"
                echo -e "${YELLOW}提示: 需要重新生成配置才能生效${NC}"
                read -p "是否立即重新生成配置? (y/N): " regen
                if [[ "$regen" =~ ^[Yy]$ ]] && [[ -n "$INBOUNDS_JSON" ]]; then
                    generate_config && start_svc
                fi
                ;;
            8)
                read -p "请输入 IPv4 地址: " new_ipv4
                if [[ -n "$new_ipv4" ]]; then
                    SERVER_IP="$new_ipv4"
                    save_ip_config
                    print_success "IPv4 地址已更新: ${SERVER_IP}"
                    echo -e "${YELLOW}提示: 需要重新生成链接文件${NC}"
                fi
                ;;
            9)
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
        
        [[ "$ip_choice" != "0" ]] && pause
    done
}

# ==================== Reality 节点修改 ====================
modify_reality_node() {
    if [[ ${#INBOUND_TAGS[@]} -eq 0 ]]; then
        print_warning "当前没有可修改的节点"
        return 1
    fi
    
    echo ""
    echo -e "${CYAN}当前 Reality 节点:${NC}"
    local reality_nodes=()
    for i in "${!INBOUND_TAGS[@]}"; do
        if [[ "${INBOUND_PROTOS[$i]}" == "Reality" ]]; then
            reality_nodes+=("$i")
            echo -e "  ${GREEN}[${#reality_nodes[@]}]${NC} 端口: ${INBOUND_PORTS[$i]}, SNI: ${INBOUND_SNIS[$i]}, TAG: ${INBOUND_TAGS[$i]}"
        fi
    done
    
    if [[ ${#reality_nodes[@]} -eq 0 ]]; then
        print_warning "没有找到 Reality 节点"
        return 1
    fi
    
    read -p "请选择要修改的节点序号 (0 取消): " node_choice
    [[ "$node_choice" == "0" ]] && return 0
    local idx=$((10#$node_choice-1))
    if ! [[ "$node_choice" =~ ^[0-9]+$ ]] || (( idx < 0 || idx >= ${#reality_nodes[@]} )); then
        print_error "序号无效"
        return 1
    fi
    
    local array_idx="${reality_nodes[$idx]}"
    local tag="${INBOUND_TAGS[$array_idx]}"
    local port="${INBOUND_PORTS[$array_idx]}"
    
    local config_changed=0
    
    while true; do
        echo ""
        echo -e "${CYAN}修改 Reality 节点 ${tag}:${NC}"
        echo -e "  ${GREEN}[1]${NC} 修改端口 (当前: ${port})"
        echo -e "  ${GREEN}[2]${NC} 修改 SNI (当前: ${INBOUND_SNIS[$array_idx]})"
        echo -e "  ${GREEN}[3]${NC} 重新生成 UUID"
        echo -e "  ${GREEN}[4]${NC} 重新生成 Short ID"
        echo -e "  ${GREEN}[0]${NC} 返回"
        read -p "请选择: " mod_choice
        
        case $mod_choice in
            1)
                echo -e "${YELLOW}新端口 (留空随机分配)${NC}"
                read -p "端口: " new_port
                if [[ -z "$new_port" ]]; then
                    new_port=$(get_random_free_port)
                    [[ -z "$new_port" ]] && { print_error "无法获取随机端口"; continue; }
                fi
                if ! [[ "$new_port" =~ ^[0-9]+$ ]] || (( new_port < 1 || new_port > 65535 )); then
                    print_error "端口无效"; continue
                fi
                if check_port_in_use "$new_port" && [[ "$new_port" != "$port" ]]; then
                    print_warning "端口 ${new_port} 已被占用"; continue
                fi
                local new_tag=$(modify_port "$tag" "vless-in-" "$new_port")
                INBOUND_TAGS[$array_idx]="$new_tag"
                INBOUND_PORTS[$array_idx]="$new_port"
                tag="$new_tag"
                port="$new_port"
                config_changed=1
                print_success "端口已修改为 ${new_port}"
                ;;
            2)
                echo -e "${YELLOW}新 SNI (留空随机)${NC}"
                echo -e "${CYAN}例如: ${DEFAULT_SNI1}${NC}"
                read -p "SNI: " new_sni
                if [[ -z "$new_sni" ]]; then
                    new_sni=$(get_random_sni)
                fi
                jq_update_config --arg tag "$tag" --arg sni "$new_sni" \
                    '(.inbounds[] | select(.tag == $tag)) |= (.tls.server_name = $sni | .tls.reality.handshake.server = $sni)'
                INBOUND_SNIS[$array_idx]="$new_sni"
                config_changed=1
                print_success "SNI 已修改为 ${new_sni}"
                ;;
            3)
                regenerate_secret uuid "$tag" || continue
                config_changed=1
                ;;
            4)
                regenerate_secret sid "$tag"
                config_changed=1
                ;;
            0)
                break
                ;;
            *)
                print_error "无效选项"
                ;;
        esac
    done
    
    if [[ $config_changed -eq 1 ]]; then
        load_inbounds_from_config
        generate_config && start_svc
        regenerate_links_from_config
    fi
}

# ==================== Hysteria2 节点修改 ====================
modify_hysteria2_node() {
    if [[ ${#INBOUND_TAGS[@]} -eq 0 ]]; then
        print_warning "当前没有可修改的节点"
        return 1
    fi
    
    echo ""
    echo -e "${CYAN}当前 Hysteria2 节点:${NC}"
    local hy2_nodes=()
    for i in "${!INBOUND_TAGS[@]}"; do
        if [[ "${INBOUND_PROTOS[$i]}" == "Hysteria2" ]]; then
            hy2_nodes+=("$i")
            echo -e "  ${GREEN}[${#hy2_nodes[@]}]${NC} 端口: ${INBOUND_PORTS[$i]}, SNI: ${INBOUND_SNIS[$i]}, TAG: ${INBOUND_TAGS[$i]}"
        fi
    done
    
    if [[ ${#hy2_nodes[@]} -eq 0 ]]; then
        print_warning "没有找到 Hysteria2 节点"
        return 1
    fi
    
    read -p "请选择要修改的节点序号 (0 取消): " node_choice
    [[ "$node_choice" == "0" ]] && return 0
    local idx=$((10#$node_choice-1))
    if ! [[ "$node_choice" =~ ^[0-9]+$ ]] || (( idx < 0 || idx >= ${#hy2_nodes[@]} )); then
        print_error "序号无效"
        return 1
    fi
    
    local array_idx="${hy2_nodes[$idx]}"
    local tag="${INBOUND_TAGS[$array_idx]}"
    local port="${INBOUND_PORTS[$array_idx]}"
    local current_sni="${INBOUND_SNIS[$array_idx]}"
    
    local config_changed=0
    
    while true; do
        echo ""
        echo -e "${CYAN}修改 Hysteria2 节点 ${tag}:${NC}"
        echo -e "  ${GREEN}[1]${NC} 修改端口 (当前: ${port})"
        echo -e "  ${GREEN}[2]${NC} 修改 SNI (当前: ${current_sni})"
        echo -e "  ${GREEN}[3]${NC} 重新生成密码"
        echo -e "  ${GREEN}[4]${NC} 重新生成混淆密码"
        echo -e "  ${GREEN}[0]${NC} 返回"
        read -p "请选择: " mod_choice
        
        case $mod_choice in
            1)
                echo -e "${YELLOW}新端口 (留空随机分配)${NC}"
                read -p "端口: " new_port
                if [[ -z "$new_port" ]]; then
                    new_port=$(get_random_free_port)
                    [[ -z "$new_port" ]] && { print_error "无法获取随机端口"; continue; }
                fi
                if ! [[ "$new_port" =~ ^[0-9]+$ ]] || (( new_port < 1 || new_port > 65535 )); then
                    print_error "端口无效"; continue
                fi
                if check_port_in_use "$new_port" && [[ "$new_port" != "$port" ]]; then
                    print_warning "端口 ${new_port} 已被占用"; continue
                fi
                local new_tag=$(modify_port "$tag" "hy2-in-" "$new_port")
                INBOUND_TAGS[$array_idx]="$new_tag"
                INBOUND_PORTS[$array_idx]="$new_port"
                tag="$new_tag"
                port="$new_port"
                config_changed=1
                print_success "端口已修改为 ${new_port}"
                ;;
            2)
                echo -e "${YELLOW}新 SNI (留空随机)${NC}"
                echo -e "${CYAN}例如: ${DEFAULT_SNI1}${NC}"
                read -p "SNI: " new_sni
                if [[ -z "$new_sni" ]]; then
                    new_sni=$(get_random_sni)
                fi
                jq_update_config --arg tag "$tag" --arg sni "$new_sni" \
                    '(.inbounds[] | select(.tag == $tag)) |= (.tls.server_name = $sni | .tls.certificate_path = ($sni | "/etc/sing-box/certs/\(.)" + "/cert.pem") | .tls.key_path = ($sni | "/etc/sing-box/certs/\(.)" + "/private.key"))'
                gen_cert_for_sni "${new_sni}"
                INBOUND_SNIS[$array_idx]="$new_sni"
                current_sni="$new_sni"
                config_changed=1
                print_success "SNI 已修改为 ${new_sni}，证书已重新生成"
                ;;
            3)
                regenerate_secret password "$tag"
                config_changed=1
                ;;
            4)
                regenerate_secret obfs_password "$tag"
                config_changed=1
                ;;
            0)
                break
                ;;
            *)
                print_error "无效选项"
                ;;
        esac
    done
    
    if [[ $config_changed -eq 1 ]]; then
        load_inbounds_from_config
        generate_config && start_svc
        regenerate_links_from_config
    fi
}

# ==================== SOCKS5 节点修改 ====================
modify_socks5_node() {
    if [[ ${#INBOUND_TAGS[@]} -eq 0 ]]; then
        print_warning "当前没有可修改的节点"
        return 1
    fi
    
    echo ""
    echo -e "${CYAN}当前 SOCKS5 节点:${NC}"
    local socks_nodes=()
    for i in "${!INBOUND_TAGS[@]}"; do
        if [[ "${INBOUND_PROTOS[$i]}" == "SOCKS5" ]]; then
            socks_nodes+=("$i")
            echo -e "  ${GREEN}[${#socks_nodes[@]}]${NC} 端口: ${INBOUND_PORTS[$i]}, TAG: ${INBOUND_TAGS[$i]}"
        fi
    done
    
    if [[ ${#socks_nodes[@]} -eq 0 ]]; then
        print_warning "没有找到 SOCKS5 节点"
        return 1
    fi
    
    read -p "请选择要修改的节点序号 (0 取消): " node_choice
    [[ "$node_choice" == "0" ]] && return 0
    local idx=$((10#$node_choice-1))
    if ! [[ "$node_choice" =~ ^[0-9]+$ ]] || (( idx < 0 || idx >= ${#socks_nodes[@]} )); then
        print_error "序号无效"
        return 1
    fi
    
    local array_idx="${socks_nodes[$idx]}"
    local tag="${INBOUND_TAGS[$array_idx]}"
    local port="${INBOUND_PORTS[$array_idx]}"
    
    # 读取当前用户名
    local current_user=$(jq -r --arg tag "$tag" '(.inbounds[] | select(.tag == $tag)).users[0].username // ""' "${CONFIG_FILE}")
    
    local config_changed=0
    
    while true; do
        echo ""
        echo -e "${CYAN}修改 SOCKS5 节点 ${tag}:${NC}"
        echo -e "  ${GREEN}[1]${NC} 修改端口 (当前: ${port})"
        echo -e "  ${GREEN}[2]${NC} 修改用户名 (当前: ${current_user:-无})"
        echo -e "  ${GREEN}[3]${NC} 重新生成密码"
        echo -e "  ${GREEN}[0]${NC} 返回"
        read -p "请选择: " mod_choice
        
        case $mod_choice in
            1)
                echo -e "${YELLOW}新端口 (留空随机分配)${NC}"
                read -p "端口: " new_port
                if [[ -z "$new_port" ]]; then
                    new_port=$(get_random_free_port)
                    [[ -z "$new_port" ]] && { print_error "无法获取随机端口"; continue; }
                fi
                if ! [[ "$new_port" =~ ^[0-9]+$ ]] || (( new_port < 1 || new_port > 65535 )); then
                    print_error "端口无效"; continue
                fi
                if check_port_in_use "$new_port" && [[ "$new_port" != "$port" ]]; then
                    print_warning "端口 ${new_port} 已被占用"; continue
                fi
                local new_tag=$(modify_port "$tag" "socks-in-" "$new_port")
                INBOUND_TAGS[$array_idx]="$new_tag"
                INBOUND_PORTS[$array_idx]="$new_port"
                tag="$new_tag"
                port="$new_port"
                config_changed=1
                print_success "端口已修改为 ${new_port}"
                ;;
            2)
                echo -e "${YELLOW}新用户名 (留空随机生成)${NC}"
                read -p "用户名: " new_user
                if [[ -z "$new_user" ]]; then
                    new_user="user_$(openssl rand -hex 4)"
                fi
                jq_update_config --arg tag "$tag" --arg user "$new_user" \
                    '(.inbounds[] | select(.tag == $tag)) |= (.users[0].username = $user)'
                current_user="$new_user"
                config_changed=1
                print_success "用户名已修改为 ${new_user}"
                ;;
            3)
                regenerate_secret socks_password "$tag"
                config_changed=1
                ;;
            0)
                break
                ;;
            *)
                print_error "无效选项"
                ;;
        esac
    done
    
    if [[ $config_changed -eq 1 ]]; then
        load_inbounds_from_config
        generate_config && start_svc
        regenerate_links_from_config
    fi
}

# ==================== ShadowTLS 节点修改 ====================
modify_shadowtls_node() {
    if [[ ${#INBOUND_TAGS[@]} -eq 0 ]]; then
        print_warning "当前没有可修改的节点"
        return 1
    fi
    
    echo ""
    echo -e "${CYAN}当前 ShadowTLS 节点:${NC}"
    local stls_nodes=()
    for i in "${!INBOUND_TAGS[@]}"; do
        if [[ "${INBOUND_PROTOS[$i]}" == "ShadowTLS v3" ]]; then
            stls_nodes+=("$i")
            echo -e "  ${GREEN}[${#stls_nodes[@]}]${NC} 端口: ${INBOUND_PORTS[$i]}, SNI: ${INBOUND_SNIS[$i]}, TAG: ${INBOUND_TAGS[$i]}"
        fi
    done
    
    if [[ ${#stls_nodes[@]} -eq 0 ]]; then
        print_warning "没有找到 ShadowTLS 节点"
        return 1
    fi
    
    read -p "请选择要修改的节点序号 (0 取消): " node_choice
    [[ "$node_choice" == "0" ]] && return 0
    local idx=$((10#$node_choice-1))
    if ! [[ "$node_choice" =~ ^[0-9]+$ ]] || (( idx < 0 || idx >= ${#stls_nodes[@]} )); then
        print_error "序号无效"
        return 1
    fi
    
    local array_idx="${stls_nodes[$idx]}"
    local tag="${INBOUND_TAGS[$array_idx]}"
    local port="${INBOUND_PORTS[$array_idx]}"
    local current_sni="${INBOUND_SNIS[$array_idx]}"
    
    local config_changed=0
    
    while true; do
        echo ""
        echo -e "${CYAN}修改 ShadowTLS 节点 ${tag}:${NC}"
        echo -e "  ${GREEN}[1]${NC} 修改端口 (当前: ${port})"
        echo -e "  ${GREEN}[2]${NC} 修改 SNI (当前: ${current_sni})"
        echo -e "  ${GREEN}[3]${NC} 重新生成 ShadowTLS 密码"
        echo -e "  ${GREEN}[4]${NC} 重新生成 SS 密码"
        echo -e "  ${GREEN}[0]${NC} 返回"
        read -p "请选择: " mod_choice
        
        case $mod_choice in
            1)
                echo -e "${YELLOW}新端口 (留空随机分配)${NC}"
                read -p "端口: " new_port
                if [[ -z "$new_port" ]]; then
                    new_port=$(get_random_free_port)
                    [[ -z "$new_port" ]] && { print_error "无法获取随机端口"; continue; }
                fi
                if ! [[ "$new_port" =~ ^[0-9]+$ ]] || (( new_port < 1 || new_port > 65535 )); then
                    print_error "端口无效"; continue
                fi
                if check_port_in_use "$new_port" && [[ "$new_port" != "$port" ]]; then
                    print_warning "端口 ${new_port} 已被占用"; continue
                fi
                local new_stls_tag="shadowtls-in-${new_port}"
                local new_ss_tag="shadowsocks-in-${new_port}"
                local old_ss_tag="shadowsocks-in-${port}"
                # Update shadowtls inbound tag, port, and detour
                jq_update_config --arg old_tag "$tag" --arg new_tag "$new_stls_tag" --argjson new_port "$new_port" --arg new_ss_tag "$new_ss_tag" \
                    '(.inbounds[] | select(.tag == $old_tag)) |= (.tag = $new_tag | .listen_port = $new_port | .detour = $new_ss_tag)'
                # Update shadowsocks inbound tag and detour reference
                jq_update_config --arg old_ss_tag "$old_ss_tag" --arg new_ss_tag "$new_ss_tag" \
                    '(.inbounds[] | select(.tag == $old_ss_tag)) |= (.tag = $new_ss_tag)'
                # Update route rules
                if jq -e '.route.rules' "${CONFIG_FILE}" >/dev/null 2>&1; then
                    jq_update_config --arg old_tag "$tag" --arg new_tag "$new_stls_tag" \
                        '(.route.rules[] | select(.inbound[]? == $old_tag)) |= (.inbound = [.inbound[] | if . == $old_tag then $new_tag else . end])'
                fi
                INBOUND_TAGS[$array_idx]="$new_stls_tag"
                INBOUND_PORTS[$array_idx]="$new_port"
                tag="$new_stls_tag"
                port="$new_port"
                config_changed=1
                print_success "端口已修改为 ${new_port}，SS 标签和 detour 已同步更新"
                ;;
            2)
                echo -e "${YELLOW}新 SNI (留空随机)${NC}"
                echo -e "${CYAN}例如: ${DEFAULT_SNI1}${NC}"
                read -p "SNI: " new_sni
                if [[ -z "$new_sni" ]]; then
                    new_sni=$(get_random_sni)
                fi
                jq_update_config --arg tag "$tag" --arg sni "$new_sni" \
                    '(.inbounds[] | select(.tag == $tag)) |= (.handshake.server = $sni)'
                INBOUND_SNIS[$array_idx]="$new_sni"
                current_sni="$new_sni"
                config_changed=1
                print_success "SNI 已修改为 ${new_sni}，handshake.server 已同步更新"
                ;;
            3)
                regenerate_secret stls_password "$tag"
                config_changed=1
                print_success "ShadowTLS 密码已重新生成"
                ;;
            4)
                local ss_tag="shadowsocks-in-${port}"
                regenerate_secret ss_password "$ss_tag"
                config_changed=1
                ;;
            0)
                break
                ;;
            *)
                print_error "无效选项"
                ;;
        esac
    done
    
    if [[ $config_changed -eq 1 ]]; then
        load_inbounds_from_config
        generate_config && start_svc
        regenerate_links_from_config
    fi
}

# ==================== HTTPS 节点修改 ====================
modify_https_node() {
    if [[ ${#INBOUND_TAGS[@]} -eq 0 ]]; then
        print_warning "当前没有可修改的节点"
        return 1
    fi
    
    echo ""
    echo -e "${CYAN}当前 HTTPS 节点:${NC}"
    local https_nodes=()
    for i in "${!INBOUND_TAGS[@]}"; do
        if [[ "${INBOUND_PROTOS[$i]}" == "HTTPS" ]]; then
            https_nodes+=("$i")
            echo -e "  ${GREEN}[${#https_nodes[@]}]${NC} 端口: ${INBOUND_PORTS[$i]}, SNI: ${INBOUND_SNIS[$i]}, TAG: ${INBOUND_TAGS[$i]}"
        fi
    done
    
    if [[ ${#https_nodes[@]} -eq 0 ]]; then
        print_warning "没有找到 HTTPS 节点"
        return 1
    fi
    
    read -p "请选择要修改的节点序号 (0 取消): " node_choice
    [[ "$node_choice" == "0" ]] && return 0
    local idx=$((10#$node_choice-1))
    if ! [[ "$node_choice" =~ ^[0-9]+$ ]] || (( idx < 0 || idx >= ${#https_nodes[@]} )); then
        print_error "序号无效"
        return 1
    fi
    
    local array_idx="${https_nodes[$idx]}"
    local tag="${INBOUND_TAGS[$array_idx]}"
    local port="${INBOUND_PORTS[$array_idx]}"
    local current_sni="${INBOUND_SNIS[$array_idx]}"
    
    local config_changed=0
    
    while true; do
        echo ""
        echo -e "${CYAN}修改 HTTPS 节点 ${tag}:${NC}"
        echo -e "  ${GREEN}[1]${NC} 修改端口 (当前: ${port})"
        echo -e "  ${GREEN}[2]${NC} 修改 SNI (当前: ${current_sni})"
        echo -e "  ${GREEN}[3]${NC} 重新生成 UUID"
        echo -e "  ${GREEN}[0]${NC} 返回"
        read -p "请选择: " mod_choice
        
        case $mod_choice in
            1)
                echo -e "${YELLOW}新端口 (留空随机分配)${NC}"
                read -p "端口: " new_port
                if [[ -z "$new_port" ]]; then
                    new_port=$(get_random_free_port)
                    [[ -z "$new_port" ]] && { print_error "无法获取随机端口"; continue; }
                fi
                if ! [[ "$new_port" =~ ^[0-9]+$ ]] || (( new_port < 1 || new_port > 65535 )); then
                    print_error "端口无效"; continue
                fi
                if check_port_in_use "$new_port" && [[ "$new_port" != "$port" ]]; then
                    print_warning "端口 ${new_port} 已被占用"; continue
                fi
                local new_tag=$(modify_port "$tag" "vless-tls-in-" "$new_port")
                INBOUND_TAGS[$array_idx]="$new_tag"
                INBOUND_PORTS[$array_idx]="$new_port"
                tag="$new_tag"
                port="$new_port"
                config_changed=1
                print_success "端口已修改为 ${new_port}"
                ;;
            2)
                echo -e "${YELLOW}新 SNI (留空随机)${NC}"
                echo -e "${CYAN}例如: ${DEFAULT_SNI1}${NC}"
                read -p "SNI: " new_sni
                if [[ -z "$new_sni" ]]; then
                    new_sni=$(get_random_sni)
                fi
                jq_update_config --arg tag "$tag" --arg sni "$new_sni" \
                    '(.inbounds[] | select(.tag == $tag)) |= (.tls.server_name = $sni | .tls.certificate_path = ($sni | "/etc/sing-box/certs/\(.)" + "/cert.pem") | .tls.key_path = ($sni | "/etc/sing-box/certs/\(.)" + "/private.key"))'
                gen_cert_for_sni "${new_sni}"
                INBOUND_SNIS[$array_idx]="$new_sni"
                current_sni="$new_sni"
                config_changed=1
                print_success "SNI 已修改为 ${new_sni}，证书已重新生成"
                ;;
            3)
                regenerate_secret uuid "$tag" || continue
                config_changed=1
                ;;
            0)
                break
                ;;
            *)
                print_error "无效选项"
                ;;
        esac
    done
    
    if [[ $config_changed -eq 1 ]]; then
        load_inbounds_from_config
        generate_config && start_svc
        regenerate_links_from_config
    fi
}

# ==================== AnyTLS 节点修改 ====================
modify_anytls_node() {
    if [[ ${#INBOUND_TAGS[@]} -eq 0 ]]; then
        print_warning "当前没有可修改的节点"
        return 1
    fi
    
    echo ""
    echo -e "${CYAN}当前 AnyTLS 节点:${NC}"
    local anytls_nodes=()
    for i in "${!INBOUND_TAGS[@]}"; do
        if [[ "${INBOUND_PROTOS[$i]}" == "AnyTLS" || "${INBOUND_PROTOS[$i]}" == "AnyTLS+REALITY" ]]; then
            anytls_nodes+=("$i")
            echo -e "  ${GREEN}[${#anytls_nodes[@]}]${NC} 协议: ${INBOUND_PROTOS[$i]}, 端口: ${INBOUND_PORTS[$i]}, SNI: ${INBOUND_SNIS[$i]}, TAG: ${INBOUND_TAGS[$i]}"
        fi
    done
    
    if [[ ${#anytls_nodes[@]} -eq 0 ]]; then
        print_warning "没有找到 AnyTLS 节点"
        return 1
    fi
    
    read -p "请选择要修改的节点序号 (0 取消): " node_choice
    [[ "$node_choice" == "0" ]] && return 0
    local idx=$((10#$node_choice-1))
    if ! [[ "$node_choice" =~ ^[0-9]+$ ]] || (( idx < 0 || idx >= ${#anytls_nodes[@]} )); then
        print_error "序号无效"
        return 1
    fi
    
    local array_idx="${anytls_nodes[$idx]}"
    local tag="${INBOUND_TAGS[$array_idx]}"
    local port="${INBOUND_PORTS[$array_idx]}"
    local current_sni="${INBOUND_SNIS[$array_idx]}"
    local proto="${INBOUND_PROTOS[$array_idx]}"
    
    # 判断是否为 AnyTLS+REALITY 模式
    local is_reality=0
    if [[ "$proto" == "AnyTLS+REALITY" ]]; then
        is_reality=1
    fi
    
    local config_changed=0
    
    while true; do
        echo ""
        echo -e "${CYAN}修改 ${proto} 节点 ${tag}:${NC}"
        echo -e "  ${GREEN}[1]${NC} 修改端口 (当前: ${port})"
        echo -e "  ${GREEN}[2]${NC} 修改 SNI (当前: ${current_sni})"
        echo -e "  ${GREEN}[3]${NC} 重新生成密码"
        echo -e "  ${GREEN}[0]${NC} 返回"
        read -p "请选择: " mod_choice
        
        case $mod_choice in
            1)
                echo -e "${YELLOW}新端口 (留空随机分配)${NC}"
                read -p "端口: " new_port
                if [[ -z "$new_port" ]]; then
                    new_port=$(get_random_free_port)
                    [[ -z "$new_port" ]] && { print_error "无法获取随机端口"; continue; }
                fi
                if ! [[ "$new_port" =~ ^[0-9]+$ ]] || (( new_port < 1 || new_port > 65535 )); then
                    print_error "端口无效"; continue
                fi
                if check_port_in_use "$new_port" && [[ "$new_port" != "$port" ]]; then
                    print_warning "端口 ${new_port} 已被占用"; continue
                fi
                local new_tag_prefix
                if [[ $is_reality -eq 1 ]]; then
                    new_tag_prefix="anytls-reality-"
                else
                    new_tag_prefix="anytls-in-"
                fi
                local new_tag=$(modify_port "$tag" "$new_tag_prefix" "$new_port")
                INBOUND_TAGS[$array_idx]="$new_tag"
                INBOUND_PORTS[$array_idx]="$new_port"
                tag="$new_tag"
                port="$new_port"
                config_changed=1
                print_success "端口已修改为 ${new_port}"
                ;;
            2)
                echo -e "${YELLOW}新 SNI (留空随机)${NC}"
                echo -e "${CYAN}例如: ${DEFAULT_SNI1}${NC}"
                read -p "SNI: " new_sni
                if [[ -z "$new_sni" ]]; then
                    new_sni=$(get_random_sni)
                fi
                if [[ $is_reality -eq 1 ]]; then
                    jq_update_config --arg tag "$tag" --arg sni "$new_sni" \
                        '(.inbounds[] | select(.tag == $tag)) |= (.tls.server_name = $sni | .tls.reality.handshake.server = $sni)'
                else
                    jq_update_config --arg tag "$tag" --arg sni "$new_sni" \
                        '(.inbounds[] | select(.tag == $tag)) |= (.tls.server_name = $sni | .tls.certificate_path = ($sni | "/etc/sing-box/certs/\(.)" + "/cert.pem") | .tls.key_path = ($sni | "/etc/sing-box/certs/\(.)" + "/private.key"))'
                    gen_cert_for_sni "${new_sni}"
                fi
                INBOUND_SNIS[$array_idx]="$new_sni"
                current_sni="$new_sni"
                config_changed=1
                if [[ $is_reality -eq 1 ]]; then
                    print_success "SNI 已修改为 ${new_sni}，handshake.server 已同步更新"
                else
                    print_success "SNI 已修改为 ${new_sni}，证书已重新生成"
                fi
                ;;
            3)
                regenerate_secret password "$tag"
                config_changed=1
                ;;
            0)
                break
                ;;
            *)
                print_error "无效选项"
                ;;
        esac
    done
    
    if [[ $config_changed -eq 1 ]]; then
        load_inbounds_from_config
        generate_config && start_svc
        regenerate_links_from_config
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

    if ! confirm "确认删除? (y/N): "; then
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
        svc_restart
        sleep 2
        
        if svc_is_active; then
            print_success "节点已删除: ${proto}:${port} (SNI: ${sni})"
            print_success "服务已重启"
        else
            print_error "服务重启失败"
            if [[ $ALPINE -eq 1 ]]; then
                tail -n 10 /var/log/messages | grep sing-box || cat /var/log/sing-box.log 2>/dev/null
            else
                journalctl -u sing-box -n 10 --no-pager
            fi
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
    
    if ! confirm "确认删除所有节点? (y/N): "; then
        print_info "取消删除操作"
        return 0
    fi
    
    INBOUNDS_JSON=""
    INBOUND_TAGS=()
    INBOUND_PORTS=()
    INBOUND_PROTOS=()
    INBOUND_SNIS=()
    INBOUND_RELAY_TAGS=()
    
    # 根据出站模式设置 DNS 策略
    local dns_strategy="prefer_ipv4"
    [[ "$OUTBOUND_IP_MODE" == "ipv6" ]] && dns_strategy="prefer_ipv6"
    [[ "$OUTBOUND_IP_MODE" == "ipv6_only" ]] && dns_strategy="ipv6_only"
    
    cat > ${CONFIG_FILE} << EOFCONFIG
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "local",
        "type": "local"
      },
      {
        "tag": "remote",
        "type": "udp",
        "server": "8.8.8.8"
      }
    ],
    "final": "remote",
    "strategy": "${dns_strategy}"
  },
  "inbounds": [],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "final": "direct",
    "default_domain_resolver": "local"
  }
}
EOFCONFIG
    
    print_info "停止 sing-box 服务..."
    svc_stop
    
    cleanup_links
    
    print_success "所有节点已删除，配置文件已重置"
    
    read -p "是否启动空配置的 sing-box 服务? (y/N): " restart_service
    restart_service=${restart_service:-N}
    
    if [[ "$restart_service" =~ ^[Yy]$ ]]; then
        svc_start
        sleep 2
        if svc_is_active; then
            print_success "服务已启动 (空配置)"
        else
            print_error "服务启动失败"
        fi
    fi
}
# ==================== 配置生成（修复路由逻辑） ====================
generate_config() {
    print_info "生成最终配置文件..."

    if [[ -f "${CONFIG_FILE}" ]]; then
        local backup_file="${CONFIG_FILE}.bak"
        cp "${CONFIG_FILE}" "${backup_file}" 2>/dev/null
        print_info "已备份配置到: ${backup_file}"
    fi

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
    
    # 添加 direct outbound（根据出站模式设置绑定地址和域名解析策略）
    # sing-box 1.14.0+ 移除了 domain_strategy，需通过 domain_resolver 设置解析策略
    local direct_outbound
    if [[ "$OUTBOUND_IP_MODE" == "ipv6" ]]; then
        # IPv6优先：绑定IPv6地址 + domain_resolver策略prefer_ipv6，IPv6不可用时回退IPv4
        if [[ -n "${SERVER_IPV6}" ]]; then
            direct_outbound="{\"type\": \"direct\", \"tag\": \"direct\", \"tcp_fast_open\": false, \"inet6_bind_address\": \"${SERVER_IPV6}\", \"fallback_delay\": \"300ms\", \"domain_resolver\": {\"server\": \"remote\", \"strategy\": \"prefer_ipv6\"}}"
        else
            direct_outbound='{"type": "direct", "tag": "direct", "tcp_fast_open": false, "domain_resolver": {"server": "remote", "strategy": "prefer_ipv6"}}'
        fi
    elif [[ "$OUTBOUND_IP_MODE" == "ipv6_only" ]]; then
        # 仅IPv6：绑定IPv6地址 + domain_resolver策略ipv6_only，配合block规则彻底阻断IPv4
        if [[ -n "${SERVER_IPV6}" ]]; then
            direct_outbound="{\"type\": \"direct\", \"tag\": \"direct\", \"tcp_fast_open\": false, \"inet6_bind_address\": \"${SERVER_IPV6}\", \"domain_resolver\": {\"server\": \"remote\", \"strategy\": \"ipv6_only\"}}"
        else
            direct_outbound='{"type": "direct", "tag": "direct", "tcp_fast_open": false, "domain_resolver": {"server": "remote", "strategy": "ipv6_only"}}'
        fi
    elif [[ "$OUTBOUND_IP_MODE" == "ipv4" ]]; then
        # 仅IPv4：绑定IPv4地址 + domain_resolver策略ipv4_only
        if [[ -n "${SERVER_IP}" ]]; then
            direct_outbound="{\"type\": \"direct\", \"tag\": \"direct\", \"tcp_fast_open\": false, \"inet4_bind_address\": \"${SERVER_IP}\", \"domain_resolver\": {\"server\": \"remote\", \"strategy\": \"ipv4_only\"}}"
        else
            direct_outbound='{"type": "direct", "tag": "direct", "tcp_fast_open": false, "domain_resolver": {"server": "remote", "strategy": "ipv4_only"}}'
        fi
    else
        # dual 双栈：不限制绑定地址
        direct_outbound='{"type": "direct", "tag": "direct", "tcp_fast_open": false}'
    fi
    outbounds_array+=("$direct_outbound")
    
    # ipv6_only 模式下添加 block outbound 用于阻断 IPv4 出站
    if [[ "$OUTBOUND_IP_MODE" == "ipv6_only" ]]; then
        local block_outbound='{"type": "block", "tag": "block-ipv4"}'
        outbounds_array+=("$block_outbound")
    fi
    
    # 组合 outbounds
    local outbounds="["
    for i in "${!outbounds_array[@]}"; do
        [[ $i -gt 0 ]] && outbounds+=", "
        outbounds+="${outbounds_array[$i]}"
    done
    outbounds+="]"
    
    # 加载分流规则
    load_domain_routes_from_file
    
    # 构建路由规则
    local route_rules=()
    local has_relay=0
    
    # ipv6_only 模式下，添加规则阻断所有 IPv4 出站流量
    if [[ "$OUTBOUND_IP_MODE" == "ipv6_only" ]]; then
        route_rules+=('{"ip_cidr":["0.0.0.0/0"],"outbound":"block-ipv4"}')
        has_relay=1
    fi
    
    # 1. 首先添加所有分流域名规则（无论节点默认是中转还是直连）
    for route in "${DOMAIN_ROUTES[@]}"; do
        IFS='|' read -r inbound_tag match_type match_value relay_tag desc <<< "$route"
        [[ -z "$inbound_tag" || -z "$match_type" || -z "$match_value" || -z "$relay_tag" ]] && continue
        
        # 检查中转是否存在
        local relay_exists=0
        for rt in "${RELAY_TAGS[@]}"; do
            if [[ "$rt" == "$relay_tag" ]]; then
                relay_exists=1
                break
            fi
        done
        if [[ $relay_exists -eq 0 ]]; then
            print_warning "分流规则引用的中转 ${relay_tag} 不存在，跳过规则: ${match_type}=${match_value}"
            continue
        fi
        
        # 根据匹配类型生成对应的 sing-box 规则
        local rule_part=""
        case "$match_type" in
            domain_suffix)
                rule_part="\"domain_suffix\":[\"${match_value}\"]"
                ;;
            domain)
                rule_part="\"domain\":[\"${match_value}\"]"
                ;;
            domain_keyword)
                rule_part="\"domain_keyword\":[\"${match_value}\"]"
                ;;
            ip_cidr)
                rule_part="\"ip_cidr\":[\"${match_value}\"]"
                ;;
            *)
                continue
                ;;
        esac
        
        route_rules+=("{\"inbound\":[\"${inbound_tag}\"],${rule_part},\"outbound\":\"${relay_tag}\"}")
        has_relay=1
    done
    
    # 2. 为每个节点添加默认路由（仅当节点配置了中转且不是 direct）
    for i in "${!INBOUND_TAGS[@]}"; do
        local inbound_tag="${INBOUND_TAGS[$i]}"
        local relay_tag="${INBOUND_RELAY_TAGS[$i]}"
        
        # 如果节点配置了具体的中转（非 direct），则添加兜底规则
        if [[ "$relay_tag" != "direct" ]]; then
            # 检查中转是否存在
            local relay_exists=0
            for rt in "${RELAY_TAGS[@]}"; do
                if [[ "$rt" == "$relay_tag" ]]; then
                    relay_exists=1
                    break
                fi
            done
            if [[ $relay_exists -eq 0 ]]; then
                print_warning "节点 ${inbound_tag} 配置的中转 ${relay_tag} 不存在，将改为直连"
                INBOUND_RELAY_TAGS[$i]="direct"
                continue
            fi
            route_rules+=("{\"inbound\":[\"${inbound_tag}\"],\"outbound\":\"${relay_tag}\"}")
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
        route_json+="],\"final\":\"direct\",\"default_domain_resolver\":\"local\"}"
    else
        route_json="{\"final\":\"direct\",\"default_domain_resolver\":\"local\"}"
    fi
    
    # 构建 DNS 配置（根据出站 IP 模式）
    local dns_json
    if [[ "$OUTBOUND_IP_MODE" == "ipv6_only" ]]; then
        dns_json='{
    "servers": [
      {
        "tag": "local",
        "type": "local"
      },
      {
        "tag": "remote",
        "type": "udp",
        "server": "8.8.8.8"
      }
    ],
    "final": "remote",
    "strategy": "ipv6_only"
  }'
    elif [[ "$OUTBOUND_IP_MODE" == "ipv6" ]]; then
        dns_json='{
    "servers": [
      {
        "tag": "local",
        "type": "local"
      },
      {
        "tag": "remote",
        "type": "udp",
        "server": "8.8.8.8"
      }
    ],
    "final": "remote",
    "strategy": "prefer_ipv6"
  }'
    elif [[ "$OUTBOUND_IP_MODE" == "dual" ]]; then
        dns_json='{
    "servers": [
      {
        "tag": "local",
        "type": "local"
      },
      {
        "tag": "remote",
        "type": "udp",
        "server": "8.8.8.8"
      }
    ],
    "final": "remote",
    "strategy": "prefer_ipv4"
  }'
    else
        dns_json='{
    "servers": [
      {
        "tag": "local",
        "type": "local"
      },
      {
        "tag": "remote",
        "type": "udp",
        "server": "8.8.8.8"
      }
    ],
    "final": "remote",
    "strategy": "prefer_ipv4"
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
    
    local check_output
    check_output=$("${INSTALL_DIR}/sing-box" check -c "${CONFIG_FILE}" 2>&1)
    local check_exit_code=$?
    
    if [[ $check_exit_code -ne 0 ]]; then
        print_error "配置验证失败 (退出码: ${check_exit_code})"
        echo -e "${YELLOW}错误详情:${NC}"
        echo "$check_output"
        echo ""
        echo -e "${YELLOW}配置文件内容:${NC}"
        cat "${CONFIG_FILE}"
        return 1
    fi
    
    if echo "$check_output" | grep -q "WARN"; then
        print_warning "配置验证通过，但有警告："
        echo "$check_output" | grep "WARN"
        echo ""
    else
        print_success "配置验证通过"
    fi
    
    print_info "启动 sing-box 服务..."
    svc_restart
    sleep 2
    
    if svc_is_active; then
        print_success "服务启动成功"
    else
        print_error "服务启动失败，查看日志："
        if [[ $ALPINE -eq 1 ]]; then
            tail -n 10 /var/log/messages | grep sing-box || cat /var/log/sing-box.log 2>/dev/null
        else
            journalctl -u sing-box -n 10 --no-pager
        fi
        return 1
    fi
}
# ==================== 结果显示 ====================
show_result() {
    clear
    echo ""
    menu_header "配置完成！"
    echo -e "${YELLOW}服务器信息:${NC}"
    echo -e "  协议: ${GREEN}${PROTO}${NC}"
    echo -e "  IP: ${GREEN}${SERVER_IP}${NC}"
    echo -e "  端口: ${GREEN}${PORT}${NC}"
    echo ""
    
    if [[ -n "$EXTRA_INFO" ]]; then
        echo -e "${YELLOW}协议详情:${NC}"
        echo -e "$EXTRA_INFO" | sed 's/^/  /'
        echo ""
    fi
    
    echo -e "${CYAN}───────────────────────────────────────────────────────${NC}"
    echo -e "${GREEN}📋 新添加的节点链接:${NC}"
    echo -e "${CYAN}───────────────────────────────────────────────────────${NC}"
    echo ""
    # 只显示新添加的节点链接
    if [[ -n "$CURRENT_NEW_LINKS" ]]; then
        echo -e "${YELLOW}${CURRENT_NEW_LINKS}${NC}"
    else
        echo -e "${YELLOW}${LINK}${NC}"
    fi
    echo ""
    echo -e "${CYAN}───────────────────────────────────────────────────────${NC}"
    echo ""
    echo -e "${CYAN}💡 提示: 去菜单的 [配置与查看] 可以查看全部节点链接${NC}"
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
    echo -e "${GREEN}[6]${NC} AnyTLS ${CYAN}→ 通用 TLS 协议，可启用 REALITY 伪装${NC}"
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
    menu_header "Sing-Box 一键管理面板"
    
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
        declare -A relay_proto_count
        for relay_tag in "${!relay_usage[@]}"; do
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
        declare -A relay_type_count
        for desc in "${RELAY_DESCS[@]}"; do
            local proto=$(echo "$desc" | cut -d' ' -f1)
            if [[ -n "${relay_type_count[$proto]}" ]]; then
                relay_type_count[$proto]=$((${relay_type_count[$proto]} + 1))
            else
                relay_type_count[$proto]=1
            fi
        done
        
        local relay_list=""
        for proto in "${!relay_type_count[@]}"; do
            [[ -n "$relay_list" ]] && relay_list+=", "
            relay_list+="${proto}:${relay_type_count[$proto]}"
        done
        
        echo -e "  ${YELLOW}中转列表: ${GREEN}${#RELAY_TAGS[@]} 个 [${relay_list}]${NC}"
        
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
            "AnyTLS+REALITY") ((anytls_count++)) ;;
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
        echo -e "  ${GREEN}[2]${NC} 中转配置 (添加/配置/删除/域名分流)"
        echo ""
        echo -e "  ${GREEN}[3]${NC} 出入站配置 (IPv4/IPv6)"
        echo ""
        echo -e "  ${GREEN}[4]${NC} 配置/查看节点"
        echo ""
        echo -e "  ${GREEN}[5]${NC} 重新生成链接文件"
        echo ""
        echo -e "  ${GREEN}[6]${NC} 一键删除脚本并退出"
        echo ""
        echo -e "  ${GREEN}[0]${NC} 退出脚本"
        echo ""
}

# ==================== 修改节点菜单 ====================
modify_node_menu() {
    if [[ ${#INBOUND_TAGS[@]} -eq 0 ]]; then
        print_warning "当前没有可修改的节点"
        return 1
    fi
    
    echo ""
    echo -e "${CYAN}请选择要修改的节点类型:${NC}"
    echo -e "  ${GREEN}[1]${NC} Reality 节点"
    echo -e "  ${GREEN}[2]${NC} Hysteria2 节点"
    echo -e "  ${GREEN}[3]${NC} SOCKS5 节点"
    echo -e "  ${GREEN}[4]${NC} ShadowTLS 节点"
    echo -e "  ${GREEN}[5]${NC} HTTPS 节点"
    echo -e "  ${GREEN}[6]${NC} AnyTLS 节点"
    echo -e "  ${GREEN}[0]${NC} 返回"
    echo ""
    read -p "请选择: " mod_type
    
    case $mod_type in
        1) modify_reality_node ;;
        2) modify_hysteria2_node ;;
        3) modify_socks5_node ;;
        4) modify_shadowtls_node ;;
        5) modify_https_node ;;
        6) modify_anytls_node ;;
        0) return 0 ;;
        *) print_error "无效选项" ;;
    esac
}

# ==================== 配置查看菜单 ====================
config_and_view_menu() {
    while true; do
        show_banner
        menu_header "配置 / 查看节点菜单"
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
        echo -e "  ${GREEN}[9]${NC} 修改节点配置"
        echo ""
        echo -e "  ${GREEN}[10]${NC} 删除单个节点"
        echo ""
        echo -e "  ${GREEN}[11]${NC} 删除全部节点"
        echo ""
        echo -e "  ${GREEN}[0]${NC} 返回主菜单"
        echo ""
        
        read -p "请选择 [0-11]: " cv_choice
        
        case $cv_choice in
            1)
                if [[ -f "${CONFIG_FILE}" ]]; then
                    if generate_config && start_svc; then
                        print_success "配置已重新加载并启动服务"
                    fi
                else
                    print_error "配置文件不存在，请先添加节点"
                fi
                pause "按回车返回..."
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
                pause "按回车返回..."
                ;;
            3)
                clear
                show_protocol_links "Reality 节点" "$REALITY_LINKS" "$YELLOW"
                [[ -z "$REALITY_LINKS" ]] && echo "(暂无 Reality 节点)"
                pause "按回车返回..."
                ;;
            4)
                clear
                show_protocol_links "Hysteria2 节点" "$HYSTERIA2_LINKS" "$YELLOW"
                [[ -z "$HYSTERIA2_LINKS" ]] && echo "(暂无 Hysteria2 节点)"
                pause "按回车返回..."
                ;;
            5)
                clear
                show_protocol_links "SOCKS5 节点" "$SOCKS5_LINKS" "$YELLOW"
                [[ -z "$SOCKS5_LINKS" ]] && echo "(暂无 SOCKS5 节点)"
                pause "按回车返回..."
                ;;
            6)
                clear
                show_protocol_links "ShadowTLS 节点" "$SHADOWTLS_LINKS" "$YELLOW"
                [[ -z "$SHADOWTLS_LINKS" ]] && echo "(暂无 ShadowTLS 节点)"
                [[ -n "$SHADOWTLS_LINKS" ]] && echo -e "${CYAN}提示: 可直接复制上方 ss:// 链接导入客户端 (Shadowrocket/NekoBox/v2rayN)${NC}"
                pause "按回车返回..."
                ;;
            7)
                clear
                show_protocol_links "HTTPS 节点" "$HTTPS_LINKS" "$YELLOW"
                [[ -z "$HTTPS_LINKS" ]] && echo "(暂无 HTTPS 节点)"
                pause "按回车返回..."
                ;;
            8)
                clear
                show_protocol_links "AnyTLS 节点" "$ANYTLS_LINKS" "$YELLOW"
                [[ -z "$ANYTLS_LINKS" ]] && echo "(暂无 AnyTLS 节点)"
                pause "按回车返回..."
                ;;
            9)
                modify_node_menu
                ;;
            10)
                delete_single_node
                pause "按回车返回..."
                ;;
            11)
                delete_all_nodes
                pause "按回车返回..."
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
    svc_stop
    svc_disable
    
    if [[ $ALPINE -eq 1 ]]; then
        if [[ -f /etc/init.d/sing-box ]]; then
            print_info "删除 OpenRC 服务..."
            rm -f /etc/init.d/sing-box
        fi
    else
        if [[ -f /etc/systemd/system/sing-box.service ]]; then
            print_info "删除 systemd 服务文件..."
            rm -f /etc/systemd/system/sing-box.service
            systemctl daemon-reload 2>/dev/null
        fi
    fi
    
    if [[ -d /run/sing-box ]]; then
        print_info "删除 sing-box 运行时文件..."
        rm -rf /run/sing-box 2>/dev/null
    fi
    
    if command -v sing-box &>/dev/null; then
        local sb_bin=$(command -v sing-box)
        print_info "删除 sing-box 二进制: ${sb_bin}"
        rm -f "${sb_bin}" 2>/dev/null
    else
        if [[ -f ${INSTALL_DIR}/sing-box ]]; then
            print_info "删除 sing-box 二进制: ${INSTALL_DIR}/sing-box"
            rm -f "${INSTALL_DIR}/sing-box" 2>/dev/null
        fi
    fi
    
    if [[ -d /etc/sing-box ]]; then
        print_info "删除 /etc/sing-box 配置目录..."
        rm -rf /etc/sing-box 2>/dev/null
    fi
    
    # 清理 logrotate 配置（Alpine）
    if [[ -f /etc/logrotate.d/sing-box ]]; then
        print_info "删除 logrotate 配置..."
        rm -f /etc/logrotate.d/sing-box 2>/dev/null
    fi
    
    if [[ -d ${CERT_DIR} ]]; then
        print_info "删除证书目录: ${CERT_DIR}"
        rm -rf "${CERT_DIR}" 2>/dev/null
    fi
    
    if [[ -d "${LINK_DIR}" ]]; then
        print_info "删除链接文件目录: ${LINK_DIR}"
        rm -rf "${LINK_DIR}" 2>/dev/null
    fi
    
    if [[ -f "${KEY_FILE}" ]]; then
        print_info "删除密钥文件: ${KEY_FILE}"
        rm -f "${KEY_FILE}" 2>/dev/null
    fi
    
    if [[ -d /var/log/sing-box ]]; then
        print_info "删除 sing-box 日志目录..."
        rm -rf /var/log/sing-box 2>/dev/null
    fi
    
    # 清理 journal 日志 (仅 systemd)
    if [[ $ALPINE -eq 0 ]] && command -v journalctl &>/dev/null; then
        print_info "清理 systemd journal 日志..."
        journalctl --vacuum-time=1s --quiet 2>/dev/null || true
    fi
    
    print_info "清理临时文件..."
    rm -f /tmp/sb.tar.gz 2>/dev/null
    rm -rf /tmp/sing-box-* 2>/dev/null
    
    print_info "删除快捷命令 sb..."
    for cmd in /usr/local/bin/sb /usr/bin/sb /usr/local/sbin/sb /usr/sbin/sb; do
        if [[ -f "$cmd" ]]; then
            print_info "删除快捷命令: $cmd"
            rm -f "$cmd" 2>/dev/null
        fi
    done
    
    print_info "删除当前脚本文件: ${SCRIPT_PATH}"
    rm -f "${SCRIPT_PATH}" 2>/dev/null
    
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

# ==================== 域名分流配置菜单 ====================
domain_route_menu() {
    while true; do
        # 加载最新的分流规则、中转和入站配置
        load_domain_routes_from_file
        load_relays_from_file
        
        show_banner
        menu_header "域名分流配置菜单"
        
        # 显示当前的分流规则（按入站节点分组）
        echo -e "${YELLOW}当前分流规则 (共 ${#DOMAIN_ROUTES[@]} 条):${NC}"
        if [[ ${#DOMAIN_ROUTES[@]} -eq 0 ]]; then
            echo "  (暂无分流规则)"
        else
            # 先按入站节点分组
            unset inbound_rules 2>/dev/null
            declare -A inbound_rules
            for route in "${DOMAIN_ROUTES[@]}"; do
                IFS='|' read -r inbound_tag match_type match_value relay_tag desc <<< "$route"
                inbound_rules["$inbound_tag"]+="$route;"
            done
            
            # 显示每个入站节点的分组
            local global_idx=1
            for inbound_tag in "${!inbound_rules[@]}"; do
                # 获取该入站节点的详细信息
                local inbound_proto=""
                local inbound_port=""
                local inbound_relay_tag=""
                local inbound_relay_info=""
                
                for i in "${!INBOUND_TAGS[@]}"; do
                    if [[ "${INBOUND_TAGS[$i]}" == "$inbound_tag" ]]; then
                        inbound_proto="${INBOUND_PROTOS[$i]}"
                        inbound_port="${INBOUND_PORTS[$i]}"
                        inbound_relay_tag="${INBOUND_RELAY_TAGS[$i]}"
                        break
                    fi
                done
                
                # 获取入站节点的连接状态信息
                if [[ "$inbound_relay_tag" == "direct" || -z "$inbound_relay_tag" ]]; then
                    # 直连状态
                    inbound_relay_info="📡 直连"
                elif [[ -n "$inbound_relay_tag" ]]; then
                    # 从 RELAY_JSONS 中提取中转配置信息
                    for j in "${!RELAY_TAGS[@]}"; do
                        if [[ "${RELAY_TAGS[$j]}" == "$inbound_relay_tag" ]]; then
                            local relay_json="${RELAY_JSONS[$j]}"
                            # 提取中转协议类型
                            local relay_type=$(echo "$relay_json" | grep -o '"type": "[^"]*"' | cut -d'"' -f4 | tr '[:lower:]' '[:upper:]')
                            # 提取服务器地址
                            local relay_server=$(echo "$relay_json" | grep -o '"server": "[^"]*"' | cut -d'"' -f4)
                            # 提取端口
                            local relay_port=$(echo "$relay_json" | grep -o '"server_port": [0-9]*' | grep -o '[0-9]*')
                            
                            if [[ -n "$relay_type" && -n "$relay_server" && -n "$relay_port" ]]; then
                                inbound_relay_info="📍 中转: ${relay_type} ${relay_server}:${relay_port}"
                            fi
                            break
                        fi
                    done
                fi
                
                # 显示入站节点和连接状态
                echo ""
                echo -e "  ${CYAN}▶ ${inbound_proto}:${inbound_port}${NC}"
                echo -e "  ${CYAN}   ${inbound_relay_info}${NC}"
                
                # 显示分流规则
                IFS=';' read -ra routes_array <<< "${inbound_rules[$inbound_tag]}"
                
                for route in "${routes_array[@]}"; do
                    [[ -z "$route" ]] && continue
                    
                    IFS='|' read -r tag mtype mval rtag rdesc <<< "$route"
                    if [[ -n "$mval" ]]; then
                        # 获取中转节点的描述
                        local relay_node_desc="$rtag"
                        for j in "${!RELAY_TAGS[@]}"; do
                            if [[ "${RELAY_TAGS[$j]}" == "$rtag" ]]; then
                                relay_node_desc="${RELAY_DESCS[$j]}"
                                break
                            fi
                        done
                        
                        local match_display=""
                        case "$mtype" in
                            domain_suffix) match_display="域名后缀" ;;
                            domain) match_display="完整域名" ;;
                            domain_keyword) match_display="关键词" ;;
                            ip_cidr) match_display="IP/CIDR" ;;
                            *) match_display="$mtype" ;;
                        esac
                        
                        echo -e "    ${GREEN}[${global_idx}]${NC} ${match_display}: ${mval} -> ${relay_node_desc}"
                        ((global_idx++))
                    fi
                done
            done
        fi
        echo ""
        
        echo -e "  ${GREEN}[1]${NC} 添加分流规则"
        echo ""
        echo -e "  ${GREEN}[2]${NC} 删除单个分流规则"
        echo ""
        echo -e "  ${GREEN}[3]${NC} 清空所有分流规则"
        echo ""
        echo -e "  ${GREEN}[0]${NC} 返回主菜单"
        echo ""
        
        read -p "请选择 [0-3]: " dr_choice
        
        case $dr_choice in
            1)
                add_domain_route
                ;;
            2)
                delete_domain_route
                ;;
            3)
                echo ""
                echo -e "${YELLOW}此操作将删除所有分流规则！${NC}"
                if confirm "确认清空？(y/N): "; then
                    DOMAIN_ROUTES=()
                    save_domain_routes_to_file
                    print_success "已清空所有分流规则"
                    # 重新生成配置
                    if [[ -n "$INBOUNDS_JSON" ]]; then
                        generate_config && start_svc
                    fi
                fi
                ;;
            0)
                break
                ;;
            *)
                print_error "无效选项"
                ;;
        esac
        echo ""
        pause
    done
}

add_domain_route() {
    # 检查是否有入站节点和中转节点
    if [[ ${#INBOUND_TAGS[@]} -eq 0 ]]; then
        print_error "没有可用的入站节点，请先添加节点"
        return 1
    fi
    if [[ ${#RELAY_TAGS[@]} -eq 0 ]]; then
        print_error "没有可用的中转节点，请先添加中转"
        return 1
    fi
    
    echo ""
    echo -e "${CYAN}选择要配置分流的入站节点:${NC}"
    local idx=1
    for i in "${!INBOUND_TAGS[@]}"; do
        echo -e "  ${GREEN}[${idx}]${NC} ${INBOUND_PROTOS[$i]}:${INBOUND_PORTS[$i]} (${INBOUND_TAGS[$i]})"
        ((idx++))
    done
    echo ""
    
    read -p "请选择 [1-$((idx-1))]: " inbound_idx
    if ! [[ "$inbound_idx" =~ ^[0-9]+$ ]] || [[ "$inbound_idx" -lt 1 ]] || [[ "$inbound_idx" -ge "$idx" ]]; then
        print_error "无效选项"
        return 1
    fi
    ((inbound_idx--))
    local selected_inbound="${INBOUND_TAGS[$inbound_idx]}"
    
    echo ""
    echo -e "${CYAN}选择匹配类型:${NC}"
    echo -e "  ${GREEN}[1]${NC} domain_suffix - 域名后缀匹配 (推荐，如 time.is 匹配 time.is, a.time.is)"
    echo -e "  ${GREEN}[2]${NC} domain - 完整域名匹配 (如 www.time.is 只匹配该域名)"
    echo -e "  ${GREEN}[3]${NC} domain_keyword - 关键词匹配 (如 time 匹配所有含 time 的域名)"
    echo -e "  ${GREEN}[4]${NC} ip_cidr - IP/CIDR 匹配 (如 1.2.3.4 或 1.2.3.0/24)"
    echo ""
    
    read -p "请选择 [1-4]: " type_idx
    local match_type=""
    case "$type_idx" in
        1) match_type="domain_suffix" ;;
        2) match_type="domain" ;;
        3) match_type="domain_keyword" ;;
        4) match_type="ip_cidr" ;;
        *)
            print_error "无效选项"
            return 1
            ;;
    esac
    
    echo ""
    echo -e "${CYAN}输入要分流的域名或IP (支持多个，用英文逗号分隔):${NC}"
    echo -e "${YELLOW}示例: time.is, ip.sb, youtube.com${NC}"
    echo -e "${YELLOW}       1.2.3.4, 5.6.7.0/24${NC}"
    echo ""
    read -p "请输入: " match_input
    
    # 预处理输入：替换中文逗号为英文逗号，并去除空格
    match_input=$(echo "$match_input" | sed 's/，/,/g' | tr -d ' ')
    
    if [[ -z "$match_input" ]]; then
        print_error "输入不能为空"
        return 1
    fi
    
    # 检查是否包含逗号，决定是单个还是批量
    local is_batch=0
    if [[ "$match_input" == *,* ]]; then
        is_batch=1
    fi
    
    echo ""
    echo -e "${CYAN}选择要使用的中转节点:${NC}"
    idx=1
    for i in "${!RELAY_TAGS[@]}"; do
        echo -e "  ${GREEN}[${idx}]${NC} ${RELAY_DESCS[$i]}"
        ((idx++))
    done
    echo ""
    
    read -p "请选择 [1-$((idx-1))]: " relay_idx
    if ! [[ "$relay_idx" =~ ^[0-9]+$ ]] || [[ "$relay_idx" -lt 1 ]] || [[ "$relay_idx" -ge "$idx" ]]; then
        print_error "无效选项"
        return 1
    fi
    ((relay_idx--))
    local selected_relay="${RELAY_TAGS[$relay_idx]}"
    local selected_relay_desc="${RELAY_DESCS[$relay_idx]}"
    
    echo ""
    read -p "请输入描述 (可选): " desc
    if [[ -z "$desc" ]]; then
        if [[ $is_batch -eq 1 ]]; then
            desc="批量分流规则"
        else
            desc="分流规则"
        fi
    fi
    
    # 批量添加分流规则
    if [[ $is_batch -eq 1 ]]; then
        # 使用 IFS 分割字符串
        IFS=',' read -ra MATCH_VALUES <<< "$match_input"
        local added_count=0
        local base_idx=${#DOMAIN_ROUTES[@]}
        
        for match_value in "${MATCH_VALUES[@]}"; do
            # 去除首尾空格
            match_value=$(echo "$match_value" | xargs)
            if [[ -n "$match_value" ]]; then
                local route_str="${selected_inbound}|${match_type}|${match_value}|${selected_relay}|${desc}"
                DOMAIN_ROUTES+=("$route_str")
                ((added_count++))
            fi
        done
        
        if [[ $added_count -gt 0 ]]; then
            save_domain_routes_to_file
            print_success "已添加 ${added_count} 条分流规则到入站 ${selected_inbound}，全部走 ${selected_relay_desc}"
            echo ""
            echo -e "${CYAN}添加的域名/IP:${NC}"
            for match_value in "${MATCH_VALUES[@]}"; do
                match_value=$(echo "$match_value" | xargs)
                if [[ -n "$match_value" ]]; then
                    echo -e "  ${GREEN}✓${NC} ${match_value}"
                fi
            done
        fi
    else
        # 单个添加
        local route_str="${selected_inbound}|${match_type}|${match_input}|${selected_relay}|${desc}"
        DOMAIN_ROUTES+=("$route_str")
        save_domain_routes_to_file
        print_success "分流规则已添加: ${match_input} -> ${selected_relay_desc}"
    fi
    
    # 重新生成配置
    if [[ -n "$INBOUNDS_JSON" ]]; then
        echo ""
        if confirm "是否立即重新生成配置并生效？(y/N): "; then
            generate_config && start_svc
        fi
    fi
}

delete_domain_route() {
    if [[ ${#DOMAIN_ROUTES[@]} -eq 0 ]]; then
        print_warning "没有可删除的分流规则"
        return 0
    fi
    
    echo ""
    echo -e "${CYAN}选择要删除的分流规则 (按入站节点分组):${NC}"
    echo ""
    
    # 为每条规则创建带有原始索引的结构，同时按入站分组
    declare -A inbound_groups
    local -A index_map
    local display_idx=1
    
    for orig_idx in "${!DOMAIN_ROUTES[@]}"; do
        local route="${DOMAIN_ROUTES[$orig_idx]}"
        IFS='|' read -r inbound_tag match_type match_value relay_tag desc <<< "$route"
        
        # 存储分组信息
        if [[ -z "${inbound_groups[$inbound_tag]}" ]]; then
            inbound_groups[$inbound_tag]="$orig_idx|$route"
        else
            inbound_groups[$inbound_tag]="${inbound_groups[$inbound_tag]}
$orig_idx|$route"
        fi
    done
    
    # 显示规则并记录显示索引到原始索引的映射
    for inbound_tag in "${!inbound_groups[@]}"; do
        # 获取该入站节点的详细信息
        local inbound_proto=""
        local inbound_port=""
        local inbound_relay_tag=""
        local inbound_relay_info=""
        
        for i in "${!INBOUND_TAGS[@]}"; do
            if [[ "${INBOUND_TAGS[$i]}" == "$inbound_tag" ]]; then
                inbound_proto="${INBOUND_PROTOS[$i]}"
                inbound_port="${INBOUND_PORTS[$i]}"
                inbound_relay_tag="${INBOUND_RELAY_TAGS[$i]}"
                break
            fi
        done
        
        # 获取入站节点的连接状态信息
        if [[ "$inbound_relay_tag" == "direct" || -z "$inbound_relay_tag" ]]; then
            # 直连状态
            inbound_relay_info="📡 直连"
        elif [[ -n "$inbound_relay_tag" ]]; then
            # 从 RELAY_JSONS 中提取中转配置信息
            for j in "${!RELAY_TAGS[@]}"; do
                if [[ "${RELAY_TAGS[$j]}" == "$inbound_relay_tag" ]]; then
                    local relay_json="${RELAY_JSONS[$j]}"
                    # 提取中转协议类型
                    local relay_type=$(echo "$relay_json" | grep -o '"type": "[^"]*"' | cut -d'"' -f4 | tr '[:lower:]' '[:upper:]')
                    # 提取服务器地址
                    local relay_server=$(echo "$relay_json" | grep -o '"server": "[^"]*"' | cut -d'"' -f4)
                    # 提取端口
                    local relay_port=$(echo "$relay_json" | grep -o '"server_port": [0-9]*' | grep -o '[0-9]*')
                    
                    if [[ -n "$relay_type" && -n "$relay_server" && -n "$relay_port" ]]; then
                        inbound_relay_info="📍 中转: ${relay_type} ${relay_server}:${relay_port}"
                    fi
                    break
                fi
            done
        fi
        
        echo -e "  ${CYAN}▶ ${inbound_proto}:${inbound_port}${NC}"
        echo -e "  ${CYAN}   ${inbound_relay_info}${NC}"
        
        local grouped_str="${inbound_groups[$inbound_tag]}"
        local grouped_array=()
        while IFS= read -r line; do
            [[ -n "$line" ]] && grouped_array+=("$line")
        done <<< "$grouped_str"
        
        for item in "${grouped_array[@]}"; do
            IFS='|' read -r orig_idx tag mtype mval rtag rdesc <<< "$item"
            
            # 记录显示索引到原始索引的映射
            index_map[$display_idx]="$orig_idx"
            
            # 获取中转节点的描述
            local relay_node_desc="$rtag"
            for j in "${!RELAY_TAGS[@]}"; do
                if [[ "${RELAY_TAGS[$j]}" == "$rtag" ]]; then
                    relay_node_desc="${RELAY_DESCS[$j]}"
                    break
                fi
            done
            
            local match_display=""
            case "$mtype" in
                domain_suffix) match_display="域名后缀" ;;
                domain) match_display="完整域名" ;;
                domain_keyword) match_display="关键词" ;;
                ip_cidr) match_display="IP/CIDR" ;;
                *) match_display="$mtype" ;;
            esac
            
            echo -e "    ${GREEN}[${display_idx}]${NC} ${match_display}: ${mval} -> ${relay_node_desc}"
            ((display_idx++))
        done
        echo ""
    done
    
    local max_idx=$((display_idx - 1))
    read -p "请选择要删除的规则编号 [1-$max_idx]: " delete_idx
    if ! [[ "$delete_idx" =~ ^[0-9]+$ ]] || [[ "$delete_idx" -lt 1 ]] || [[ "$delete_idx" -gt "$max_idx" ]]; then
        print_error "无效选项"
        return 1
    fi
    
    # 获取对应的原始索引
    local orig_idx_to_delete="${index_map[$delete_idx]}"
    local to_delete="${DOMAIN_ROUTES[$orig_idx_to_delete]}"
    IFS='|' read -r del_inbound del_type del_value del_relay del_desc <<< "$to_delete"
    
    # 构建新数组，排除要删除的元素（使用原始索引）
    local new_routes=()
    for i in "${!DOMAIN_ROUTES[@]}"; do
        if [[ "$i" -ne "$orig_idx_to_delete" ]]; then
            new_routes+=("${DOMAIN_ROUTES[$i]}")
        fi
    done
    DOMAIN_ROUTES=("${new_routes[@]}")
    
    save_domain_routes_to_file
    
    echo ""
    print_success "已删除分流规则: ${del_type}:${del_value}"
    echo -e "  ${CYAN}入站节点: ${del_inbound}${NC}"
    
    # 重新生成配置
    if [[ -n "$INBOUNDS_JSON" ]]; then
        echo ""
        if confirm "是否立即重新生成配置并生效？(y/N): "; then
            generate_config && start_svc
        fi
    fi
}

# ==================== 主循环 ====================
main_menu() {
    while true; do
        # 每次显示菜单前，从配置文件重新加载节点信息、中转配置和 IP 配置
        if [[ -f "${CONFIG_FILE}" ]]; then
            load_inbounds_from_config
        fi
        load_relays_from_file
        load_ip_config
        
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
        pause "按回车返回主菜单..."
    done
}

setup_sb_shortcut() {
    print_info "创建快捷命令 sb..."
    
    local sb_target="/etc/sing-box/install.sh"
    
    # 确保脚本在标准位置
    if [[ ! -f "${SCRIPT_PATH}" ]]; then
        print_warning "脚本不在磁盘上，跳过创建 sb"
        return
    fi
    
    # 如果脚本不在标准位置，复制一份
    if [[ "${SCRIPT_PATH}" != "${sb_target}" ]]; then
        cp "${SCRIPT_PATH}" "${sb_target}" 2>/dev/null && chmod +x "${sb_target}"
        SCRIPT_PATH="${sb_target}"
    fi
    
    cat > /usr/local/bin/sb << EOSB
#!/bin/sh
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
    
    # 如果脚本不在磁盘上（如 curl|bash 方式运行），先保存到磁盘再重新执行
    local sb_script="/etc/sing-box/install.sh"
    if [[ ! -f "${SCRIPT_PATH}" ]]; then
        mkdir -p /etc/sing-box
        # 尝试从 BASH_SOURCE 获取
        local script_src="${BASH_SOURCE[0]:-$0}"
        if [[ -f "${script_src}" ]]; then
            cp "${script_src}" "${sb_script}" 2>/dev/null
        fi
        # 如果 BASH_SOURCE 也不可用，从 GitHub 重新下载
        if [[ ! -f "${sb_script}" ]]; then
            print_info "脚本不在磁盘上，从 GitHub 下载到 ${sb_script} ..."
            # 自动检测仓库 URL
            _repo_raw=""
            _script_url="${BASH_SOURCE[0]:-$0}"
            if [[ "$_script_url" =~ ^https?:// ]]; then
                _repo_raw="$_script_url"
            else
                _pp_cmdline=$(cat /proc/$PPID/cmdline 2>/dev/null | tr '\0' ' ')
                for _word in $_pp_cmdline; do
                    if [[ "$_word" =~ ^https://raw\.githubusercontent\.com/.*install\.sh$ ]]; then
                        _repo_raw="$_word"
                        break
                    fi
                done
            fi
            [[ -z "$_repo_raw" ]] && _repo_raw="https://raw.githubusercontent.com/Kiss8202/Trae/main/install.sh"
            wget -q -O "${sb_script}" "$_repo_raw" 2>/dev/null || curl -sL -o "${sb_script}" "$_repo_raw" 2>/dev/null || true
            unset _repo_raw _script_url _pp_cmdline _word
        fi
        if [[ -f "${sb_script}" ]]; then
            chmod +x "${sb_script}"
            print_success "脚本已保存到 ${sb_script}，重新执行..."
            exec bash "${sb_script}" "$@"
        fi
    fi
    
    detect_system
    install_singbox
    mkdir -p /etc/sing-box
    gen_keys
    
    # 先加载 IP 配置（如果存在）
    load_ip_config
    
    get_ip
    
    setup_sb_shortcut
    
    # 从配置文件加载节点信息
    if [[ -f "${CONFIG_FILE}" ]]; then
        load_inbounds_from_config
    fi
    
    # 加载中转配置
    load_relays_from_file
    
    # 从配置文件重新生成链接（避免加载旧链接文件）
    if [[ -f "${CONFIG_FILE}" ]]; then
        cleanup_links
        regenerate_links_from_config
    fi
    
    # 如果配置文件存在但链接文件为空，自动重新生成链接
    if [[ -f "${CONFIG_FILE}" ]] && [[ -z "$ALL_LINKS_TEXT" ]]; then
        print_info "检测到链接文件缺失，正在重新生成..."
        regenerate_links_from_config
    fi
    
    main_menu
}

main "$@"
