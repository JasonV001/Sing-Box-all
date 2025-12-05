#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'

AUTHOR_BLOG="${SERVER_IP}"
CONFIG_FILE="/etc/sing-box/config.json"
INSTALL_DIR="/usr/local/bin"
CERT_DIR="/etc/sing-box/certs"

# 链接保存目录
LINK_DIR="/etc/sing-box/links"
ALL_LINKS_FILE="${LINK_DIR}/all.txt"
REALITY_LINKS_FILE="${LINK_DIR}/reality.txt"
HYSTERIA2_LINKS_FILE="${LINK_DIR}/hysteria2.txt"
SOCKS5_LINKS_FILE="${LINK_DIR}/socks5.txt"
SHADOWTLS_LINKS_FILE="${LINK_DIR}/shadowtls.txt"
HTTPS_LINKS_FILE="${LINK_DIR}/https.txt"
ANYTLS_LINKS_FILE="${LINK_DIR}/anytls.txt"

# 密钥保存文件
KEY_FILE="/etc/sing-box/keys.txt"

SCRIPT_PATH=$(readlink -f "$0" 2>/dev/null || realpath "$0" 2>/dev/null || echo "$0")
INBOUNDS_JSON=""
OUTBOUND_TAG="direct"
ALL_LINKS_TEXT=""
REALITY_LINKS=""
HYSTERIA2_LINKS=""
SOCKS5_LINKS=""
SHADOWTLS_LINKS=""
HTTPS_LINKS=""
ANYTLS_LINKS=""
SELECTED_RELAY_TAG=""
SELECTED_RELAY_DESC=""

INBOUND_TAGS=()
INBOUND_PORTS=()
INBOUND_PROTOS=()
INBOUND_RELAY_FLAGS=()
INBOUND_SNIS=()  # 存储每个节点的SNI

RELAY_JSON=""

# 关键密钥变量
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

# 默认自签证书域名
DEFAULT_SNI="time.is"

print_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }

show_banner() {
    clear
    echo ""
}

detect_system() {
    [[ -f /etc/os-release ]] && . /etc/os-release || { print_error "无法检测系统"; exit 1; }
    OS="${NAME}"
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        *) print_error "不支持的架构: $ARCH"; exit 1 ;;
    esac
    print_success "系统: ${OS} (${ARCH})"
}

install_singbox() {
    print_info "检查依赖和 sing-box..."
    
    # 修改：只安装必需的依赖
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
    [[ -z "$LATEST" ]] && LATEST="1.12.0"
    
    print_info "目标版本: ${LATEST}"
    
    wget -q --show-progress -O /tmp/sb.tar.gz "https://github.com/SagerNet/sing-box/releases/download/v${LATEST}/sing-box-${LATEST}-linux-${ARCH}.tar.gz" 2>&1
    
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
    systemctl enable sing-box >/dev/null 2>&1
    
    print_success "sing-box 安装完成 (版本: ${LATEST})"
}

# 为特定节点生成证书
gen_cert_for_sni() {
    local sni="$1"
    local node_cert_dir="${CERT_DIR}/${sni}"
    
    mkdir -p "${node_cert_dir}"
    
    openssl genrsa -out "${node_cert_dir}/private.key" 2048 2>/dev/null
    openssl req -new -x509 -days 36500 -key "${node_cert_dir}/private.key" -out "${node_cert_dir}/cert.pem" \
        -subj "/C=US/ST=California/L=Cupertino/O=Apple Inc./CN=${sni}" 2>/dev/null
    
    print_success "证书生成完成（${sni}，有效期100年）"
}

gen_keys() {
    print_info "生成密钥和 UUID..."
    
    # 如果密钥文件已存在，则加载它
    if [[ -f "${KEY_FILE}" ]]; then
        print_info "从文件加载已保存的密钥..."
        . "${KEY_FILE}"
        print_success "密钥加载完成"
        return 0
    fi
    
    # 生成新的密钥
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
    
    # 保存密钥到文件
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

# 保存链接到文件
save_links_to_files() {
    mkdir -p "${LINK_DIR}"
    
    # 保存到文件（不带转义符，实际换行）
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
    
    if [[ -f "${ALL_LINKS_FILE}" ]]; then
        ALL_LINKS_TEXT=$(cat "${ALL_LINKS_FILE}")
    fi
    if [[ -f "${REALITY_LINKS_FILE}" ]]; then
        REALITY_LINKS=$(cat "${REALITY_LINKS_FILE}")
    fi
    if [[ -f "${HYSTERIA2_LINKS_FILE}" ]]; then
        HYSTERIA2_LINKS=$(cat "${HYSTERIA2_LINKS_FILE}")
    fi
    if [[ -f "${SOCKS5_LINKS_FILE}" ]]; then
        SOCKS5_LINKS=$(cat "${SOCKS5_LINKS_FILE}")
    fi
    if [[ -f "${SHADOWTLS_LINKS_FILE}" ]]; then
        SHADOWTLS_LINKS=$(cat "${SHADOWTLS_LINKS_FILE}")
    fi
    if [[ -f "${HTTPS_LINKS_FILE}" ]]; then
        HTTPS_LINKS=$(cat "${HTTPS_LINKS_FILE}")
    fi
    if [[ -f "${ANYTLS_LINKS_FILE}" ]]; then
        ANYTLS_LINKS=$(cat "${ANYTLS_LINKS_FILE}")
    fi
}

# 从配置文件加载 INBOUNDS_JSON 和节点信息
load_inbounds_from_config() {
    print_info "正在从配置文件加载节点配置..."
    
    # 清空变量
    INBOUNDS_JSON=""
    INBOUND_TAGS=()
    INBOUND_PORTS=()
    INBOUND_PROTOS=()
    INBOUND_RELAY_FLAGS=()
    INBOUND_SNIS=()
    
    if [[ ! -f "${CONFIG_FILE}" ]]; then
        print_warning "配置文件不存在，无法加载节点配置"
        return 1
    fi
    
    if ! command -v jq &>/dev/null; then
        print_warning "jq命令未安装，无法解析配置文件"
        return 1
    fi
    
    # 获取所有 inbounds
    local inbounds_count=$(jq '.inbounds | length' "${CONFIG_FILE}" 2>/dev/null || echo "0")
    
    if [[ "$inbounds_count" -eq 0 ]]; then
        print_warning "配置文件中没有找到inbounds"
        return 1
    fi
    
    print_info "找到 ${inbounds_count} 个 inbound 配置"
    
    # 构建 INBOUNDS_JSON
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
        
        # 提取信息到数组
        local tag=$(echo "$inbound" | jq -r '.tag' 2>/dev/null || echo "unknown")
        local port=$(echo "$inbound" | jq -r '.listen_port' 2>/dev/null || echo "0")
        local type=$(echo "$inbound" | jq -r '.type' 2>/dev/null || echo "unknown")
        
        # 根据 tag 判断协议类型
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
        
        # 如果没有获取到SNI，使用默认值
        if [[ -z "$sni" ]]; then
            sni="${DEFAULT_SNI}"
        fi
        
        INBOUND_TAGS+=("$tag")
        INBOUND_PORTS+=("$port")
        INBOUND_PROTOS+=("$proto")
        INBOUND_SNIS+=("$sni")
        INBOUND_RELAY_FLAGS+=(0)  # 默认直连
    done
    
    INBOUNDS_JSON="$inbound_list"
    
    # 加载中转配置
    if jq -e '.outbounds[] | select(.tag == "relay")' "${CONFIG_FILE}" >/dev/null 2>&1; then
        RELAY_JSON=$(jq -c '.outbounds[] | select(.tag == "relay")' "${CONFIG_FILE}")
        OUTBOUND_TAG="relay"
        
        # 尝试获取路由规则，确定哪些inbound走中转
        local rule_inbounds=$(jq -r '.route.rules[0].inbound[]?' "${CONFIG_FILE}" 2>/dev/null)
        if [[ -n "$rule_inbounds" ]]; then
            while IFS= read -r inbound_tag; do
                for idx in "${!INBOUND_TAGS[@]}"; do
                    if [[ "${INBOUND_TAGS[$idx]}" == "$inbound_tag" ]]; then
                        INBOUND_RELAY_FLAGS[$idx]=1
                        break
                    fi
                done
            done <<< "$rule_inbounds"
        fi
    else
        RELAY_JSON=""
        OUTBOUND_TAG="direct"
    fi
    
    print_success "节点配置加载完成"
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
        print_info "从密钥文件加载密钥..."
        . "${KEY_FILE}"
    fi
    
    # 确保 SERVER_IP 已设置
    if [[ -z "${SERVER_IP}" ]]; then
        get_ip
    fi
    
    if [[ ! -f "${CONFIG_FILE}" ]]; then
        print_warning "配置文件不存在，无法重新生成链接"
        return 1
    fi
    
    if ! command -v jq &>/dev/null; then
        print_warning "jq命令未安装，无法解析配置文件"
        return 1
    fi
    
    # 获取所有inbounds
    local inbounds_count=$(jq '.inbounds | length' "${CONFIG_FILE}" 2>/dev/null || echo "0")
    
    if [[ "$inbounds_count" -eq 0 ]]; then
        print_warning "配置文件中没有找到inbounds"
        return 1
    fi
    
    print_info "从配置文件中找到 ${inbounds_count} 个inbound配置"
    
    # 遍历每个inbound
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
                # 检查是否是Reality
                local tls_enabled=$(echo "$inbound" | jq -r '.tls.enabled // false' 2>/dev/null)
                if [[ "$tls_enabled" == "true" ]]; then
                    local reality_enabled=$(echo "$inbound" | jq -r '.tls.reality.enabled // false' 2>/dev/null)
                    if [[ "$reality_enabled" == "true" ]]; then
                        # Reality
                        local uuid=$(echo "$inbound" | jq -r '.users[0].uuid // ""' 2>/dev/null)
                        local sni=$(echo "$inbound" | jq -r '.tls.server_name // ""' 2>/dev/null)
                        local pbk=$(echo "$inbound" | jq -r '.tls.reality.public_key // ""' 2>/dev/null)
                        local sid=$(echo "$inbound" | jq -r '.tls.reality.short_id[0] // ""' 2>/dev/null)
                        
                        # 如果没有从配置文件获取到UUID，使用密钥文件中的UUID
                        if [[ -z "$uuid" && -n "${UUID}" ]]; then
                            uuid="${UUID}"
                        fi
                        
                        # 如果没有从配置文件获取到公钥，使用密钥文件中的公钥
                        if [[ -z "$pbk" && -n "${REALITY_PUBLIC}" ]]; then
                            pbk="${REALITY_PUBLIC}"
                        fi
                        
                        # 如果没有从配置文件获取到短ID，使用密钥文件中的短ID
                        if [[ -z "$sid" && -n "${SHORT_ID}" ]]; then
                            sid="${SHORT_ID}"
                        fi
                        
                        # 如果没有SNI，使用默认值
                        if [[ -z "$sni" ]]; then
                            sni="${DEFAULT_SNI}"
                        fi
                        
                        if [[ -n "$uuid" && -n "$pbk" ]]; then
                            local link="vless://${uuid}@${SERVER_IP}:${port}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${sni}&fp=chrome&pbk=${pbk}&sid=${sid}&type=tcp#Reality-${SERVER_IP}"
                            local line="[Reality] ${SERVER_IP}:${port} (SNI: ${sni})\n${link}\n"
                            ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}\n"
                            REALITY_LINKS="${REALITY_LINKS}${line}\n"
                        fi
                    else
                        # HTTPS
                        local uuid=$(echo "$inbound" | jq -r '.users[0].uuid // ""' 2>/dev/null)
                        local sni=$(echo "$inbound" | jq -r '.tls.server_name // ""' 2>/dev/null)
                        
                        if [[ -z "$uuid" && -n "${UUID}" ]]; then
                            uuid="${UUID}"
                        fi
                        
                        # 如果没有SNI，使用默认值
                        if [[ -z "$sni" ]]; then
                            sni="${DEFAULT_SNI}"
                        fi
                        
                        if [[ -n "$uuid" ]]; then
                            local link="vless://${uuid}@${SERVER_IP}:${port}?encryption=none&security=tls&sni=${sni}&type=tcp&allowInsecure=1#HTTPS-${SERVER_IP}"
                            local line="[HTTPS] ${SERVER_IP}:${port} (SNI: ${sni})\n${link}\n"
                            ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}\n"
                            HTTPS_LINKS="${HTTPS_LINKS}${line}\n"
                        fi
                    fi
                fi
                ;;
            "hysteria2")
                local password=$(echo "$inbound" | jq -r '.users[0].password // ""' 2>/dev/null)
                local sni=$(echo "$inbound" | jq -r '.tls.server_name // ""' 2>/dev/null)
                
                # 如果没有SNI，使用默认值
                if [[ -z "$sni" ]]; then
                    sni="${DEFAULT_SNI}"
                fi
                
                if [[ -n "$password" ]]; then
                    local link="hysteria2://${password}@${SERVER_IP}:${port}?insecure=1&sni=${sni}#Hysteria2-${SERVER_IP}"
                    local line="[Hysteria2] ${SERVER_IP}:${port} (SNI: ${sni})\n${link}\n"
                    ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}\n"
                    HYSTERIA2_LINKS="${HYSTERIA2_LINKS}${line}\n"
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
                    local line="[SOCKS5] ${SERVER_IP}:${port}\n${link}\n"
                    ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}\n"
                    SOCKS5_LINKS="${SOCKS5_LINKS}${line}\n"
                fi
                ;;
            "shadowtls")
                # ShadowTLS 需要特殊处理
                local password=$(echo "$inbound" | jq -r '.users[0].password // ""' 2>/dev/null)
                local sni=$(echo "$inbound" | jq -r '.handshake.server // ""' 2>/dev/null)
                
                # 如果没有SNI，使用默认值
                if [[ -z "$sni" ]]; then
                    sni="${DEFAULT_SNI}"
                fi
                
                if [[ -n "$password" ]]; then
                    # 简化处理，只标记存在
                    local line="[ShadowTLS v3] ${SERVER_IP}:${port} (SNI: ${sni}) (需要手动查看配置)\n"
                    ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}\n"
                    SHADOWTLS_LINKS="${SHADOWTLS_LINKS}${line}\n"
                fi
                ;;
            "anytls")
                local password=$(echo "$inbound" | jq -r '.users[0].password // ""' 2>/dev/null)
                local sni=$(echo "$inbound" | jq -r '.tls.server_name // ""' 2>/dev/null)
                
                # 如果没有SNI，使用默认值
                if [[ -z "$sni" ]]; then
                    sni="${DEFAULT_SNI}"
                fi
                
                if [[ -n "$password" ]]; then
                    # 使用 chrome 指纹，无需获取证书指纹
                    local link_v2rayn="anytls://${password}@${SERVER_IP}:${port}?security=tls&fp=chrome&insecure=1&sni=${sni}&type=tcp#AnyTLS-${SERVER_IP}"
                    local line="[AnyTLS] ${SERVER_IP}:${port} (SNI: ${sni})\n${link_v2rayn}\n"
                    
                    ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}\n"
                    ANYTLS_LINKS="${ANYTLS_LINKS}${line}\n"
                fi
                ;;
        esac
    done
    
    print_success "链接重新生成完成"
    save_links_to_files
}

# 清理链接文件
cleanup_links() {
    print_info "清理所有链接文件..."
    rm -rf "${LINK_DIR}" 2>/dev/null || true
    ALL_LINKS_TEXT=""
    REALITY_LINKS=""
    HYSTERIA2_LINKS=""
    SOCKS5_LINKS=""
    SHADOWTLS_LINKS=""
    HTTPS_LINKS=""
    ANYTLS_LINKS=""
    print_success "链接文件已清理"
}

# 删除单个节点
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
    
    # 从 INBOUNDS_JSON 中删除对应的节点
    local new_inbounds=""
    local count=0
    
    # 使用 jq 重新构建 inbounds 数组
    if command -v jq &>/dev/null && [[ -f "${CONFIG_FILE}" ]]; then
        # 使用 jq 过滤掉要删除的节点
        local inbounds_count=$(jq '.inbounds | length' "${CONFIG_FILE}")
        
        for ((i=0; i<inbounds_count; i++)); do
            local current_tag=$(jq -r ".inbounds[${i}].tag // \"\"" "${CONFIG_FILE}")
            
            if [[ "$current_tag" != "$tag" ]]; then
                local inbound=$(jq -c ".inbounds[${i}]" "${CONFIG_FILE}")
                if [[ -z "$new_inbounds" ]]; then
                    new_inbounds="$inbound"
                else
                    new_inbounds="${new_inbounds},${inbound}"
                fi
                count=$((count+1))
            fi
        done
        
        INBOUNDS_JSON="$new_inbounds"
        
        # 从数组中删除
        unset INBOUND_TAGS[$index]
        unset INBOUND_PORTS[$index]
        unset INBOUND_PROTOS[$index]
        unset INBOUND_SNIS[$index]
        unset INBOUND_RELAY_FLAGS[$index]
        
        # 重建数组（移除空元素）
        INBOUND_TAGS=("${INBOUND_TAGS[@]}")
        INBOUND_PORTS=("${INBOUND_PORTS[@]}")
        INBOUND_PROTOS=("${INBOUND_PROTOS[@]}")
        INBOUND_SNIS=("${INBOUND_SNIS[@]}")
        INBOUND_RELAY_FLAGS=("${INBOUND_RELAY_FLAGS[@]}")
        
        # 重新生成配置
        generate_config
        start_svc
        
        # 重新生成链接
        regenerate_links_from_config
        
        print_success "节点已删除: ${proto}:${port} (SNI: ${sni})"
    else
        print_error "无法解析配置文件"
        return 1
    fi
}

# 删除全部节点
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
    
    # 清空所有节点相关变量
    INBOUNDS_JSON=""
    INBOUND_TAGS=()
    INBOUND_PORTS=()
    INBOUND_PROTOS=()
    INBOUND_SNIS=()
    INBOUND_RELAY_FLAGS=()
    
    # 创建空的配置文件
    cat > ${CONFIG_FILE} << EOFCONFIG
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
    
    # 停止服务
    print_info "停止 sing-box 服务..."
    systemctl stop sing-box 2>/dev/null || true
    
    # 清理链接文件
    cleanup_links
    
    print_success "所有节点已删除，配置文件已重置"
    
    # 询问是否重新启动服务
    read -p "是否启动空配置的 sing-box 服务? (y/N): " restart_service
    restart_service=${restart_service:-N}
    
    if [[ "$restart_service" =~ ^[Yy]$ ]]; then
        # 确保服务文件存在
        if [[ ! -f /etc/systemd/system/sing-box.service ]]; then
            print_warning "服务文件不存在，正在重新创建..."
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
            print_success "服务文件已重新创建"
        fi
        
        systemctl start sing-box
        sleep 2
        if systemctl is-active --quiet sing-box; then
            print_success "服务已启动 (空配置)"
        else
            print_error "服务启动失败，请检查日志: journalctl -u sing-box -n 20"
        fi
    fi
}

get_ip() {
    print_info "获取服务器 IP..."
    SERVER_IP=$(curl -s4m5 ifconfig.me || curl -s4m5 api.ipify.org || curl -s4m5 ip.sb)
    [[ -z "$SERVER_IP" ]] && { print_error "无法获取IP"; exit 1; }
    print_success "服务器 IP: ${SERVER_IP}"
}

check_port_in_use() {
    local port="$1"

    if command -v ss &>/dev/null; then
        ss -tuln | awk '{print $5}' | grep -E "[:.]${port}$" >/dev/null 2>&1 && return 0 || return 1
    elif command -v netstat &>/dev/null; then
        netstat -tuln | awk '{print $4}' | grep -E "[:.]${port}$" >/dev/null 2>&1 && return 0 || return 1
    else
        # 无法检测时，默认认为未占用
        return 1
    fi
}

read_port_with_check() {
    local default_port="$1"
    while true; do
        read -p "监听端口 [${default_port}]: " PORT
        PORT=${PORT:-${default_port}}

        if ! [[ "$PORT" =~ ^[0-9]+$ ]] || ((PORT < 1 || PORT > 65535)); then
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

setup_reality() {
    echo ""
    read_port_with_check 443
    
    # 询问伪装域名
    echo -e "${YELLOW}请输入伪装域名（建议使用常见HTTPS网站域名）${NC}"
    echo -e "${CYAN}例如: itunes.apple.com, www.bing.com, www.google.com${NC}"
    read -p "伪装域名 [${DEFAULT_SNI}]: " SNI
    SNI=${SNI:-${DEFAULT_SNI}}
    
    print_info "生成配置文件..."
    
    local inbound='{
  "type": "vless",
  "tag": "vless-in-'${PORT}'",
  "listen": "::",
  "listen_port": '${PORT}',
  "users": [{"uuid": "'${UUID}'", "flow": "xtls-rprx-vision"}],
  "tls": {
    "enabled": true,
    "server_name": "'${SNI}'",
    "reality": {
      "enabled": true,
      "handshake": {"server": "'${SNI}'", "server_port": 443},
      "private_key": "'${REALITY_PRIVATE}'",
      "short_id": ["'${SHORT_ID}'"]
    }
  }
}'

    if [[ -z "$INBOUNDS_JSON" ]]; then
        INBOUNDS_JSON="$inbound"
    else
        INBOUNDS_JSON="${INBOUNDS_JSON},${inbound}"
    fi
    
    # V2rayN/NekoBox 格式链接
    LINK="vless://${UUID}@${SERVER_IP}:${PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=chrome&pbk=${REALITY_PUBLIC}&sid=${SHORT_ID}&type=tcp#Reality-${SERVER_IP}"
    
    PROTO="Reality"
    EXTRA_INFO="UUID: ${UUID}\nPublic Key: ${REALITY_PUBLIC}\nShort ID: ${SHORT_ID}\nSNI: ${SNI}"
    local line="[Reality] ${SERVER_IP}:${PORT} (SNI: ${SNI})\n${LINK}\n"
    ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}\n"
    REALITY_LINKS="${REALITY_LINKS}${line}\n"
    local tag="vless-in-${PORT}"
    INBOUND_TAGS+=("${tag}")
    INBOUND_PORTS+=("${PORT}")
    INBOUND_PROTOS+=("${PROTO}")
    INBOUND_SNIS+=("${SNI}")
    INBOUND_RELAY_FLAGS+=(0)
    print_success "Reality 配置完成 (SNI: ${SNI})"
    save_links_to_files
}

setup_hysteria2() {
    echo ""
    read_port_with_check 443
    
    # 询问伪装域名
    echo -e "${YELLOW}请输入伪装域名（建议使用常见HTTPS网站域名）${NC}"
    echo -e "${CYAN}例如: itunes.apple.com, www.bing.com, www.google.com${NC}"
    read -p "伪装域名 [${DEFAULT_SNI}]: " HY2_SNI
    HY2_SNI=${HY2_SNI:-${DEFAULT_SNI}}
    
    print_info "为 ${HY2_SNI} 生成自签证书..."
    gen_cert_for_sni "${HY2_SNI}"
    
    print_info "生成配置文件..."
    
    local inbound='{
  "type": "hysteria2",
  "tag": "hy2-in-'${PORT}'",
  "listen": "::",
  "listen_port": '${PORT}',
  "users": [{"password": "'${HY2_PASSWORD}'"}],
  "tls": {
    "enabled": true,
    "alpn": ["h3"],
    "server_name": "'${HY2_SNI}'",
    "certificate_path": "'${CERT_DIR}'/${HY2_SNI}/cert.pem",
    "key_path": "'${CERT_DIR}'/${HY2_SNI}/private.key"
  }
}'
    
    if [[ -z "$INBOUNDS_JSON" ]]; then
        INBOUNDS_JSON="$inbound"
    else
        INBOUNDS_JSON="${INBOUNDS_JSON},${inbound}"
    fi
    
    # Hysteria2 链接格式（NekoBox支持）
    LINK="hysteria2://${HY2_PASSWORD}@${SERVER_IP}:${PORT}?insecure=1&sni=${HY2_SNI}#Hysteria2-${SERVER_IP}"
    PROTO="Hysteria2"
    EXTRA_INFO="密码: ${HY2_PASSWORD}\n证书: 自签证书(${HY2_SNI})\nSNI: ${HY2_SNI}"
    local line="[Hysteria2] ${SERVER_IP}:${PORT} (SNI: ${HY2_SNI})\n${LINK}\n"
    ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}\n"
    HYSTERIA2_LINKS="${HYSTERIA2_LINKS}${line}\n"
    local tag="hy2-in-${PORT}"
    INBOUND_TAGS+=("${tag}")
    INBOUND_PORTS+=("${PORT}")
    INBOUND_PROTOS+=("${PROTO}")
    INBOUND_SNIS+=("${HY2_SNI}")
    INBOUND_RELAY_FLAGS+=(0)
    print_success "Hysteria2 配置完成 (SNI: ${HY2_SNI})"
    save_links_to_files
}

setup_socks5() {
    echo ""
    read_port_with_check 1080
    read -p "是否启用认证? [Y/n]: " ENABLE_AUTH
    ENABLE_AUTH=${ENABLE_AUTH:-Y}
    
    print_info "生成配置文件..."
    
    if [[ "$ENABLE_AUTH" =~ ^[Yy]$ ]]; then
        local inbound='{
  "type": "socks",
  "tag": "socks-in-'${PORT}'",
  "listen": "::",
  "listen_port": '${PORT}',
  "users": [{"username": "'${SOCKS_USER}'", "password": "'${SOCKS_PASS}'"}]
}'
        LINK="socks5://${SOCKS_USER}:${SOCKS_PASS}@${SERVER_IP}:${PORT}#SOCKS5-${SERVER_IP}"
        EXTRA_INFO="用户名: ${SOCKS_USER}\n密码: ${SOCKS_PASS}"
    else
        local inbound='{
  "type": "socks",
  "tag": "socks-in",
  "listen": "::",
  "listen_port": '${PORT}'
}'
        LINK="socks5://${SERVER_IP}:${PORT}#SOCKS5-${SERVER_IP}"
        EXTRA_INFO="无认证"
    fi
    
    if [[ -z "$INBOUNDS_JSON" ]]; then
        INBOUNDS_JSON="$inbound"
    else
        INBOUNDS_JSON="${INBOUNDS_JSON},${inbound}"
    fi
    PROTO="SOCKS5"
    local line="[SOCKS5] ${SERVER_IP}:${PORT}\n${LINK}\n"
    ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}\n"
    SOCKS5_LINKS="${SOCKS5_LINKS}${line}\n"
    local tag
    if [[ "$ENABLE_AUTH" =~ ^[Yy]$ ]]; then
        tag="socks-in-${PORT}"
    else
        tag="socks-in"
    fi
    INBOUND_TAGS+=("${tag}")
    INBOUND_PORTS+=("${PORT}")
    INBOUND_PROTOS+=("${PROTO}")
    INBOUND_SNIS+=("")
    INBOUND_RELAY_FLAGS+=(0)
    print_success "SOCKS5 配置完成"
    save_links_to_files
}

setup_shadowtls() {
    echo ""
    read_port_with_check 443
    
    # 询问伪装域名
    echo -e "${YELLOW}请输入伪装域名（建议使用常见HTTPS网站域名）${NC}"
    echo -e "${CYAN}例如: itunes.apple.com, www.bing.com, www.google.com${NC}"
    read -p "伪装域名 [${DEFAULT_SNI}]: " SHADOWTLS_SNI
    SHADOWTLS_SNI=${SHADOWTLS_SNI:-${DEFAULT_SNI}}
    
    print_info "生成配置文件..."
    print_warning "ShadowTLS 通过伪装真实域名的TLS握手工作"
    
    local inbound='{
  "type": "shadowtls",
  "tag": "shadowtls-in-'${PORT}'",
  "listen": "::",
  "listen_port": '${PORT}',
  "version": 3,
  "users": [{"password": "'${SHADOWTLS_PASSWORD}'"}],
  "handshake": {
    "server": "'${SHADOWTLS_SNI}'",
    "server_port": 443
  },
  "strict_mode": true,
  "detour": "shadowsocks-in"
},
{
  "type": "shadowsocks",
  "tag": "shadowsocks-in-'${PORT}'",
  "listen": "127.0.0.1",
  "method": "2022-blake3-aes-128-gcm",
  "password": "'${SS_PASSWORD}'"
}'
    
    local ss_userinfo=$(echo -n "2022-blake3-aes-128-gcm:${SS_PASSWORD}" | base64 -w0)
    local plugin_json="{\"version\":\"3\",\"host\":\"${SHADOWTLS_SNI}\",\"password\":\"${SHADOWTLS_PASSWORD}\"}"
    local plugin_base64=$(echo -n "$plugin_json" | base64 -w0)
    
    # ShadowTLS 链接格式（NekoBox支持）
    LINK="ss://${ss_userinfo}@${SERVER_IP}:${PORT}?shadow-tls=${plugin_base64}#ShadowTLS-${SERVER_IP}"
    
    if [[ -z "$INBOUNDS_JSON" ]]; then
        INBOUNDS_JSON="$inbound"
    else
        INBOUNDS_JSON="${INBOUNDS_JSON},${inbound}"
    fi
    PROTO="ShadowTLS v3"
    local line="[ShadowTLS v3] ${SERVER_IP}:${PORT} (SNI: ${SHADOWTLS_SNI})\n${LINK}\n"
    ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}\n"
    SHADOWTLS_LINKS="${SHADOWTLS_LINKS}${line}\n"
    EXTRA_INFO="Shadowsocks方法: 2022-blake3-aes-128-gcm\nShadowsocks密码: ${SS_PASSWORD}\nShadowTLS密码: ${SHADOWTLS_PASSWORD}\n伪装域名: ${SHADOWTLS_SNI}"
    local tag="shadowtls-in-${PORT}"
    INBOUND_TAGS+=("${tag}")
    INBOUND_PORTS+=("${PORT}")
    INBOUND_PROTOS+=("${PROTO}")
    INBOUND_SNIS+=("${SHADOWTLS_SNI}")
    INBOUND_RELAY_FLAGS+=(0)
    print_success "ShadowTLS v3 配置完成 (SNI: ${SHADOWTLS_SNI})"
    save_links_to_files
}

setup_https() {
    echo ""
    read_port_with_check 443
    
    # 询问伪装域名
    echo -e "${YELLOW}请输入伪装域名（建议使用常见HTTPS网站域名）${NC}"
    echo -e "${CYAN}例如: itunes.apple.com, www.bing.com, www.google.com${NC}"
    read -p "伪装域名 [${DEFAULT_SNI}]: " HTTPS_SNI
    HTTPS_SNI=${HTTPS_SNI:-${DEFAULT_SNI}}
    
    print_info "为 ${HTTPS_SNI} 生成自签证书..."
    gen_cert_for_sni "${HTTPS_SNI}"
    
    print_info "生成配置文件..."
    
    local inbound='{
  "type": "vless",
  "tag": "vless-tls-in-'${PORT}'",
  "listen": "::",
  "listen_port": '${PORT}',
  "users": [{"uuid": "'${UUID}'"}],
  "tls": {
    "enabled": true,
    "server_name": "'${HTTPS_SNI}'",
    "certificate_path": "'${CERT_DIR}'/${HTTPS_SNI}/cert.pem",
    "key_path": "'${CERT_DIR}'/${HTTPS_SNI}/private.key"
  }
}'
    
    # V2rayN/NekoBox 格式链接
    LINK="vless://${UUID}@${SERVER_IP}:${PORT}?encryption=none&security=tls&sni=${HTTPS_SNI}&type=tcp&allowInsecure=1#HTTPS-${SERVER_IP}"
    if [[ -z "$INBOUNDS_JSON" ]]; then
        INBOUNDS_JSON="$inbound"
    else
        INBOUNDS_JSON="${INBOUNDS_JSON},${inbound}"
    fi
    PROTO="HTTPS"
    EXTRA_INFO="UUID: ${UUID}\n证书: 自签证书(${HTTPS_SNI})\nSNI: ${HTTPS_SNI}"
    local line="[HTTPS] ${SERVER_IP}:${PORT} (SNI: ${HTTPS_SNI})\n${LINK}\n"
    ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}\n"
    HTTPS_LINKS="${HTTPS_LINKS}${line}\n"
    local tag="vless-tls-in-${PORT}"
    INBOUND_TAGS+=("${tag}")
    INBOUND_PORTS+=("${PORT}")
    INBOUND_PROTOS+=("${PROTO}")
    INBOUND_SNIS+=("${HTTPS_SNI}")
    INBOUND_RELAY_FLAGS+=(0)
    print_success "HTTPS 配置完成 (SNI: ${HTTPS_SNI})"
    save_links_to_files
}

setup_anytls() {
    echo ""
    read_port_with_check 443
    
    # 询问伪装域名
    echo -e "${YELLOW}请输入伪装域名（建议使用常见HTTPS网站域名）${NC}"
    echo -e "${CYAN}例如: itunes.apple.com, www.bing.com, www.google.com${NC}"
    read -p "伪装域名 [${DEFAULT_SNI}]: " ANYTLS_SNI
    ANYTLS_SNI=${ANYTLS_SNI:-${DEFAULT_SNI}}
    
    print_info "为 ${ANYTLS_SNI} 生成自签证书..."
    gen_cert_for_sni "${ANYTLS_SNI}"
    
    print_info "生成配置文件..."
    
    local inbound='{
  "type": "anytls",
  "tag": "anytls-in-'${PORT}'",
  "listen": "::",
  "listen_port": '${PORT}',
  "users": [{"password": "'${ANYTLS_PASSWORD}'"}],
  "padding_scheme": [],
  "tls": {
    "enabled": true,
    "server_name": "'${ANYTLS_SNI}'",
    "certificate_path": "'${CERT_DIR}'/${ANYTLS_SNI}/cert.pem",
    "key_path": "'${CERT_DIR}'/${ANYTLS_SNI}/private.key"
  }
}'
    
    # V2rayN/NekoBox 格式链接
    LINK="anytls://${ANYTLS_PASSWORD}@${SERVER_IP}:${PORT}?security=tls&fp=chrome&insecure=1&sni=${ANYTLS_SNI}&type=tcp#AnyTLS-${SERVER_IP}"
    
    if [[ -z "$INBOUNDS_JSON" ]]; then
        INBOUNDS_JSON="$inbound"
    else
        INBOUNDS_JSON="${INBOUNDS_JSON},${inbound}"
    fi
    PROTO="AnyTLS"
    
    EXTRA_INFO="密码: ${ANYTLS_PASSWORD}\n自签证书: ${ANYTLS_SNI}\nSNI: ${ANYTLS_SNI}"
    local line="[AnyTLS] ${SERVER_IP}:${PORT} (SNI: ${ANYTLS_SNI})\n${LINK}\n"
    ALL_LINKS_TEXT="${ALL_LINKS_TEXT}${line}\n"
    ANYTLS_LINKS="${ANYTLS_LINKS}${line}\n"
    local tag="anytls-in-${PORT}"
    INBOUND_TAGS+=("${tag}")
    INBOUND_PORTS+=("${PORT}")
    INBOUND_PROTOS+=("${PROTO}")
    INBOUND_SNIS+=("${ANYTLS_SNI}")
    INBOUND_RELAY_FLAGS+=(0)
    print_success "AnyTLS 配置完成 (SNI: ${ANYTLS_SNI})"
    save_links_to_files
}

parse_socks_link() {
    local link="$1"
    
    # 检查是否是 base64 编码格式 (socks://base64)
    if [[ "$link" =~ ^socks://([A-Za-z0-9+/=]+) ]]; then
        print_info "检测到 base64 编码的 SOCKS 链接，正在解码..."
        local base64_part="${BASH_REMATCH[1]}"
        # 解码 base64
        local decoded=$(echo "$base64_part" | base64 -d 2>/dev/null)
        if [[ -z "$decoded" ]]; then
            print_error "base64 解码失败"
            RELAY_JSON=''
            OUTBOUND_TAG="direct"
            return
        fi
        # 解码后格式: username:password@server:port
        link="socks5://${decoded}"
    fi
    
    # 移除 socks:// 或 socks5:// 前缀
    local data=$(echo "$link" | sed 's|socks5\?://||')
    # 移除 URL 参数
    data=$(echo "$data" | cut -d'?' -f1)
    
    if [[ "$data" =~ @ ]]; then
        local userpass=$(echo "$data" | cut -d'@' -f1)
        local username=$(echo "$userpass" | cut -d':' -f1)
        local password=$(echo "$userpass" | cut -d':' -f2)
        local server_port=$(echo "$data" | cut -d'@' -f2)
        local server=$(echo "$server_port" | cut -d':' -f1)
        local port=$(echo "$server_port" | cut -d':' -f2 | cut -d'#' -f1 | cut -d'?' -f1)
        
        RELAY_JSON='{
  "type": "socks",
  "tag": "relay",
  "server": "'${server}'",
  "server_port": '${port}',
  "version": "5",
  "username": "'${username}'",
  "password": "'${password}'"
}'
    else
        local server=$(echo "$data" | cut -d':' -f1)
        local port=$(echo "$data" | cut -d':' -f2 | cut -d'#' -f1 | cut -d'?' -f1)
        
        RELAY_JSON='{
  "type": "socks",
  "tag": "relay",
  "server": "'${server}'",
  "server_port": '${port}',
  "version": "5"
}'
    fi
    
    OUTBOUND_TAG="relay"
    print_success "SOCKS5 中转配置解析完成"
}

parse_http_link() {
    local link="$1"
    local protocol=$(echo "$link" | cut -d':' -f1)
    local data=$(echo "$link" | sed 's|https\?://||')
    
    local tls="false"
    [[ "$protocol" == "https" ]] && tls="true"
    
    if [[ "$data" =~ @ ]]; then
        local userpass=$(echo "$data" | cut -d'@' -f1)
        local username=$(echo "$userpass" | cut -d':' -f1)
        local password=$(echo "$userpass" | cut -d':' -f2)
        local server_port=$(echo "$data" | cut -d'@' -f2)
        local server=$(echo "$server_port" | cut -d':' -f1)
        local port=$(echo "$server_port" | cut -d':' -f2 | cut -d'/' -f1 | cut -d'#' -f1 | cut -d'?' -f1)
        
        RELAY_JSON='{
  "type": "http",
  "tag": "relay",
  "server": "'${server}'",
  "server_port": '${port}',
  "username": "'${username}'",
  "password": "'${password}'",
  "tls": {"enabled": '${tls}'}
}'
    else
        local server=$(echo "$data" | cut -d':' -f1)
        local port=$(echo "$data" | cut -d':' -f2 | cut -d'/' -f1 | cut -d'#' -f1 | cut -d'?' -f1)
        
        RELAY_JSON='{
  "type": "http",
  "tag": "relay",
  "server": "'${server}'",
  "server_port": '${port}',
  "tls": {"enabled": '${tls}'}
}'
    fi
    
    OUTBOUND_TAG="relay"
    print_success "HTTP(S) 中转配置解析完成"
}

setup_relay() {
    while true; do
        echo ""
        echo -e "${CYAN}中转配置菜单:${NC}"
        echo ""
        echo -e "  ${GREEN}[1]${NC} 设置/修改中转上游（SOCKS5 / HTTP(S)）"
        echo ""
        echo -e "  ${GREEN}[2]${NC} 选择要走中转的节点（按端口）"
        echo ""
        echo -e "  ${GREEN}[0]${NC} 返回主菜单"
        echo ""
        read -p "请选择 [0-2]: " r_choice

        case $r_choice in
            1)
                echo ""
                echo ""
                echo -e "${CYAN}支持的中转格式:${NC}"
                echo -e "  ${GREEN}SOCKS5:${NC}"
                echo -e "    socks5://user:pass@server:port"
                echo -e "    socks5://server:port"
                echo -e "    socks://base64编码"
                echo ""
                echo -e "  ${GREEN}HTTP/HTTPS:${NC}"
                echo -e "    http://user:pass@server:port"
                echo -e "    https://server:port"
                echo ""
                read -p "粘贴中转链接: " RELAY_LINK

                if [[ -z "$RELAY_LINK" ]]; then
                    print_warning "未提供链接，中转配置保持不变"
                else
                    if [[ "$RELAY_LINK" =~ ^socks ]]; then
                        parse_socks_link "$RELAY_LINK"
                    elif [[ "$RELAY_LINK" =~ ^https? ]]; then
                        parse_http_link "$RELAY_LINK"
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

                while true; do
                    echo ""
                    echo -e "${CYAN}当前节点列表（按端口选择是否走中转）:${NC}"
                    for i in "${!INBOUND_TAGS[@]}"; do
                        idx=$((i+1))
                        status="直连"
                        [[ "${INBOUND_RELAY_FLAGS[$i]}" == "1" ]] && status="中转"
                        echo -e "  ${GREEN}[${idx}]${NC} 协议: ${INBOUND_PROTOS[$i]}, 端口: ${INBOUND_PORTS[$i]}, SNI: ${INBOUND_SNIS[$i]}  → ${YELLOW}${status}${NC}"
                    done
                    echo ""
                    echo -e "输入要切换中转状态的序号，多个用逗号分隔，例如: 1,3"
                    echo -e "输入 0 完成选择并应用配置，返回上一级菜单"
                    read -p "请输入: " sel

                    sel=$(echo "$sel" | tr -d ' ')
                    if [[ -z "$sel" ]]; then
                        continue
                    fi
                    if [[ "$sel" == "0" ]]; then
                        # 完成选择后自动生成配置并重启服务
                        if [[ -n "$INBOUNDS_JSON" ]]; then
                            generate_config && start_svc
                        fi
                        break
                    fi

                    IFS=',' read -ra indices <<< "$sel"
                    for one in "${indices[@]}"; do
                        if ! [[ "$one" =~ ^[0-9]+$ ]]; then
                            continue
                        fi
                        n=$((one-1))
                        if (( n < 0 || n >= ${#INBOUND_TAGS[@]} )); then
                            continue
                        fi
                        if [[ "${INBOUND_RELAY_FLAGS[$n]}" == "1" ]]; then
                            INBOUND_RELAY_FLAGS[$n]=0
                        else
                            INBOUND_RELAY_FLAGS[$n]=1
                        fi
                    done
                    print_success "节点中转状态已更新"
                done
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

clear_relay() {
    RELAY_JSON=''
    OUTBOUND_TAG="direct"
    if [[ ${#INBOUND_RELAY_FLAGS[@]} -gt 0 ]]; then
        for i in "${!INBOUND_RELAY_FLAGS[@]}"; do
            INBOUND_RELAY_FLAGS[$i]=0
        done
    fi
    print_success "已删除中转配置，当前为直连模式"
}

show_menu() {
    show_banner
    echo -e "${YELLOW}请选择要添加的协议节点:${NC}"
    echo ""
    echo -e "${GREEN}[1]${NC} VlessReality ${CYAN}→ 抗审查最强，伪装真实TLS，无需证书${NC} ${YELLOW}(⭐ 强烈推荐)${NC}"
    echo ""
    echo -e "${GREEN}[2]${NC} Hysteria2 ${CYAN}→ 基于QUIC，速度快，垃圾线路专用，适合高延迟网络${NC}"
    echo ""
    echo -e "${GREEN}[3]${NC} SOCKS5 ${CYAN}→ 适合中转的代理协议，只能在落地机上用${NC}"
    echo ""
    echo -e "${GREEN}[4]${NC} ShadowTLS v3 ${CYAN}→ TLS流量伪装，支持 Shadowrocket${NC}"
    echo ""
    echo -e "${GREEN}[5]${NC} HTTPS ${CYAN}→ 标准HTTPS，可过CDN${NC}"
    echo ""
    echo -e "${GREEN}[6]${NC} AnyTLS ${YELLOW} ${CYAN}→ 通用TLS协议，支持多客户端自动配置${NC}"
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

    # 添加节点后立刻生成配置并启动服务，同时输出当前节点信息
    if [[ -n "$INBOUNDS_JSON" ]]; then
        generate_config || return 1
        start_svc || return 1
        show_result
    fi
}

show_main_menu() {
    show_banner
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║          ${GREEN}Sing-Box 一键管理面板${CYAN}          ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════╝${NC}"
    echo ""

    local outbound_desc
    if [[ "$OUTBOUND_TAG" == "relay" ]]; then
        # 查找所有走中转的节点
        local relay_nodes=()
        if [[ ${#INBOUND_RELAY_FLAGS[@]} -gt 0 ]]; then
            for i in "${!INBOUND_RELAY_FLAGS[@]}"; do
                if [[ "${INBOUND_RELAY_FLAGS[$i]}" == "1" ]]; then
                    relay_nodes+=("${INBOUND_PROTOS[$i]}:${INBOUND_PORTS[$i]}")
                fi
            done
        fi

        if [[ ${#relay_nodes[@]} -gt 0 ]]; then
            # 如果有走中转的节点，显示协议和端口
            outbound_desc="中转"
            for node in "${relay_nodes[@]}"; do
                outbound_desc="${outbound_desc} ${node}"
            done
        else
            # 如果没有节点走中转，但仍然配置了中转，显示"中转(无节点)"
            outbound_desc="中转(无节点)"
        fi
    else
        outbound_desc="直连"
    fi

    echo -e "  ${YELLOW}当前出站: ${GREEN}${outbound_desc}${NC}"
    echo -e "  ${YELLOW}当前节点数: ${GREEN}${#INBOUND_TAGS[@]}${NC}"
    echo ""
    echo -e "  ${GREEN}[1]${NC} 添加/继续添加节点"
    echo ""
    echo -e "  ${GREEN}[2]${NC} 设置中转（SOCKS5 / HTTP(S)）"
    echo ""    
    echo -e "  ${GREEN}[3]${NC} 删除中转，恢复直连"
    echo ""    
    echo -e "  ${GREEN}[4]${NC} 配置 / 查看节点"
    echo ""    
    echo -e "  ${GREEN}[5]${NC} 清理链接文件"
    echo ""    
    echo -e "  ${GREEN}[6]${NC} 一键删除脚本并退出"
    echo ""
    echo -e "  ${GREEN}[0]${NC} 退出脚本"
    echo ""
}

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

    # 停止并禁用 sing-box 服务
    print_info "停止 sing-box 服务（如存在）..."
    if systemctl list-unit-files | grep -q '^sing-box\.service'; then
        systemctl stop sing-box 2>/dev/null || true
        systemctl disable sing-box 2>/dev/null || true
    fi

    # 删除 systemd service 文件
    if [[ -f /etc/systemd/system/sing-box.service ]]; then
        print_info "删除 sing-box systemd 服务文件..."
        rm -f /etc/systemd/system/sing-box.service 2>/dev/null || true
        systemctl daemon-reload 2>/dev/null || true
    fi

    # 删除 systemd 运行时文件（如果有）
    if [[ -d /run/sing-box ]]; then
        print_info "删除 sing-box 运行时文件..."
        rm -rf /run/sing-box 2>/dev/null || true
    fi

    # 删除 sing-box 二进制
    if command -v sing-box &>/dev/null; then
        local sb_bin
        sb_bin="$(command -v sing-box)"
        print_info "删除 sing-box 二进制: ${sb_bin}"
        rm -f "${sb_bin}" 2>/dev/null || true
    else
        # 回退到默认安装路径
        if [[ -f ${INSTALL_DIR}/sing-box ]]; then
            print_info "删除 sing-box 二进制: ${INSTALL_DIR}/sing-box"
            rm -f "${INSTALL_DIR}/sing-box" 2>/dev/null || true
        fi
    fi

    # 删除配置目录
    if [[ -d /etc/sing-box ]]; then
        print_info "删除 /etc/sing-box 配置目录及所有节点配置..."
        rm -rf /etc/sing-box 2>/dev/null || true
    fi

    # 删除证书目录
    if [[ -d ${CERT_DIR} ]]; then
        print_info "删除证书目录: ${CERT_DIR}"
        rm -rf "${CERT_DIR}" 2>/dev/null || true
    fi

    # 删除链接文件目录
    if [[ -d "${LINK_DIR}" ]]; then
        print_info "删除链接文件目录: ${LINK_DIR}"
        rm -rf "${LINK_DIR}" 2>/dev/null || true
    fi

    # 删除密钥文件
    if [[ -f "${KEY_FILE}" ]]; then
        print_info "删除密钥文件: ${KEY_FILE}"
        rm -f "${KEY_FILE}" 2>/dev/null || true
    fi

    # 删除可能存在的日志文件
    if [[ -d /var/log/sing-box ]]; then
        print_info "删除 sing-box 日志目录..."
        rm -rf /var/log/sing-box 2>/dev/null || true
    fi

    # 删除 journal 日志中的相关条目
    print_info "清理 systemd journal 日志中 sing-box 相关条目..."
    journalctl --vacuum-time=1s --quiet 2>/dev/null || true

    # 删除临时文件
    print_info "清理临时文件..."
    rm -f /tmp/sb.tar.gz 2>/dev/null || true
    rm -rf /tmp/sing-box-* 2>/dev/null || true

    # 删除快捷命令 sb
    print_info "删除快捷命令 sb（如存在）..."
    if command -v sb &>/dev/null; then
        rm -f "$(command -v sb)" 2>/dev/null || true
    elif [[ -f /usr/local/bin/sb ]]; then
        rm -f /usr/local/bin/sb 2>/dev/null || true
    fi

    # 删除可能存在的其他快捷命令
    for cmd in /usr/bin/sb /usr/local/sbin/sb /usr/sbin/sb; do
        if [[ -f "$cmd" ]]; then
            print_info "删除快捷命令: $cmd"
            rm -f "$cmd" 2>/dev/null || true
        fi
    done

    # 清理防火墙规则（可选，根据实际情况）
    if command -v ufw &>/dev/null; then
        print_info "检查并清理 ufw 防火墙规则..."
        # 这里可以添加具体的端口清理规则
        # ufw delete allow 443/tcp 2>/dev/null || true
        # ufw delete allow 1080/tcp 2>/dev/null || true
    fi

    # 清理可能的 cron 任务
    print_info "清理可能的定时任务..."
    crontab -l 2>/dev/null | grep -v 'sing-box' | crontab - 2>/dev/null || true
    rm -f /etc/cron.d/sing-box* 2>/dev/null || true

    # 清理可能的环境变量设置
    print_info "清理可能的环境变量设置..."
    for file in ~/.bashrc ~/.bash_profile ~/.zshrc ~/.profile /etc/profile.d/sing-box.sh; do
        if [[ -f "$file" ]]; then
            sed -i '/sing-box/d' "$file" 2>/dev/null || true
            sed -i '/SB_HOME/d' "$file" 2>/dev/null || true
        fi
    done

    # 删除当前脚本
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

main_menu() {
    while true; do
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
                clear_relay
                ;;
            4)
                config_and_view_menu
                ;;
            5)
                cleanup_links
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

generate_config() {
    print_info "生成最终配置文件..."
    
    if [[ -z "$INBOUNDS_JSON" ]]; then
        print_error "未找到任何入站节点，请先添加节点"
        return 1
    fi

    local outbounds='[{"type": "direct", "tag": "direct"}]'
    
    if [[ -n "$RELAY_JSON" ]]; then
        outbounds='['${RELAY_JSON}', {"type": "direct", "tag": "direct"}]'
    fi

    local route_json
    local has_relay_inbound=0

    if [[ -n "$RELAY_JSON" ]]; then
        local relay_inbounds=()
        local i
        for i in "${!INBOUND_TAGS[@]}"; do
            if [[ "${INBOUND_RELAY_FLAGS[$i]}" == "1" ]]; then
                relay_inbounds+=("\"${INBOUND_TAGS[$i]}\"")
                has_relay_inbound=1
            fi
        done

        if [[ $has_relay_inbound -eq 1 ]]; then
            local inbound_array
            inbound_array=$(IFS=,; echo "${relay_inbounds[*]}")
            route_json='{"rules":[{"inbound":['${inbound_array}'],"outbound":"relay"}],"final":"direct"}'
        else
            route_json='{"final":"direct"}'
        fi
    else
        route_json='{"final":"direct"}'
    fi

    if [[ -n "$RELAY_JSON" && $has_relay_inbound -eq 1 ]]; then
        OUTBOUND_TAG="relay"
    else
        OUTBOUND_TAG="direct"
    fi

    cat > ${CONFIG_FILE} << EOFCONFIG
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [${INBOUNDS_JSON}],
  "outbounds": ${outbounds},
  "route": ${route_json}
}
EOFCONFIG
    
    print_success "配置文件生成完成"
    
    # 生成配置后，重新生成链接并保存
    regenerate_links_from_config
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
    echo -e "  SNI: ${GREEN}${SNI:-${HY2_SNI:-${SHADOWTLS_SNI:-${HTTPS_SNI:-${ANYTLS_SNI:-未设置}}}}${NC}"
    echo -e "  出站: ${GREEN}${OUTBOUND_TAG}${NC}"
    echo ""
    
    if [[ -n "$EXTRA_INFO" ]]; then
        echo -e "${YELLOW}协议详情:${NC}"
        echo -e "$EXTRA_INFO" | sed 's/^/  /'
        echo ""
    fi
    
    echo -e "${CYAN}───────────────────────────────────────────────────────${NC}"
    
    echo -e "${GREEN}📋 V2rayN/NekoBox 节点链接:${NC}"
    echo -e "${CYAN}───────────────────────────────────────────────────────${NC}"
    echo ""
    echo -e "${YELLOW}${LINK}${NC}"
    echo ""
    
    if [[ "$PROTO" == "AnyTLS" ]]; then
        echo -e "${CYAN}───────────────────────────────────────────────────────${NC}"
        echo -e "${GREEN}✨ 客户端支持:${NC}"
        echo -e "${CYAN}───────────────────────────────────────────────────────${NC}"
        echo ""
        echo -e "  ${GREEN}• V2rayN / NekoBox:${NC}"
        echo -e "    1. 复制上方链接"
        echo -e "    2. 打开客户端，从剪贴板导入"
        echo ""
    
    elif [[ "$PROTO" == "Reality" ]]; then
        echo -e "${CYAN}───────────────────────────────────────────────────────${NC}"
        echo -e "${GREEN}✨ 客户端支持:${NC}"
        echo -e "${CYAN}───────────────────────────────────────────────────────${NC}"
        echo ""
        echo -e "  ${GREEN}• V2rayN / NekoBox:${NC}"
        echo -e "    1. 复制上方链接"
        echo -e "    2. 打开客户端，从剪贴板导入"
        echo ""
    else
        echo -e "${CYAN}───────────────────────────────────────────────────────${NC}"
        echo -e "${GREEN}✨ 客户端支持:${NC}"
        echo -e "${CYAN}───────────────────────────────────────────────────────${NC}"
        echo ""
        echo -e "  ${GREEN}• NekoBox:${NC}"
        echo -e "    1. 复制上方链接"
        echo -e "    2. 打开NekoBox，从剪贴板导入"
        echo ""
        if [[ "$PROTO" == "Hysteria2" ]]; then
            echo -e "  ${YELLOW}• V2rayN:${NC}"
            echo -e "    不支持 Hysteria2 协议"
        elif [[ "$PROTO" == "SOCKS5" ]]; then
            echo -e "  ${YELLOW}• V2rayN:${NC}"
            echo -e "    请使用 NekoBox 或系统代理设置"
        fi
    fi
    
    echo -e "${CYAN}───────────────────────────────────────────────────────${NC}"
}

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
        echo -e "  ${GREEN}[9]${NC} 重新从配置文件生成链接"
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
                # 重新从配置文件加载配置
                if load_inbounds_from_config; then
                    generate_config && start_svc
                    print_success "配置已重新加载并启动服务"
                else
                    print_error "无法从配置文件加载配置，请先添加节点"
                fi
                read -p "按回车返回..." _
                ;;
            2)
                # 确保链接是最新的
                if [[ ! -f "${ALL_LINKS_FILE}" ]] || [[ -z "${ALL_LINKS_TEXT}" ]]; then
                    regenerate_links_from_config
                fi
                
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
                # 确保链接是最新的
                if [[ ! -f "${REALITY_LINKS_FILE}" ]] || [[ -z "${REALITY_LINKS}" ]]; then
                    regenerate_links_from_config
                fi
                
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
                # 确保链接是最新的
                if [[ ! -f "${HYSTERIA2_LINKS_FILE}" ]] || [[ -z "${HYSTERIA2_LINKS}" ]]; then
                    regenerate_links_from_config
                fi
                
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
                # 确保链接是最新的
                if [[ ! -f "${SOCKS5_LINKS_FILE}" ]] || [[ -z "${SOCKS5_LINKS}" ]]; then
                    regenerate_links_from_config
                fi
                
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
                # 确保链接是最新的
                if [[ ! -f "${SHADOWTLS_LINKS_FILE}" ]] || [[ -z "${SHADOWTLS_LINKS}" ]]; then
                    regenerate_links_from_config
                fi
                
                clear
                echo -e "${YELLOW}ShadowTLS 节点:${NC}"
                echo ""
                if [[ -z "$SHADOWTLS_LINKS" ]]; then
                    echo "(暂无 ShadowTLS 节点)"
                else
                    echo -e "$SHADOWTLS_LINKS"
                fi
                echo ""
                read -p "按回车返回..." _
                ;;
            7)
                # 确保链接是最新的
                if [[ ! -f "${HTTPS_LINKS_FILE}" ]] || [[ -z "${HTTPS_LINKS}" ]]; then
                    regenerate_links_from_config
                fi
                
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
                # 确保链接是最新的
                if [[ ! -f "${ANYTLS_LINKS_FILE}" ]] || [[ -z "${ANYTLS_LINKS}" ]]; then
                    regenerate_links_from_config
                fi
                
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
                regenerate_links_from_config
                read -p "按回车返回..." _
                ;;
            10)
                delete_single_node
                read -p "按回车返回..." _
                ;;
            11)
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

setup_sb_shortcut() {
    print_info "创建快捷命令 sb..."
    # 仅当脚本路径是实际文件时才创建快捷命令
    if [[ ! -f "${SCRIPT_PATH}" ]]; then
        print_warning "当前脚本并非磁盘文件，跳过创建 sb（请从本地脚本文件运行后再试）"
        return
    fi

    cat > /usr/local/bin/sb << EOSB
#!/bin/bash
bash "${SCRIPT_PATH}" "\$@"
EOSB
    chmod +x /usr/local/bin/sb
    print_success "已创建快捷命令: sb （任意位置输入 sb 即可重新进入脚本）"
}

main() {
    [[ $EUID -ne 0 ]] && { print_error "需要 root 权限"; exit 1; }
    
    detect_system
    
    install_singbox
    mkdir -p /etc/sing-box
    gen_keys
    get_ip
    setup_sb_shortcut
    
    # 从配置文件加载节点配置
    if load_inbounds_from_config; then
        print_success "从配置文件加载节点配置成功"
    else
        print_warning "无法从配置文件加载节点配置，或配置文件不存在"
    fi
    
    # 加载已保存的链接
    load_links_from_files
    
    # 如果配置文件存在但链接为空，尝试重新生成链接
    if [[ -f "${CONFIG_FILE}" ]] && [[ -z "${ALL_LINKS_TEXT}" ]]; then
        print_info "检测到配置文件存在，尝试重新生成链接"
        regenerate_links_from_config
    fi
    
    main_menu
}

main
