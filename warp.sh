#!/usr/bin/env bash
#=============================================
# Cloudflare WARP 一键脚本 (支持 Alpine + 分流)
# 特性：自动注册密钥、保活、下载校验
#=============================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'
WORKDIR="/etc/wireguard"
WGCF_BIN=""
WARP_LICENSE=""
CURRENT_MODE="global"

check_root() {
    [ "$EUID" -ne 0 ] && echo -e "${RED}请使用 root 运行。${NC}" && exit 1
}

detect_os() {
    if grep -qi alpine /etc/os-release 2>/dev/null; then
        OS="alpine"; PKG_MGR="apk"
    elif command -v apt &>/dev/null; then
        OS="debian"; PKG_MGR="apt"
    elif command -v yum &>/dev/null; then
        OS="centos"; PKG_MGR="yum"
    else
        echo -e "${RED}不支持的系统。${NC}"; exit 1
    fi
}

install_deps() {
    detect_os
    echo -e "${BLUE}[信息] 安装依赖 (${OS}) ...${NC}"
    case $OS in
        alpine)
            apk update || { echo -e "${RED}apk update 失败${NC}"; exit 1; }
            apk add wireguard-tools curl openresolv bind-tools file || exit 1
            if apk search wgcf 2>/dev/null | grep -q "^wgcf"; then
                apk add wgcf && WGCF_BIN="/usr/bin/wgcf"
            else
                apk add gcompat && WGCF_BIN="/usr/local/bin/wgcf"
            fi
            ;;
        debian)
            apt update -qq && apt install -y -qq curl wireguard-tools resolvconf dnsutils file || exit 1
            WGCF_BIN="/usr/local/bin/wgcf"
            ;;
        centos)
            yum install -y -q epel-release && yum install -y -q curl wireguard-tools bind-utils file || exit 1
            WGCF_BIN="/usr/local/bin/wgcf"
            ;;
    esac
    mkdir -p "$WORKDIR"
}

# 检查文件是否为有效的 ELF 可执行文件
is_valid_binary() {
    local f="$1"
    # 读取前4字节，ELF 魔数为 \x7fELF
    local magic
    magic=$(od -An -tx1 -N4 "$f" 2>/dev/null | tr -d ' ')
    [ "$magic" = "7f454c46" ] && return 0 || return 1
}

install_wgcf_binary() {
    # 如果已存在有效二进制则跳过
    if [ -n "$WGCF_BIN" ] && [ -f "$WGCF_BIN" ] && is_valid_binary "$WGCF_BIN"; then
        return 0
    fi

    echo -e "${BLUE}[信息] 下载 wgcf ...${NC}"
    # 检查 GitHub 连通性
    if ! curl -s --connect-timeout 5 https://github.com >/dev/null; then
        echo -e "${RED}无法连接 GitHub，请检查网络或设置代理。${NC}"
        exit 1
    fi

    # 获取最新版本号
    local latest
    latest=$(curl -s --connect-timeout 10 https://api.github.com/repos/ViRb3/wgcf/releases/latest | grep tag_name | cut -d\" -f4)
    if [ -z "$latest" ]; then
        echo -e "${YELLOW}无法获取最新版本号，使用备用版本 v2.2.22${NC}"
        latest="v2.2.22"
    fi

    # 确定架构
    local arch
    arch=$(uname -m)
    case $arch in
        x86_64)  arch="amd64" ;;
        aarch64) arch="arm64" ;;
        armv7l)  arch="armv7" ;;
        *) echo -e "${RED}不支持的架构: $arch${NC}"; exit 1 ;;
    esac

    local url="https://github.com/ViRb3/wgcf/releases/download/${latest}/wgcf_${latest}_linux_${arch}"
    echo -e "下载地址: ${url}"

    # 下载临时文件
    local tmpfile="/tmp/wgcf_download_$$"
    if curl -L --connect-timeout 15 -o "$tmpfile" "$url"; then
        if is_valid_binary "$tmpfile"; then
            mv "$tmpfile" "$WGCF_BIN"
            chmod +x "$WGCF_BIN"
            echo -e "${GREEN}wgcf 下载成功${NC}"
        else
            rm -f "$tmpfile"
            echo -e "${RED}下载的文件无效（非可执行程序），可能是版本不存在或网络问题。${NC}"
            echo -e "${YELLOW}请手动下载 wgcf 并放置到 ${WGCF_BIN}，然后重新运行脚本。${NC}"
            echo -e "手动下载命令示例："
            echo -e "  wget -O ${WGCF_BIN} ${url}"
            echo -e "  chmod +x ${WGCF_BIN}"
            exit 1
        fi
    else
        rm -f "$tmpfile"
        echo -e "${RED}下载失败，请检查网络。${NC}"
        exit 1
    fi
}

generate_config() {
    cd "$WORKDIR"
    echo -e "${BLUE}[信息] 注册设备并生成 WireGuard 密钥...${NC}"
    if ! $WGCF_BIN register --accept-tos; then
        echo -e "${RED}注册失败，请检查网络或稍后再试。${NC}"
        exit 1
    fi

    if [ -n "$WARP_LICENSE" ]; then
        echo -e "${YELLOW}[信息] 激活 WARP+ 许可证...${NC}"
        $WGCF_BIN update --license "$WARP_LICENSE" || echo -e "${YELLOW}许可证激活失败，继续使用免费版${NC}"
    fi

    if ! $WGCF_BIN generate; then
        echo -e "${RED}生成配置文件失败${NC}"
        exit 1
    fi

    [ ! -f wgcf-profile.conf ] && { echo -e "${RED}配置文件未找到${NC}"; exit 1; }

    sed -i "s/MTU.*/MTU = 1280/" wgcf-profile.conf
    sed -i "s/1.1.1.1/1.1.1.1, 1.0.0.1/" wgcf-profile.conf
    sed -i "/\[Peer\]/a PersistentKeepalive = 25" wgcf-profile.conf

    apply_mode "global"
    echo -e "${GREEN}配置已保存到 /etc/wireguard/wgcf.conf (全局模式)${NC}"
    show_keys
}

apply_mode() {
    local mode="$1"
    local conf="/etc/wireguard/wgcf.conf"
    local allowed_ips

    case $mode in
        global)
            allowed_ips="0.0.0.0/0, ::/0"
            ;;
        media)
            allowed_ips="37.29.0.0/16, 37.85.0.0/16, 45.57.0.0/16,
54.154.0.0/16, 63.84.0.0/16, 143.244.0.0/16,
185.2.0.0/16, 188.34.0.0/16, 198.38.0.0/16,
199.255.0.0/16, 64.145.64.0/24, 69.22.168.0/21,
104.37.176.0/21, 108.175.32.0/20, 157.52.0.0/16,
162.159.0.0/16, 173.245.0.0/16, 185.180.0.0/22,
188.114.96.0/20, 190.115.16.0/21, 192.133.77.0/24,
198.44.160.0/19, 198.135.108.0/22, 199.36.220.0/22"
            for domain in netflix.com disneyplus.com hulu.com; do
                local ips=$(dig +short "$domain" A 2>/dev/null)
                if [ -n "$ips" ]; then
                    while IFS= read -r ip; do
                        allowed_ips+=", ${ip}/32"
                    done <<< "$ips"
                fi
            done
            allowed_ips=$(echo "$allowed_ips" | tr -d '\n' | sed 's/,$//')
            ;;
        custom)
            read -rp "输入要使用 WARP 的 IP 段或域名(用逗号分隔): " raw_input
            IFS=',' read -ra items <<< "$raw_input"
            allowed_ips=""
            for item in "${items[@]}"; do
                item=$(echo "$item" | xargs)
                [ -z "$item" ] && continue
                if [[ $item =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ ]]; then
                    [[ ! $item =~ / ]] && item="${item}/32"
                    allowed_ips+="${item}, "
                else
                    local ips=$(dig +short "$item" A 2>/dev/null)
                    if [ -z "$ips" ]; then
                        echo -e "${YELLOW}无法解析 $item，跳过${NC}"
                    else
                        while IFS= read -r ip; do
                            allowed_ips+="${ip}/32, "
                        done <<< "$ips"
                    fi
                fi
            done
            allowed_ips=$(echo "$allowed_ips" | sed 's/, $//')
            if [ -z "$allowed_ips" ]; then
                echo -e "${RED}没有有效的 IP 段，切换回全局模式${NC}"
                apply_mode "global"
                return
            fi
            ;;
        *)
            echo -e "${RED}未知模式: $mode${NC}"; return 1
            ;;
    esac

    if grep -q "AllowedIPs" "$conf"; then
        sed -i "s|AllowedIPs.*|AllowedIPs = ${allowed_ips}|" "$conf"
    else
        sed -i "/\[Peer\]/a AllowedIPs = ${allowed_ips}" "$conf"
    fi
    CURRENT_MODE="$mode"
}

show_keys() {
    local conf="/etc/wireguard/wgcf.conf"
    if [ ! -f "$conf" ]; then
        echo -e "${RED}配置文件不存在。${NC}"; return 1
    fi
    local privkey peer_pubkey pubkey
    privkey=$(grep -i "PrivateKey" "$conf" | awk '{print $NF}')
    peer_pubkey=$(grep -i "PublicKey" "$conf" | tail -1 | awk '{print $NF}')
    pubkey=$(echo "$privkey" | wg pubkey 2>/dev/null)
    echo -e "${GREEN}================ WARP 密钥信息 ================${NC}"
    echo -e "客户端私钥:  ${YELLOW}${privkey}${NC}"
    echo -e "客户端公钥:  ${GREEN}${pubkey:-未能派生}${NC}"
    echo -e "对端公钥:    ${BLUE}${peer_pubkey}${NC}"
    echo -e "${GREEN}==============================================${NC}"
}

start_warp() {
    echo -e "${BLUE}启动 WARP 接口 wgcf ...${NC}"
    wg-quick up wgcf || { echo -e "${RED}启动失败，请检查配置。${NC}"; return 1; }
    echo -e "${GREEN}已连接，当前出站 IP:${NC}"
    curl -s myip.ipip.net || echo -e "${YELLOW}查询 IP 失败，但接口可能已启动。${NC}"
}

stop_warp() {
    echo -e "${YELLOW}停止 WARP 接口...${NC}"
    wg-quick down wgcf 2>/dev/null || true
}

status_warp() {
    wg show wgcf || echo -e "${RED}WARP 接口未运行${NC}"
}

uninstall_warp() {
    stop_warp
    rm -f /etc/wireguard/wgcf.conf /usr/local/bin/wgcf "$WORKDIR"/wgcf*
    command -v apk &>/dev/null && apk del wgcf wireguard-tools 2>/dev/null
    echo -e "${GREEN}已卸载所有 WARP 组件${NC}"
}

switch_mode() {
    echo -e "${GREEN}当前模式: ${YELLOW}${CURRENT_MODE}${NC}"
    echo -e "1) 全局模式"
    echo -e "2) 流媒体模式"
    echo -e "3) 自定义模式"
    read -rp "请选择 [1-3]: " choice
    case $choice in
        1) apply_mode "global" ;;
        2) apply_mode "media" ;;
        3) apply_mode "custom" ;;
        *) echo -e "${RED}无效选择${NC}"; return 1 ;;
    esac
    echo -e "${GREEN}配置已更新，重启 WARP 后生效${NC}"
    read -rp "是否立即重启 WARP？(y/n) " yn
    if [ "$yn" = "y" -o "$yn" = "Y" ]; then
        stop_warp
        start_warp
    fi
}

show_menu() {
    echo -e "${GREEN}================================${NC}"
    echo -e "${GREEN}   Cloudflare WARP 管理脚本${NC}"
    echo -e "${GREEN}================================${NC}"
    echo -e "1) 安装并连接  WARP"
    echo -e "2) 断开连接"
    echo -e "3) 重启连接"
    echo -e "4) 查看状态"
    echo -e "5) 查看密钥 (证书/密匙)"
    echo -e "6) 切换分流模式"
    echo -e "7) 完全卸载"
    echo -e "0) 退出"
    read -rp "请选择 [0-7]: " choice
    case $choice in
        1)
            check_root
            install_deps
            [ "$WGCF_BIN" = "/usr/local/bin/wgcf" ] && install_wgcf_binary
            if [ ! -f /etc/wireguard/wgcf.conf ]; then
                read -rp "使用 WARP+ 密钥？(y/n) " yn
                [ "$yn" = "y" -o "$yn" = "Y" ] && read -rp "请输入密钥: " WARP_LICENSE
                generate_config
            fi
            start_warp
            ;;
        2) check_root; stop_warp ;;
        3) check_root; stop_warp; start_warp ;;
        4) check_root; status_warp ;;
        5) check_root; show_keys ;;
        6) check_root; switch_mode ;;
        7) check_root; uninstall_warp ;;
        0) exit 0 ;;
        *) echo -e "${RED}无效选项${NC}" ;;
    esac
}

if [ $# -gt 0 ]; then
    case $1 in
        start)   check_root; start_warp ;;
        stop)    check_root; stop_warp ;;
        restart) check_root; stop_warp; start_warp ;;
        status)  check_root; status_warp ;;
        keys)    check_root; show_keys ;;
        mode)    check_root; switch_mode ;;
        install) check_root; install_deps
                 [ "$WGCF_BIN" = "/usr/local/bin/wgcf" ] && install_wgcf_binary
                 generate_config; start_warp ;;
        *)       show_menu ;;
    esac
else
    show_menu
fi
