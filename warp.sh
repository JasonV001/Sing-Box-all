#!/usr/bin/env bash
set -e

#=============================================
# Cloudflare WARP 一键脚本 (支持 Alpine)
# 自动注册设备、生成 WireGuard 密钥、开启保活
# 兼容 Debian/Ubuntu/CentOS/Alpine
#=============================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'
WORKDIR="/etc/wireguard"
WGCF_BIN=""
WARP_LICENSE=""

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
        echo -e "${RED}不支持的系统，请手动安装 wireguard-tools 和 curl。${NC}"; exit 1
    fi
}

install_deps() {
    detect_os
    echo -e "${BLUE}[信息] 安装依赖 (${OS}) ...${NC}"
    case $OS in
        alpine)
            apk update
            apk add wireguard-tools curl openresolv
            if apk search wgcf 2>/dev/null | grep -q "^wgcf"; then
                apk add wgcf
                WGCF_BIN="/usr/bin/wgcf"
            else
                apk add gcompat
                WGCF_BIN="/usr/local/bin/wgcf"
            fi
            ;;
        debian)
            apt update -qq && apt install -y -qq curl wireguard-tools resolvconf
            WGCF_BIN="/usr/local/bin/wgcf"
            ;;
        centos)
            yum install -y -q epel-release && yum install -y -q curl wireguard-tools
            WGCF_BIN="/usr/local/bin/wgcf"
            ;;
    esac
    mkdir -p "$WORKDIR"
}

install_wgcf_binary() {
    if [ -n "$WGCF_BIN" ] && [ -f "$WGCF_BIN" ]; then return 0; fi
    echo -e "${BLUE}[信息] 下载 wgcf ...${NC}"
    local latest
    latest=$(curl -s https://api.github.com/repos/ViRb3/wgcf/releases/latest | grep tag_name | cut -d\" -f4)
    [ -z "$latest" ] && latest="v2.2.22"
    local arch
    arch=$(uname -m)
    case $arch in
        x86_64)  arch="amd64" ;;
        aarch64) arch="arm64" ;;
        armv7l)  arch="armv7" ;;
        *) echo -e "${RED}不支持的架构: $arch${NC}"; exit 1 ;;
    esac
    curl -L -o "$WGCF_BIN" "https://github.com/ViRb3/wgcf/releases/download/${latest}/wgcf_${latest}_linux_${arch}"
    chmod +x "$WGCF_BIN"
}

generate_config() {
    cd "$WORKDIR"
    echo -e "${BLUE}[信息] 注册设备并自动生成 WireGuard 密钥...${NC}"
    $WGCF_BIN register --accept-tos

    if [ -n "$WARP_LICENSE" ]; then
        echo -e "${YELLOW}[信息] 激活 WARP+ 许可证...${NC}"
        $WGCF_BIN update --license "$WARP_LICENSE"
    fi

    $WGCF_BIN generate
    [ ! -f wgcf-profile.conf ] && { echo -e "${RED}配置文件生成失败！${NC}"; exit 1; }

    # 优化配置
    sed -i "s/MTU.*/MTU = 1280/" wgcf-profile.conf
    sed -i "s/1.1.1.1/1.1.1.1, 1.0.0.1/" wgcf-profile.conf
    # 添加保活（防 NAT 断连）
    sed -i "/\[Peer\]/a PersistentKeepalive = 25" wgcf-profile.conf

    cp wgcf-profile.conf /etc/wireguard/wgcf.conf
    echo -e "${GREEN}配置已保存到 /etc/wireguard/wgcf.conf${NC}"
    show_keys
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
    wg-quick up wgcf
    echo -e "${GREEN}已连接，当前出站 IP:${NC}"
    curl -s myip.ipip.net
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

show_menu() {
    echo -e "${GREEN}================================${NC}"
    echo -e "${GREEN}   Cloudflare WARP 管理脚本${NC}"
    echo -e "${GREEN}================================${NC}"
    echo -e "1) 安装并连接 WARP"
    echo -e "2) 断开连接"
    echo -e "3) 重启连接"
    echo -e "4) 查看状态"
    echo -e "5) 查看密钥 (证书/密匙)"
    echo -e "6) 完全卸载"
    echo -e "0) 退出"
    read -rp "请选择 [0-6]: " choice
    case $choice in
        1)
            check_root; install_deps
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
        6) check_root; uninstall_warp ;;
        0) exit 0 ;;
        *) echo -e "${RED}无效选项${NC}" ;;
    esac
}

# 命令行快捷调用
if [ $# -gt 0 ]; then
    case $1 in
        start)   check_root; start_warp ;;
        stop)    check_root; stop_warp ;;
        restart) check_root; stop_warp; start_warp ;;
        status)  check_root; status_warp ;;
        keys)    check_root; show_keys ;;
        install) check_root; install_deps
                 [ "$WGCF_BIN" = "/usr/local/bin/wgcf" ] && install_wgcf_binary
                 generate_config; start_warp ;;
        *)       show_menu ;;
    esac
else
    show_menu
fi
