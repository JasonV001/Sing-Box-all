cat > /root/vps-test.sh << 'EOF'
#!/bin/bash
# ===================================================
# VPS 网络质量交互测试脚本 (智能解析版 v4)
# 修复：强制安装 DNS 工具，确保域名解析成功
# ===================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ---------- 核心：智能解析域名 ----------
resolve_ip() {
    local target="$1"
    # 如果已经是 IPv4 地址，直接返回
    if [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "$target"
        return 0
    fi

    local ip=""
    # 优先使用 dig
    if command -v dig &>/dev/null; then
        ip=$(dig +short "$target" 2>/dev/null | grep -E '^[0-9.]+$' | head -1)
        [ -n "$ip" ] && { echo "$ip"; return 0; }
    fi
    # 其次 nslookup
    if command -v nslookup &>/dev/null; then
        ip=$(nslookup "$target" 2>/dev/null | grep -E 'Address: [0-9.]+$' | tail -1 | awk '{print $2}')
        [ -n "$ip" ] && { echo "$ip"; return 0; }
    fi
    # 备胎 host
    if command -v host &>/dev/null; then
        ip=$(host -t A "$target" 2>/dev/null | grep 'has address' | head -1 | awk '{print $4}')
        [ -n "$ip" ] && { echo "$ip"; return 0; }
    fi
    # 最后用 getent（glibc 自带）
    if command -v getent &>/dev/null; then
        ip=$(getent ahosts "$target" 2>/dev/null | grep -E '^[0-9.]+' | head -1 | awk '{print $1}')
        [ -n "$ip" ] && { echo "$ip"; return 0; }
    fi
    return 1
}

# 获取用户输入，自动解析
get_target() {
    local prompt="$1"
    local default="$2"
    while true; do
        read -p "$prompt" input
        [ -z "$input" ] && [ -n "$default" ] && input="$default"
        [ -z "$input" ] && { echo -e "${RED}输入不能为空${NC}"; continue; }
        local ip=$(resolve_ip "$input")
        if [ $? -eq 0 ] && [ -n "$ip" ]; then
            echo "$ip"
            return 0
        else
            echo -e "${RED}解析失败，请重新输入${NC}"
        fi
    done
}

# ---------- 依赖检查（已添加 DNS 工具） ----------
check_deps() {
    # 基础网络工具
    for dep in curl mtr traceroute; do
        if ! command -v $dep &>/dev/null; then
            echo -e "${YELLOW}安装 $dep ...${NC}"
            apt update -y && apt install -y $dep >/dev/null 2>&1 || yum install -y $dep >/dev/null 2>&1
        fi
    done
    # DNS 解析工具（关键）
    if ! command -v nslookup &>/dev/null && ! command -v dig &>/dev/null; then
        echo -e "${YELLOW}安装 DNS 工具 (dnsutils/bind-utils) ...${NC}"
        if [[ -f /etc/debian_version ]]; then
            apt update -y && apt install -y dnsutils >/dev/null 2>&1
        else
            yum install -y bind-utils >/dev/null 2>&1
        fi
    fi
    # Speedtest CLI
    if ! command -v speedtest &>/dev/null || ! speedtest --version | grep -q "ookla"; then
        echo -e "${YELLOW}安装 Ookla Speedtest ...${NC}"
        if [[ -f /etc/debian_version ]]; then
            curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | bash >/dev/null 2>&1
            apt install -y speedtest >/dev/null 2>&1
        else
            curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.rpm.sh | bash >/dev/null 2>&1
            yum install -y speedtest >/dev/null 2>&1
        fi
    fi
}

# 获取联通测速ID
get_speedtest_id() {
    local id=$(speedtest --servers 2>/dev/null | grep -i "shenyang" | grep -i "china unicom" | head -1 | awk '{print $1}')
    [ -z "$id" ] && id=$(speedtest --servers 2>/dev/null | grep -i "beijing" | grep -i "china unicom" | head -1 | awk '{print $1}')
    [ -z "$id" ] && id=$(speedtest --servers 2>/dev/null | grep -i "shanghai" | grep -i "china unicom" | head -1 | awk '{print $1}')
    echo $id
}

# ---------- 菜单功能（此处省略详细实现，与之前一致，但全部使用新的解析逻辑）----------
# 为了节省篇幅，所有菜单函数沿用之前版本，但解析调用均已更新
# 实际脚本中会包含全部完整函数，下面仅列出主菜单和卸载

menu_speedtest() {
    clear
    echo -e "${BLUE}========================================${NC}"
    echo -e "${GREEN}🚀 测速到国内联通节点${NC}"
    echo -e "${BLUE}========================================${NC}"
    local id=$(get_speedtest_id)
    if [ -z "$id" ]; then
        echo -e "${RED}未找到联通测速节点，使用默认就近测速${NC}"
        speedtest
    else
        echo -e "使用节点 ID: $id"
        speedtest -s $id
    fi
    echo ""
    read -p "按回车返回菜单..."
}

menu_mtr() {
    clear
    echo -e "${BLUE}========================================${NC}"
    echo -e "${GREEN}📡 延迟+丢包测试 (MTR)${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo "1) 沈阳联通 (202.96.69.38)"
    echo "2) 北京联通 (123.125.0.1)"
    echo "3) 上海联通 (210.22.70.3)"
    echo "4) 大连联通 (202.96.64.68)"
    echo "5) 锦州联通 (自动解析)"
    echo "6) 手动输入 IP/域名"
    read -p "请选择 [1-6]: " opt
    case $opt in
        1) target="202.96.69.38" ;;
        2) target="123.125.0.1" ;;
        3) target="210.22.70.3" ;;
        4) target="202.96.64.68" ;;
        5) target="ln-jinzhou-cu-v4.ip.zstaticcdn.com" ;;
        6) target=$(get_target "请输入 IP 或域名: ") ;;
        *) echo "无效" ; sleep 1 ; menu_mtr ; return ;;
    esac
    local ip=$(resolve_ip "$target")
    if [ $? -eq 0 ] && [ -n "$ip" ]; then
        echo -e "${GREEN}解析成功: $target -> $ip${NC}"
        echo -e "${YELLOW}MTR 到 $ip ...${NC}"
        mtr -4 -r -c 20 -n "$ip"
    else
        echo -e "${RED}解析失败，请检查目标${NC}"
    fi
    read -p "按回车返回..."
}

menu_traceroute() {
    clear
    echo -e "${BLUE}========================================${NC}"
    echo -e "${GREEN}🗺️  路由追踪 (traceroute)${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo "1) 沈阳联通 (202.96.69.38)"
    echo "2) 北京联通 (123.125.0.1)"
    echo "3) 上海联通 (210.22.70.3)"
    echo "4) 大连联通 (202.96.64.68)"
    echo "5) 锦州联通 (自动解析)"
    echo "6) 手动输入 IP/域名"
    read -p "请选择 [1-6]: " opt
    case $opt in
        1) target="202.96.69.38" ;;
        2) target="123.125.0.1" ;;
        3) target="210.22.70.3" ;;
        4) target="202.96.64.68" ;;
        5) target="ln-jinzhou-cu-v4.ip.zstaticcdn.com" ;;
        6) target=$(get_target "请输入 IP 或域名: ") ;;
        *) echo "无效" ; sleep 1 ; menu_traceroute ; return ;;
    esac
    local ip=$(resolve_ip "$target")
    if [ $? -eq 0 ] && [ -n "$ip" ]; then
        echo -e "${GREEN}解析成功: $target -> $ip${NC}"
        echo -e "${YELLOW}Traceroute 到 $ip ...${NC}"
        traceroute -4 -n "$ip"
    else
        echo -e "${RED}解析失败，请检查目标${NC}"
    fi
    read -p "按回车返回..."
}

menu_ping() {
    clear
    echo -e "${BLUE}========================================${NC}"
    echo -e "${GREEN}🔄 持续 Ping 测试 (按 Ctrl+C 停止)${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo "1) 沈阳联通 (202.96.69.38)"
    echo "2) 北京联通 (123.125.0.1)"
    echo "3) 上海联通 (210.22.70.3)"
    echo "4) 大连联通 (202.96.64.68)"
    echo "5) 锦州联通 (自动解析)"
    echo "6) 手动输入 IP/域名"
    read -p "请选择 [1-6]: " opt
    case $opt in
        1) target="202.96.69.38" ;;
        2) target="123.125.0.1" ;;
        3) target="210.22.70.3" ;;
        4) target="202.96.64.68" ;;
        5) target="ln-jinzhou-cu-v4.ip.zstaticcdn.com" ;;
        6) target=$(get_target "请输入 IP 或域名: ") ;;
        *) echo "无效" ; sleep 1 ; menu_ping ; return ;;
    esac
    local ip=$(resolve_ip "$target")
    if [ $? -eq 0 ] && [ -n "$ip" ]; then
        echo -e "${GREEN}解析成功: $target -> $ip${NC}"
        echo -e "${YELLOW}开始 ping $ip ...${NC}"
        ping -4 "$ip"
    else
        echo -e "${RED}解析失败，请检查目标${NC}"
    fi
    read -p "按回车返回..."
}

menu_full() {
    clear
    echo -e "${BLUE}========================================${NC}"
    echo -e "${GREEN}📊 综合测试 (测速+MTR+路由)${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo -e "${YELLOW}1. 测速到联通节点...${NC}"
    menu_speedtest
    echo -e "${YELLOW}2. MTR到锦州联通...${NC}"
    local target="ln-jinzhou-cu-v4.ip.zstaticcdn.com"
    local ip=$(resolve_ip "$target")
    if [ $? -eq 0 ] && [ -n "$ip" ]; then
        mtr -4 -r -c 20 -n "$ip"
    else
        echo -e "${RED}锦州域名解析失败，跳过${NC}"
    fi
    echo -e "${YELLOW}3. 路由到北京联通...${NC}"
    traceroute -4 -n 123.125.0.1
    echo -e "${GREEN}综合测试完成！${NC}"
    read -p "按回车返回..."
}

# 卸载功能
menu_uninstall() {
    clear
    echo -e "${RED}========================================${NC}"
    echo -e "${RED}⚠️  卸载脚本 (清理所有相关文件)${NC}"
    echo -e "${RED}========================================${NC}"
    echo "即将删除以下文件："
    echo "  - /root/vps-test.sh (本脚本)"
    echo "  - /root/speedtest.log (测速日志)"
    echo "  - /tmp/test.bin (临时测试文件)"
    echo "  - /root/jp2ln.sh (旧版测速脚本，如有)"
    echo ""
    read -p "确认卸载？(y/n): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo -e "${GREEN}取消卸载。${NC}"
        read -p "按回车返回..."
        return
    fi
    rm -f /root/vps-test.sh
    rm -f /root/speedtest.log
    rm -f /tmp/test.bin
    rm -f /root/jp2ln.sh
    echo -e "${GREEN}✅ 已删除所有相关文件，脚本已卸载。${NC}"
    exit 0
}

# ---------- 主菜单 ----------
main_menu() {
    clear
    echo -e "${BLUE}========================================${NC}"
    echo -e "${GREEN}  VPS 网络测试 (智能解析 v4)${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo "1) 测速到国内联通"
    echo "2) MTR 延迟/丢包"
    echo "3) 路由追踪"
    echo "4) 持续 Ping"
    echo "5) 综合测试"
    echo "6) 卸载脚本"
    echo "7) 退出"
    echo -e "${BLUE}========================================${NC}"
    read -p "请选择 [1-7]: " choice
    case $choice in
        1) menu_speedtest ;;
        2) menu_mtr ;;
        3) menu_traceroute ;;
        4) menu_ping ;;
        5) menu_full ;;
        6) menu_uninstall ;;
        7) echo "bye!" ; exit 0 ;;
        *) echo "无效" ; sleep 1 ; main_menu ;;
    esac
    main_menu
}

# 启动
check_deps
main_menu
EOF

chmod +x /root/vps-test.sh