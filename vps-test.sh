cat > /root/vps-test.sh << 'EOF'
#!/bin/bash
# ===================================================
# VPS 网络质量交互测试脚本 (智能解析版)
# 功能：测速、延迟、丢包、路由追踪
# 新增：自动解析域名，若失败则用 nslookup 获取 IP
# ===================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ---------- 工具函数 ----------
# 解析域名得到 IPv4 地址，若失败返回非零
resolve_ip() {
    local target="$1"
    # 如果已经是 IP 地址（简单正则），直接返回
    if [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "$target"
        return 0
    fi
    # 尝试 dig（若已安装）
    if command -v dig &>/dev/null; then
        local ip=$(dig +short "$target" | grep -E '^[0-9.]+$' | head -1)
        if [ -n "$ip" ]; then
            echo "$ip"
            return 0
        fi
    fi
    # 尝试 nslookup（通常都自带）
    if command -v nslookup &>/dev/null; then
        local ip=$(nslookup "$target" 2>/dev/null | grep -E 'Address: [0-9.]+$' | tail -1 | awk '{print $2}')
        if [ -n "$ip" ]; then
            echo "$ip"
            return 0
        fi
    fi
    # 尝试 host（备胎）
    if command -v host &>/dev/null; then
        local ip=$(host -t A "$target" 2>/dev/null | grep 'has address' | head -1 | awk '{print $4}')
        if [ -n "$ip" ]; then
            echo "$ip"
            return 0
        fi
    fi
    return 1
}

# 获取用户输入的目标，自动解析，若失败则提示重试
get_target() {
    local prompt="$1"
    local default="$2"
    while true; do
        read -p "$prompt" input
        if [ -z "$input" ] && [ -n "$default" ]; then
            input="$default"
        fi
        if [ -z "$input" ]; then
            echo -e "${RED}输入不能为空，请重新输入${NC}"
            continue
        fi
        # 尝试解析
        local ip=$(resolve_ip "$input")
        if [ $? -eq 0 ] && [ -n "$ip" ]; then
            echo "$ip"
            return 0
        else
            echo -e "${RED}解析失败，请检查域名或输入正确的 IP${NC}"
        fi
    done
}

# ---------- 依赖检查 ----------
check_deps() {
    local deps=("curl" "mtr" "traceroute")
    for dep in "${deps[@]}"; do
        if ! command -v $dep &>/dev/null; then
            echo -e "${YELLOW}🔧 安装 $dep ...${NC}"
            apt update -y && apt install -y $dep >/dev/null 2>&1 || yum install -y $dep >/dev/null 2>&1
        fi
    done
    # 安装 speedtest
    if ! command -v speedtest &>/dev/null || ! speedtest --version | grep -q "ookla"; then
        echo -e "${YELLOW}🔧 安装 Ookla Speedtest CLI ...${NC}"
        if [[ -f /etc/debian_version ]]; then
            curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | bash >/dev/null 2>&1
            apt install -y speedtest >/dev/null 2>&1
        else
            curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.rpm.sh | bash >/dev/null 2>&1
            yum install -y speedtest >/dev/null 2>&1
        fi
    fi
    # 确保有 nslookup（一般自带）
}

# 获取联通测速服务器ID
get_speedtest_id() {
    local id=$(speedtest --servers 2>/dev/null | grep -i "shenyang" | grep -i "china unicom" | head -1 | awk '{print $1}')
    [ -z "$id" ] && id=$(speedtest --servers 2>/dev/null | grep -i "beijing" | grep -i "china unicom" | head -1 | awk '{print $1}')
    [ -z "$id" ] && id=$(speedtest --servers 2>/dev/null | grep -i "shanghai" | grep -i "china unicom" | head -1 | awk '{print $1}')
    echo $id
}

# ---------- 菜单功能 ----------
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
    echo -e "${GREEN}📡 回程延迟 & 丢包测试 (MTR)${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo "请选择目标："
    echo "1) 沈阳联通 (202.96.69.38)"
    echo "2) 北京联通 (123.125.0.1)"
    echo "3) 上海联通 (210.22.70.3)"
    echo "4) 大连联通 (202.96.64.68)"
    echo "5) 锦州联通 (ln-jinzhou-cu-v4.ip.zstaticcdn.com)  ← 自动解析"
    echo "6) 手动输入 IP 或域名"
    read -p "请输入选项 [1-6]: " opt
    case $opt in
        1) target="202.96.69.38" ;;
        2) target="123.125.0.1" ;;
        3) target="210.22.70.3" ;;
        4) target="202.96.64.68" ;;
        5) target="ln-jinzhou-cu-v4.ip.zstaticcdn.com" ;;
        6) target=$(get_target "请输入 IP 或域名: ") ;;
        *) echo "无效选项" ; sleep 1 ; menu_mtr ; return ;;
    esac
    # 如果是选项1-4或5，我们仍然要解析一下（选项5是域名），但为了统一，我们都用resolve_ip
    local ip=$(resolve_ip "$target")
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}解析成功: $target -> $ip${NC}"
        echo -e "${YELLOW}正在 MTR 到 $ip ...${NC}"
        mtr -4 -r -c 20 -n "$ip"
    else
        echo -e "${RED}解析失败，请检查目标${NC}"
    fi
    read -p "按回车返回菜单..."
}

menu_traceroute() {
    clear
    echo -e "${BLUE}========================================${NC}"
    echo -e "${GREEN}🗺️  路由追踪 (traceroute)${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo "请选择目标："
    echo "1) 沈阳联通 (202.96.69.38)"
    echo "2) 北京联通 (123.125.0.1)"
    echo "3) 上海联通 (210.22.70.3)"
    echo "4) 大连联通 (202.96.64.68)"
    echo "5) 锦州联通 (ln-jinzhou-cu-v4.ip.zstaticcdn.com)  ← 自动解析"
    echo "6) 手动输入 IP 或域名"
    read -p "请输入选项 [1-6]: " opt
    case $opt in
        1) target="202.96.69.38" ;;
        2) target="123.125.0.1" ;;
        3) target="210.22.70.3" ;;
        4) target="202.96.64.68" ;;
        5) target="ln-jinzhou-cu-v4.ip.zstaticcdn.com" ;;
        6) target=$(get_target "请输入 IP 或域名: ") ;;
        *) echo "无效选项" ; sleep 1 ; menu_traceroute ; return ;;
    esac
    local ip=$(resolve_ip "$target")
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}解析成功: $target -> $ip${NC}"
        echo -e "${YELLOW}正在 traceroute 到 $ip ...${NC}"
        traceroute -4 -n "$ip"
    else
        echo -e "${RED}解析失败，请检查目标${NC}"
    fi
    read -p "按回车返回菜单..."
}

menu_ping() {
    clear
    echo -e "${BLUE}========================================${NC}"
    echo -e "${GREEN}🔄 持续 Ping 测试 (按 Ctrl+C 停止)${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo "请选择目标："
    echo "1) 沈阳联通 (202.96.69.38)"
    echo "2) 北京联通 (123.125.0.1)"
    echo "3) 上海联通 (210.22.70.3)"
    echo "4) 大连联通 (202.96.64.68)"
    echo "5) 锦州联通 (ln-jinzhou-cu-v4.ip.zstaticcdn.com)  ← 自动解析"
    echo "6) 手动输入 IP 或域名"
    read -p "请输入选项 [1-6]: " opt
    case $opt in
        1) target="202.96.69.38" ;;
        2) target="123.125.0.1" ;;
        3) target="210.22.70.3" ;;
        4) target="202.96.64.68" ;;
        5) target="ln-jinzhou-cu-v4.ip.zstaticcdn.com" ;;
        6) target=$(get_target "请输入 IP 或域名: ") ;;
        *) echo "无效选项" ; sleep 1 ; menu_ping ; return ;;
    esac
    local ip=$(resolve_ip "$target")
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}解析成功: $target -> $ip${NC}"
        echo -e "${YELLOW}开始 ping $ip ，观察丢包和延迟波动...${NC}"
        ping -4 "$ip"
    else
        echo -e "${RED}解析失败，请检查目标${NC}"
    fi
    read -p "按回车返回菜单..."
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
    if [ $? -eq 0 ]; then
        mtr -4 -r -c 20 -n "$ip"
    else
        echo -e "${RED}锦州域名解析失败，跳过${NC}"
    fi
    echo -e "${YELLOW}3. 路由到北京联通...${NC}"
    traceroute -4 -n 123.125.0.1
    echo -e "${GREEN}综合测试完成！${NC}"
    read -p "按回车返回菜单..."
}

# ---------- 主菜单 ----------
main_menu() {
    clear
    echo -e "${BLUE}========================================${NC}"
    echo -e "${GREEN}  VPS 网络质量交互测试脚本 (智能解析)${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo "请选择测试项目："
    echo "1) 测速到国内联通节点 (Speedtest)"
    echo "2) 延迟+丢包测试 (MTR)  ← 支持域名自动解析"
    echo "3) 路由追踪 (traceroute) ← 支持域名自动解析"
    echo "4) 持续 Ping (实时监控)  ← 支持域名自动解析"
    echo "5) 综合测试 (1+2+3)"
    echo "6) 退出"
    echo -e "${BLUE}========================================${NC}"
    read -p "请输入选项 [1-6]: " choice
    case $choice in
        1) menu_speedtest ;;
        2) menu_mtr ;;
        3) menu_traceroute ;;
        4) menu_ping ;;
        5) menu_full ;;
        6) echo -e "${GREEN}bye!${NC}" ; exit 0 ;;
        *) echo -e "${RED}无效选项，请重新选择${NC}" ; sleep 1 ; main_menu ;;
    esac
    main_menu
}

# 启动
check_deps
main_menu
EOF

chmod +x /root/vps-test.sh