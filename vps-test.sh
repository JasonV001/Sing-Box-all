cat > /root/vps-test.sh << 'EOF'
#!/bin/bash
# ===================================================
# VPS 网络质量交互测试脚本 (v7 - 支持选择测速节点)
# 功能：测速时可选择沈阳/大连/北京/上海等联通节点
# ===================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# ---------- 评价函数 ----------
evaluate_latency() {
    local target_name="$1"
    local avg="$2"
    local loss="$3"
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BOLD}📊 延迟/丢包评价 (目标: $target_name)${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo -e "平均延迟: ${avg}ms  |  丢包率: ${loss}%"
    if [[ -z "$avg" || -z "$loss" || "$avg" == "?" || "$loss" == "?" ]]; then
        echo -e "${RED}❌ 无法获取有效数据${NC}"
    elif (( $(echo "$avg < 80" | bc -l 2>/dev/null) )) && (( $(echo "$loss < 2" | bc -l 2>/dev/null) )); then
        echo -e "${GREEN}${BOLD}✅ 线路评级：优秀 (★★★★★)${NC}"
    elif (( $(echo "$avg < 120" | bc -l 2>/dev/null) )) && (( $(echo "$loss < 5" | bc -l 2>/dev/null) )); then
        echo -e "${YELLOW}${BOLD}⚠️  线路评级：良好 (★★★☆☆)${NC}"
    else
        echo -e "${RED}${BOLD}❌ 线路评级：较差 (★☆☆☆☆)${NC}"
    fi
    echo -e "${BLUE}========================================${NC}"
}

evaluate_speed() {
    local download="$1"
    local upload="$2"
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BOLD}📊 带宽测速评价${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo -e "下载速度: ${download} Mbps  |  上传速度: ${upload} Mbps"
    if [[ -z "$download" || "$download" == "0" ]]; then
        echo -e "${RED}❌ 无法获取有效速度数据${NC}"
    elif (( $(echo "$download > 500" | bc -l 2>/dev/null) )); then
        echo -e "${GREEN}${BOLD}✅ 带宽评级：极速 (★★★★★)${NC}"
        echo -e "${GREEN}带宽非常充足，跑满G口，硬件无超售。${NC}"
    elif (( $(echo "$download > 100" | bc -l 2>/dev/null) )); then
        echo -e "${YELLOW}${BOLD}⚠️  带宽评级：良好 (★★★☆☆)${NC}"
        echo -e "${YELLOW}正常水平，看4K/日常使用绰绰有余。${NC}"
    else
        echo -e "${RED}${BOLD}❌ 带宽评级：较差 (★☆☆☆☆)${NC}"
        echo -e "${RED}带宽较低，可能是商家限制或线路拥堵。${NC}"
    fi
    echo -e "${BLUE}========================================${NC}"
}

# ---------- 解析 Speedtest JSON ----------
run_speedtest() {
    local id="$1"
    local output_file="/tmp/speedtest_result.json"
    if [ -n "$id" ]; then
        echo -e "${YELLOW}使用节点 ID: $id${NC}"
        speedtest -s "$id" --format=json-pretty > "$output_file" 2>/dev/null
    else
        echo -e "${YELLOW}使用默认就近测速${NC}"
        speedtest --format=json-pretty > "$output_file" 2>/dev/null
    fi
    if [ $? -ne 0 ] || [ ! -s "$output_file" ]; then
        echo -e "${RED}测速失败，请检查网络或重试${NC}"
        return 1
    fi
    local download=$(grep '"download"' "$output_file" | head -1 | awk '{print $2}' | sed 's/[^0-9.]//g')
    local upload=$(grep '"upload"' "$output_file" | head -1 | awk '{print $2}' | sed 's/[^0-9.]//g')
    if [ -n "$download" ] && [ -n "$upload" ]; then
        download=$(echo "scale=2; $download / 1000000" | bc -l 2>/dev/null)
        upload=$(echo "scale=2; $upload / 1000000" | bc -l 2>/dev/null)
        evaluate_speed "$download" "$upload"
    else
        echo -e "${RED}解析速度数据失败${NC}"
    fi
    rm -f "$output_file"
}

# ---------- 获取节点ID ----------
get_node_id() {
    local city="$1"
    speedtest --servers 2>/dev/null | grep -i "$city" | grep -i "china unicom" | head -1 | awk '{print $1}'
}

# ---------- 智能解析域名 ----------
resolve_ip() {
    local target="$1"
    if [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "$target"; return 0
    fi
    local ip=""
    if command -v dig &>/dev/null; then
        ip=$(dig +short "$target" 2>/dev/null | grep -E '^[0-9.]+$' | head -1)
        [ -n "$ip" ] && { echo "$ip"; return 0; }
    fi
    if command -v nslookup &>/dev/null; then
        ip=$(nslookup "$target" 2>/dev/null | grep -E 'Address: [0-9.]+$' | tail -1 | awk '{print $2}')
        [ -n "$ip" ] && { echo "$ip"; return 0; }
    fi
    if command -v host &>/dev/null; then
        ip=$(host -t A "$target" 2>/dev/null | grep 'has address' | head -1 | awk '{print $4}')
        [ -n "$ip" ] && { echo "$ip"; return 0; }
    fi
    if command -v getent &>/dev/null; then
        ip=$(getent ahosts "$target" 2>/dev/null | grep -E '^[0-9.]+' | head -1 | awk '{print $1}')
        [ -n "$ip" ] && { echo "$ip"; return 0; }
    fi
    return 1
}

get_target() {
    local prompt="$1"
    local default="$2"
    while true; do
        read -p "$prompt" input
        [ -z "$input" ] && [ -n "$default" ] && input="$default"
        [ -z "$input" ] && { echo -e "${RED}输入不能为空${NC}"; continue; }
        local ip=$(resolve_ip "$input")
        if [ $? -eq 0 ] && [ -n "$ip" ]; then
            echo "$ip"; return 0
        else
            echo -e "${RED}解析失败，请重新输入${NC}"
        fi
    done
}

# ---------- 依赖检查 ----------
check_deps() {
    for dep in curl mtr traceroute bc; do
        if ! command -v $dep &>/dev/null; then
            echo -e "${YELLOW}安装 $dep ...${NC}"
            apt update -y && apt install -y $dep >/dev/null 2>&1 || yum install -y $dep >/dev/null 2>&1
        fi
    done
    if ! command -v nslookup &>/dev/null && ! command -v dig &>/dev/null; then
        echo -e "${YELLOW}安装 DNS 工具 ...${NC}"
        if [[ -f /etc/debian_version ]]; then
            apt update -y && apt install -y dnsutils >/dev/null 2>&1
        else
            yum install -y bind-utils >/dev/null 2>&1
        fi
    fi
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

# ---------- 解析 MTR ----------
parse_mtr() {
    local result_file="$1"
    local last_line=$(grep -E '^[ ]*[0-9]+\.\|--' "$result_file" | grep -v '???' | grep -v '100.0%' | tail -1)
    if [ -z "$last_line" ]; then
        echo ""; echo ""; return 1
    fi
    local loss=$(echo "$last_line" | awk '{print $3}' | sed 's/%//')
    local avg=$(echo "$last_line" | awk '{print $6}')
    echo "$avg"; echo "$loss"; return 0
}

# ---------- 菜单：测速（带节点选择） ----------
menu_speedtest() {
    clear
    echo -e "${BLUE}========================================${NC}"
    echo -e "${GREEN}🚀 测速到国内联通节点 (自动评价)${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo "请选择测试节点："
    echo "1) 沈阳联通 (自动查找)"
    echo "2) 大连联通 (自动查找)"
    echo "3) 北京联通 (自动查找)"
    echo "4) 上海联通 (自动查找)"
    echo "5) 自动选择 (默认最近)"
    echo "6) 手动输入节点ID"
    read -p "请输入选项 [1-6]: " opt
    local id=""
    case $opt in
        1) id=$(get_node_id "shenyang") ;;
        2) id=$(get_node_id "dalian") ;;
        3) id=$(get_node_id "beijing") ;;
        4) id=$(get_node_id "shanghai") ;;
        5) id="" ;;
        6) read -p "请输入节点ID (如 5145): " id ;;
        *) echo "无效选项"; sleep 1; menu_speedtest; return ;;
    esac
    if [ -n "$id" ]; then
        run_speedtest "$id"
    else
        if [ "$opt" -eq 5 ] || [ -z "$id" ]; then
            run_speedtest ""
        else
            echo -e "${RED}未找到对应节点，使用默认测速${NC}"
            run_speedtest ""
        fi
    fi
    read -p "按回车返回..."
}

# ---------- 其余菜单 ----------
menu_mtr() {
    clear
    echo -e "${BLUE}========================================${NC}"
    echo -e "${GREEN}📡 延迟+丢包测试 (MTR) 含自动评价${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo "1) 沈阳联通 (202.96.69.38)"
    echo "2) 北京联通 (123.125.0.1)"
    echo "3) 上海联通 (210.22.70.3)"
    echo "4) 大连联通 (202.96.64.68)"
    echo "5) 锦州联通 (自动解析)"
    echo "6) 手动输入 IP/域名"
    read -p "请选择 [1-6]: " opt
    case $opt in
        1) target="202.96.69.38"; name="沈阳联通" ;;
        2) target="123.125.0.1"; name="北京联通" ;;
        3) target="210.22.70.3"; name="上海联通" ;;
        4) target="202.96.64.68"; name="大连联通" ;;
        5) target="ln-jinzhou-cu-v4.ip.zstaticcdn.com"; name="锦州联通" ;;
        6) target=$(get_target "请输入 IP 或域名: "); name="手动目标" ;;
        *) echo "无效" ; sleep 1 ; menu_mtr ; return ;;
    esac
    local ip=$(resolve_ip "$target")
    if [ $? -ne 0 ] || [ -z "$ip" ]; then
        echo -e "${RED}解析失败${NC}"
        read -p "按回车返回..."
        return
    fi
    echo -e "${GREEN}解析成功: $target -> $ip${NC}"
    echo -e "${YELLOW}正在 MTR ...${NC}"
    mtr -4 -r -c 20 -n "$ip" > /tmp/mtr_result
    cat /tmp/mtr_result
    local avg=$(parse_mtr "/tmp/mtr_result" | head -1)
    local loss=$(parse_mtr "/tmp/mtr_result" | tail -1)
    if [ -n "$avg" ] && [ -n "$loss" ]; then
        evaluate_latency "$name" "$avg" "$loss"
    else
        echo -e "${RED}无法获取有效数据${NC}"
    fi
    rm -f /tmp/mtr_result
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
        1) target="202.96.69.38"; name="沈阳联通" ;;
        2) target="123.125.0.1"; name="北京联通" ;;
        3) target="210.22.70.3"; name="上海联通" ;;
        4) target="202.96.64.68"; name="大连联通" ;;
        5) target="ln-jinzhou-cu-v4.ip.zstaticcdn.com"; name="锦州联通" ;;
        6) target=$(get_target "请输入 IP 或域名: "); name="手动目标" ;;
        *) echo "无效" ; sleep 1 ; menu_traceroute ; return ;;
    esac
    local ip=$(resolve_ip "$target")
    if [ $? -ne 0 ] || [ -z "$ip" ]; then
        echo -e "${RED}解析失败${NC}"
        read -p "按回车返回..."
        return
    fi
    echo -e "${GREEN}解析成功: $target -> $ip${NC}"
    traceroute -4 -n "$ip"
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
        1) target="202.96.69.38"; name="沈阳联通" ;;
        2) target="123.125.0.1"; name="北京联通" ;;
        3) target="210.22.70.3"; name="上海联通" ;;
        4) target="202.96.64.68"; name="大连联通" ;;
        5) target="ln-jinzhou-cu-v4.ip.zstaticcdn.com"; name="锦州联通" ;;
        6) target=$(get_target "请输入 IP 或域名: "); name="手动目标" ;;
        *) echo "无效" ; sleep 1 ; menu_ping ; return ;;
    esac
    local ip=$(resolve_ip "$target")
    if [ $? -ne 0 ] || [ -z "$ip" ]; then
        echo -e "${RED}解析失败${NC}"
        read -p "按回车返回..."
        return
    fi
    echo -e "${GREEN}解析成功: $target -> $ip${NC}"
    echo -e "${YELLOW}开始 ping，按 Ctrl+C 停止后自动评价${NC}"
    ping -4 "$ip" > /tmp/ping_result
    local avg=$(tail -1 /tmp/ping_result | awk -F'/' '{print $5}')
    local loss=$(grep -oP '\d+(?=% packet loss)' /tmp/ping_result)
    if [ -n "$avg" ] && [ -n "$loss" ]; then
        evaluate_latency "$name" "$avg" "$loss"
    else
        echo -e "${RED}无法获取数据${NC}"
    fi
    rm -f /tmp/ping_result
    read -p "按回车返回..."
}

menu_full() {
    clear
    echo -e "${BLUE}========================================${NC}"
    echo -e "${GREEN}📊 综合测试 (测速+MTR+路由)${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo -e "${YELLOW}1. 测速...${NC}"
    menu_speedtest
    echo -e "${YELLOW}2. MTR到锦州联通...${NC}"
    local target="ln-jinzhou-cu-v4.ip.zstaticcdn.com"
    local name="锦州联通"
    local ip=$(resolve_ip "$target")
    if [ $? -eq 0 ] && [ -n "$ip" ]; then
        mtr -4 -r -c 20 -n "$ip" > /tmp/mtr_result
        cat /tmp/mtr_result
        local avg=$(parse_mtr "/tmp/mtr_result" | head -1)
        local loss=$(parse_mtr "/tmp/mtr_result" | tail -1)
        if [ -n "$avg" ] && [ -n "$loss" ]; then
            evaluate_latency "$name" "$avg" "$loss"
        else
            echo -e "${RED}无法获取数据${NC}"
        fi
        rm -f /tmp/mtr_result
    else
        echo -e "${RED}锦州域名解析失败，跳过MTR${NC}"
    fi
    echo -e "${YELLOW}3. 路由到北京联通...${NC}"
    traceroute -4 -n 123.125.0.1
    echo -e "${GREEN}综合测试完成！${NC}"
    read -p "按回车返回..."
}

menu_uninstall() {
    clear
    echo -e "${RED}========================================${NC}"
    echo -e "${RED}⚠️  卸载脚本${NC}"
    echo -e "${RED}========================================${NC}"
    read -p "确认卸载？(y/n): " confirm
    if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
        rm -f /root/vps-test.sh /root/speedtest.log /tmp/test.bin /root/jp2ln.sh
        echo -e "${GREEN}✅ 已清理。${NC}"
        exit 0
    else
        echo -e "${GREEN}取消。${NC}"
        read -p "按回车返回..."
    fi
}

# ---------- 主菜单 ----------
main_menu() {
    clear
    echo -e "${BLUE}========================================${NC}"
    echo -e "${GREEN}  VPS 网络测试 (v7 - 可选测速节点)${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo "1) 测速到国内联通 (可选节点)"
    echo "2) MTR 延迟/丢包 (含评价)"
    echo "3) 路由追踪"
    echo "4) 持续 Ping (含评价)"
    echo "5) 综合测试 (含评价)"
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