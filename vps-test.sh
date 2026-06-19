cat > /root/vps-test.sh << 'EOF'
#!/bin/bash
# ===================================================
# VPS 网络质量交互测试脚本 (v16 - 本地测速缓存)
# 新增：首次测速后缓存结果，下次可选择跳过本地测速
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
    local test_type="$1"
    local download="$2"
    local upload="$3"
    local server_info="$4"
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BOLD}📊 ${test_type}带宽测速结果${NC}"
    echo -e "${BLUE}========================================${NC}"
    if [ -n "$server_info" ]; then
        echo -e "📌 测速节点: ${server_info}"
    fi
    echo -e "下载速度: ${download} Mbps  |  上传速度: ${upload} Mbps"
    if [[ -z "$download" || "$download" == "0" ]]; then
        echo -e "${RED}❌ 无法获取有效速度数据${NC}"
    elif (( $(echo "$download > 500" | bc -l 2>/dev/null) )); then
        echo -e "${GREEN}${BOLD}✅ 带宽评级：极速 (★★★★★)${NC}"
    elif (( $(echo "$download > 100" | bc -l 2>/dev/null) )); then
        echo -e "${YELLOW}${BOLD}⚠️  带宽评级：良好 (★★★☆☆)${NC}"
    else
        echo -e "${RED}${BOLD}❌ 带宽评级：较低 (★☆☆☆☆)${NC}"
    fi
    echo -e "${BLUE}========================================${NC}"
}

evaluate_combined() {
    local local_dl="$1"
    local cn_dl="$2"
    local cn_server="$3"
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BOLD}📊 综合对比评价${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo -e "📌 本地带宽 (VPS上限): ${local_dl} Mbps"
    echo -e "📌 国内测速 (到 ${cn_server}): ${cn_dl} Mbps"
    if [[ -z "$local_dl" || -z "$cn_dl" ]]; then
        echo -e "${RED}数据不完整，无法评价${NC}"
    elif (( $(echo "$cn_dl > 500" | bc -l 2>/dev/null) )); then
        echo -e "${GREEN}${BOLD}✅ 国内速度极佳，几乎跑满本地带宽，线路非常优秀！${NC}"
    elif (( $(echo "$cn_dl > 100" | bc -l 2>/dev/null) )); then
        echo -e "${YELLOW}${BOLD}⚠️  国内速度良好，但未完全跑满本地带宽，可能存在轻微拥堵。${NC}"
    else
        echo -e "${RED}${BOLD}❌ 国内速度远低于本地带宽，线路严重拥堵或运营商限速。${NC}"
    fi
    echo -e "${BLUE}========================================${NC}"
}

# ---------- 解析 Speedtest 文本输出 ----------
run_speedtest() {
    local id="$1"
    local output_file="/tmp/speedtest_output.txt"
    if [ -n "$id" ]; then
        speedtest -s "$id" > "$output_file" 2>&1
    else
        speedtest > "$output_file" 2>&1
    fi
    if [ $? -ne 0 ] || [ ! -s "$output_file" ]; then
        echo -e "${RED}测速失败${NC}" >&2
        cat "$output_file" >&2
        rm -f "$output_file"
        return 1
    fi
    local download=$(grep -i "Download:" "$output_file" | tail -1 | sed -E 's/.*Download:[[:space:]]*([0-9.]+).*/\1/')
    local upload=$(grep -i "Upload:" "$output_file" | tail -1 | sed -E 's/.*Upload:[[:space:]]*([0-9.]+).*/\1/')
    local server=$(grep -i "Server:" "$output_file" | head -1 | sed -E 's/^[[:space:]]*Server:[[:space:]]*//')
    if [ -z "$server" ]; then
        server="未知节点"
    fi
    rm -f "$output_file"
    echo "$download $upload $server"
    return 0
}

# ---------- 获取节点ID（增强版） ----------
get_node_id() {
    local city="$1"
    local isp="$2"
    local id=$(speedtest --servers 2>/dev/null | grep -i "$city" | grep -i "$isp" | head -1 | awk '{print $1}')
    if [ -n "$id" ]; then echo "$id"; return 0; fi
    id=$(speedtest --servers 2>/dev/null | grep -i "$city" | head -1 | awk '{print $1}')
    if [ -n "$id" ]; then echo "$id"; return 0; fi
    id=$(speedtest --servers 2>/dev/null | grep -i "$isp" | head -1 | awk '{print $1}')
    if [ -n "$id" ]; then echo "$id"; return 0; fi
    return 1
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

# ---------- 菜单1：集成测速（支持本地缓存） ----------
menu_speedtest() {
    clear
    echo -e "${BLUE}========================================${NC}"
    echo -e "${GREEN}🚀 带宽测速（先测本地，再测国内，自动对比）${NC}"
    echo -e "${BLUE}========================================${NC}"
    
    local local_dl local_ul local_server
    local local_result_file="/tmp/local_speed_result.txt"
    
    # 检查是否有上次的本地测速记录
    if [ -f "$local_result_file" ] && [ -s "$local_result_file" ]; then
        # 读取上次记录
        read local_dl local_ul local_server < "$local_result_file"
        echo -e "${YELLOW}检测到上次本地测速结果：${NC}"
        echo -e "下载: ${local_dl} Mbps, 上传: ${local_ul} Mbps (节点: ${local_server})"
        read -p "是否跳过本次本地测速，直接使用上次结果？(y/n, 默认y): " skip_local
        skip_local=${skip_local:-y}
        if [[ "$skip_local" == "y" || "$skip_local" == "Y" ]]; then
            echo -e "${GREEN}使用上次本地测速结果。${NC}"
            evaluate_speed "本地" "$local_dl" "$local_ul" "$local_server"
        else
            echo -e "${YELLOW}重新测速本地带宽...${NC}"
            local_result=$(run_speedtest "")
            if [ $? -ne 0 ]; then
                echo -e "${RED}本地测速失败，请检查网络${NC}"
                read -p "按回车返回..."
                return
            fi
            local_dl=$(echo "$local_result" | awk '{print $1}')
            local_ul=$(echo "$local_result" | awk '{print $2}')
            local_server=$(echo "$local_result" | cut -d' ' -f3-)
            echo "$local_dl $local_ul $local_server" > "$local_result_file"
            evaluate_speed "本地" "$local_dl" "$local_ul" "$local_server"
        fi
    else
        # 无记录，正常测速
        echo -e "${YELLOW}第一步：测本地带宽（最近节点）...${NC}"
        local_result=$(run_speedtest "")
        if [ $? -ne 0 ]; then
            echo -e "${RED}本地测速失败，请检查网络${NC}"
            read -p "按回车返回..."
            return
        fi
        local_dl=$(echo "$local_result" | awk '{print $1}')
        local_ul=$(echo "$local_result" | awk '{print $2}')
        local_server=$(echo "$local_result" | cut -d' ' -f3-)
        echo "$local_dl $local_ul $local_server" > "$local_result_file"
        evaluate_speed "本地" "$local_dl" "$local_ul" "$local_server"
    fi

    # ------------------ 第二步：选择国内节点 ------------------
    echo -e "${YELLOW}\n第二步：选择国内测速节点 (运营商+城市)${NC}"
    echo "  联通节点:"
    echo "    1) 北京联通    2) 上海联通    3) 广州联通"
    echo "    4) 沈阳联通    5) 大连联通"
    echo "  移动节点:"
    echo "    6) 北京移动    7) 上海移动    8) 广州移动"
    echo "  电信节点:"
    echo "    9) 北京电信   10) 上海电信   11) 广州电信"
    echo " 12) 手动输入城市和运营商 (如: shenyang unicom)"
    echo " 13) 自动 (不推荐，可能测到日本)"
    echo "  0) 返回主菜单"
    read -p "请选择 [0-13] (默认1): " opt
    opt=${opt:-1}
    if [ "$opt" == "0" ]; then
        return
    fi
    local id=""
    local desc=""
    case $opt in
        1) id=$(get_node_id "beijing" "china unicom"); desc="北京联通" ;;
        2) id=$(get_node_id "shanghai" "china unicom"); desc="上海联通" ;;
        3) id=$(get_node_id "guangzhou" "china unicom"); desc="广州联通" ;;
        4) id=$(get_node_id "shenyang" "china unicom"); desc="沈阳联通" ;;
        5) id=$(get_node_id "dalian" "china unicom"); desc="大连联通" ;;
        6) id=$(get_node_id "beijing" "china mobile"); desc="北京移动" ;;
        7) id=$(get_node_id "shanghai" "china mobile"); desc="上海移动" ;;
        8) id=$(get_node_id "guangzhou" "china mobile"); desc="广州移动" ;;
        9) id=$(get_node_id "beijing" "china telecom"); desc="北京电信" ;;
       10) id=$(get_node_id "shanghai" "china telecom"); desc="上海电信" ;;
       11) id=$(get_node_id "guangzhou" "china telecom"); desc="广州电信" ;;
       12) read -p "请输入城市和运营商 (如: shenyang unicom): " custom; id=$(get_node_id "$custom"); desc="自定义 ($custom)" ;;
       13) id=""; desc="自动 (不推荐)" ;;
       *) echo "无效" ; sleep 1 ; menu_speedtest ; return ;;
    esac

    if [ -z "$id" ] && [ "$opt" != "13" ]; then
        echo -e "${RED}❌ 未找到对应节点，请检查城市/运营商名称是否正确。${NC}"
        echo -e "${YELLOW}提示：你可以选 12 手动输入，例如 shenyang unicom${NC}"
        read -p "按回车返回..."
        return
    fi
    if [ -n "$id" ]; then
        echo -e "${YELLOW}使用节点 ID: $id (${desc})${NC}"
    else
        echo -e "${YELLOW}使用默认就近测速 (可能测到日本)${NC}"
    fi

    local cn_result=$(run_speedtest "$id")
    if [ $? -ne 0 ]; then
        echo -e "${RED}国内测速失败${NC}"
        read -p "按回车返回..."
        return
    fi
    local cn_dl=$(echo "$cn_result" | awk '{print $1}')
    local cn_ul=$(echo "$cn_result" | awk '{print $2}')
    local cn_server=$(echo "$cn_result" | cut -d' ' -f3-)
    evaluate_speed "国内" "$cn_dl" "$cn_ul" "$cn_server"

    evaluate_combined "$local_dl" "$cn_dl" "$cn_server"
    read -p "按回车返回..."
}

# ---------- 菜单2：MTR ----------
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

# ---------- 菜单3：路由追踪 ----------
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

# ---------- 菜单4：持续Ping ----------
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

# ---------- 菜单5：综合测试 ----------
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

# ---------- 菜单6：卸载 ----------
menu_uninstall() {
    clear
    echo -e "${RED}========================================${NC}"
    echo -e "${RED}⚠️  卸载脚本${NC}"
    echo -e "${RED}========================================${NC}"
    echo "即将删除："
    echo "  - /root/vps-test.sh (本脚本)"
    echo "  - /tmp/local_speed_result.txt (本地测速缓存)"
    echo "  - /root/speedtest.log (测速日志)"
    echo "  - /tmp/test.bin (临时测试文件)"
    echo "  - /root/jp2ln.sh (旧版测速脚本)"
    read -p "确认卸载？(y/n): " confirm
    if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
        rm -f /root/vps-test.sh /root/speedtest.log /tmp/test.bin /root/jp2ln.sh /tmp/local_speed_result.txt
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
    echo -e "${GREEN}  VPS 网络测试 (v16 - 本地测速缓存)${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo "1) 带宽测速（本地+国内，自动对比）"
    echo "2) MTR 延迟/丢包 (含评价)"
    echo "3) 路由追踪"
    echo "4) 持续 Ping (含评价)"
    echo "5) 综合测试 (测速+MTR+路由)"
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