cat > /root/cs.sh << 'EOF'
#!/bin/bash
# ===================================================
# VPS 网络质量交互测试脚本 (针对联通回国优化)
# 功能：测速、延迟、丢包、路由追踪
# ===================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 检查并安装必要工具
check_deps() {
    local deps=("curl" "mtr" "speedtest")
    for dep in "${deps[@]}"; do
        if ! command -v $dep &>/dev/null; then
            echo -e "${YELLOW}🔧 安装 $dep ...${NC}"
            apt update -y && apt install -y $dep >/dev/null 2>&1 || yum install -y $dep >/dev/null 2>&1
        fi
    done
    # 特别处理 speedtest (如果未安装或为旧版)
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
}

# 获取联通测速服务器ID（优先沈阳，次选北京）
get_speedtest_id() {
    local id=$(speedtest --servers | grep -i "shenyang" | grep -i "china unicom" | head -1 | awk '{print $1}')
    if [ -z "$id" ]; then
        id=$(speedtest --servers | grep -i "beijing" | grep -i "china unicom" | head -1 | awk '{print $1}')
    fi
    if [ -z "$id" ]; then
        id=$(speedtest --servers | grep -i "shanghai" | grep -i "china unicom" | head -1 | awk '{print $1}')
    fi
    echo $id
}

# 菜单1：测速到国内联通
menu_speedtest() {
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
    read -p "按回车返回菜单..."
}

# 菜单2：MTR延迟+丢包测试
menu_mtr() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${GREEN}📡 回程延迟 & 丢包测试 (MTR)${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo "请选择目标节点："
    echo "1) 沈阳联通 (202.96.69.38)"
    echo "2) 北京联通 (123.125.0.1)"
    echo "3) 上海联通 (210.22.70.3)"
    echo "4) 大连联通 (202.96.64.68)"
    echo "5) 手动输入IP"
    read -p "请输入选项 [1-5]: " opt
    case $opt in
        1) target="202.96.69.38" ;;
        2) target="123.125.0.1" ;;
        3) target="210.22.70.3" ;;
        4) target="202.96.64.68" ;;
        5) read -p "请输入目标IP: " target ;;
        *) echo "无效选项" ; menu_mtr ;;
    esac
    echo -e "${YELLOW}正在测试到 $target ...${NC}"
    mtr -4 -r -c 20 -n $target
    read -p "按回车返回菜单..."
}

# 菜单3：路由追踪
menu_traceroute() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${GREEN}🗺️  路由追踪 (traceroute)${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo "请选择目标节点："
    echo "1) 沈阳联通 (202.96.69.38)"
    echo "2) 北京联通 (123.125.0.1)"
    echo "3) 上海联通 (210.22.70.3)"
    echo "4) 手动输入IP"
    read -p "请输入选项 [1-4]: " opt
    case $opt in
        1) target="202.96.69.38" ;;
        2) target="123.125.0.1" ;;
        3) target="210.22.70.3" ;;
        4) read -p "请输入目标IP: " target ;;
        *) echo "无效选项" ; menu_traceroute ;;
    esac
    echo -e "${YELLOW}路由追踪到 $target ...${NC}"
    traceroute -4 -n $target
    read -p "按回车返回菜单..."
}

# 菜单4：持续ping测试（需在后台运行，建议搭配本地终端）
menu_ping() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${GREEN}🔄 持续 Ping 测试 (按 Ctrl+C 停止)${NC}"
    echo -e "${BLUE}========================================${NC}"
    read -p "请输入要 ping 的目标IP (留空默认测试沈阳联通): " target
    if [ -z "$target" ]; then
        target="202.96.69.38"
    fi
    echo -e "${YELLOW}开始 ping $target ，观察丢包和延迟波动...${NC}"
    ping -4 $target
    read -p "按回车返回菜单..."
}

# 菜单5：综合测试（跑全部）
menu_full() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${GREEN}📊 综合测试 (测速+MTR+路由)${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo -e "${YELLOW}1. 测速到联通节点...${NC}"
    menu_speedtest
    echo -e "${YELLOW}2. MTR到沈阳联通...${NC}"
    mtr -4 -r -c 20 -n 202.96.69.38
    echo -e "${YELLOW}3. 路由到北京联通...${NC}"
    traceroute -4 -n 123.125.0.1
    echo -e "${GREEN}综合测试完成！${NC}"
    read -p "按回车返回菜单..."
}

# 主菜单
main_menu() {
    clear
    echo -e "${BLUE}========================================${NC}"
    echo -e "${GREEN}  VPS 网络质量交互测试脚本${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo "请选择测试项目："
    echo "1) 测速到国内联通节点 (Speedtest)"
    echo "2) 延迟+丢包测试 (MTR)"
    echo "3) 路由追踪 (traceroute)"
    echo "4) 持续 Ping (实时监控)"
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
        6) echo "bye!" ; exit 0 ;;
        *) echo -e "${RED}无效选项，请重新选择${NC}" ; sleep 1 ; main_menu ;;
    esac
    main_menu
}

# 运行前检查依赖
check_deps

# 启动主菜单
main_menu
EOF

chmod +x /root/cs.sh