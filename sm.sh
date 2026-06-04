#!/usr/bin/env bash

# ============================================================
# 脚本名称: reality_scanner.sh
# 功能描述: REALITY 域名扫描器 - 交互式，支持电脑/VPS运行
# 用法: bash reality_scanner.sh
# ============================================================

set -e

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 默认参数
THREADS=100
TIMEOUT=5
OUTPUT_FILE="reality_domains.csv"
TEMP_DIR="/tmp/RealiTLScanner"

# 显示标题
clear
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}     REALITY 域名一键扫描器${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# 询问运行环境
echo -e "${BLUE}请选择运行环境:${NC}"
echo "  1) 在 VPS 上运行 (自动检测本机公网 IP)"
echo "  2) 在本地电脑上运行 (手动输入目标 VPS IP)"
read -p "请输入选项 [1/2]: " RUN_ENV

TARGET_IP=""
if [ "$RUN_ENV" == "1" ]; then
    echo -e "${GREEN}正在自动检测本机公网 IP...${NC}"
    TARGET_IP=$(curl -s -4 ifconfig.me 2>/dev/null || curl -s -4 ipinfo.io/ip 2>/dev/null)
    if [ -z "$TARGET_IP" ]; then
        echo -e "${RED}错误: 无法自动获取本机 IP，请检查网络。${NC}"
        exit 1
    fi
    echo -e "检测到 VPS IP: ${YELLOW}$TARGET_IP${NC}"
elif [ "$RUN_ENV" == "2" ]; then
    read -p "请输入目标 VPS 的 IP 地址: " TARGET_IP
    if [ -z "$TARGET_IP" ]; then
        echo -e "${RED}错误: IP 地址不能为空。${NC}"
        exit 1
    fi
    # 简单验证 IP 格式
    if ! echo "$TARGET_IP" | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'; then
        echo -e "${RED}错误: 无效的 IP 地址格式。${NC}"
        exit 1
    fi
else
    echo -e "${RED}无效选项，请输入 1 或 2。${NC}"
    exit 1
fi

echo ""
echo -e "目标 VPS: ${YELLOW}$TARGET_IP${NC}"
echo -e "线程数:   ${YELLOW}$THREADS${NC}"
echo -e "超时:     ${YELLOW}$TIMEOUT 秒${NC}"
echo ""

# 检查依赖
check_dep() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}错误: 未找到 $1，请先安装。${NC}"
        exit 1
    fi
}
check_dep curl
check_dep unzip
check_dep grep
check_dep awk

# 检测系统架构
detect_arch() {
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')
    local arch=$(uname -m)
    case "$arch" in
        x86_64)  arch="amd64" ;;
        aarch64) arch="arm64" ;;
        arm64)   arch="arm64" ;;
        *)       echo -e "${RED}不支持的架构: $arch${NC}"; exit 1 ;;
    esac
    echo "${os}_${arch}"
}

ARCH_TAG=$(detect_arch)
echo -e "系统架构: ${YELLOW}$ARCH_TAG${NC}"

# 获取最新版本
echo -e "正在获取 RealiTLScanner 最新版本..."
LATEST_VERSION=$(curl -s https://api.github.com/repos/XTLS/RealiTLScanner/releases/latest | grep '"tag_name"' | head -1 | awk -F '"' '{print $4}')
if [ -z "$LATEST_VERSION" ]; then
    echo -e "${RED}错误: 无法获取最新版本号，请检查网络。${NC}"
    exit 1
fi
echo -e "最新版本: ${YELLOW}$LATEST_VERSION${NC}"

# 下载工具
DOWNLOAD_URL="https://github.com/XTLS/RealiTLScanner/releases/download/${LATEST_VERSION}/RealiTLScanner_${LATEST_VERSION}_${ARCH_TAG}.zip"
echo -e "下载地址: $DOWNLOAD_URL"

mkdir -p "$TEMP_DIR"
cd "$TEMP_DIR"

echo -e "正在下载..."
curl -L -o scanner.zip "$DOWNLOAD_URL" --progress-bar
echo -e "正在解压..."
unzip -o scanner.zip
chmod +x RealiTLScanner

# 开始扫描
echo -e "${GREEN}开始扫描，请耐心等待（可能需要几分钟）...${NC}"
./RealiTLScanner -addr "$TARGET_IP" -port 443 -thread "$THREADS" -timeout "$TIMEOUT" -out "$OUTPUT_FILE"

# 输出结果
if [ -f "$OUTPUT_FILE" ]; then
    LINE_COUNT=$(wc -l < "$OUTPUT_FILE")
    if [ "$LINE_COUNT" -gt 1 ]; then
        echo ""
        echo -e "${GREEN}========================================${NC}"
        echo -e "${GREEN}       扫描结果（供您直观查看）${NC}"
        echo -e "${GREEN}========================================${NC}"
        echo -e "共找到 ${YELLOW}$((LINE_COUNT-1))${NC} 个可用域名"
        echo ""
        # 以表格形式展示前20行（首行为标题）
        echo -e "${BLUE}域名                              | 延迟 | 证书详情${NC}"
        echo "----------------------------------|------|-----------------------------"
        # 使用 awk 格式化输出，跳过第一行标题，只取域名、延迟、证书信息
        tail -n +2 "$OUTPUT_FILE" | head -20 | awk -F',' '{printf "%-32s | %4s | %s\n", $1, $2, substr($3,1,40)}'
        if [ "$LINE_COUNT" -gt 21 ]; then
            echo "... 还有 $((LINE_COUNT-21)) 行未显示，请查看完整文件。"
        fi
        echo ""
        echo -e "完整结果已保存到: ${YELLOW}$(pwd)/$OUTPUT_FILE${NC}"
    else
        echo -e "${RED}未找到任何可用域名。可以尝试增加线程数或降低超时时间。${NC}"
    fi
else
    echo -e "${RED}扫描失败，未生成输出文件。${NC}"
    exit 1
fi

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  扫描结束，感谢使用！${NC}"
echo -e "${GREEN}========================================${NC}"
