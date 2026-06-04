#!/usr/bin/env bash

# ============================================================
# 脚本名称: reality_scanner.sh
# 功能描述: 一键扫描 REALITY 协议可用的伪装域名 (兼容 Debian / Alpine)
# 用法: bash reality_scanner.sh
# ============================================================

set -e

# 检测 bash 路径，优先使用 /bin/bash 如果存在
SHELL_PATH="/bin/bash"
if [ ! -f "$SHELL_PATH" ]; then
    SHELL_PATH=$(command -v bash)
fi
if [ -n "$SHELL_PATH" ]; then
    exec "$SHELL_PATH" "$0" "$@"
fi

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 默认参数
THREADS=100
TIMEOUT=5
OUTPUT_FILE="reality_domains.csv"
FILTERED_OUTPUT="filtered_domains.csv"
TEMP_DIR="/tmp/RealiTLScanner"

# 显示标题
clear
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}     REALITY 域名扫描器 (Debian/Alpine 兼容版)${NC}"
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
        echo -e "${RED}错误: IP 不能为空。${NC}"
        exit 1
    fi
else
    echo -e "${RED}无效选项。${NC}"
    exit 1
fi

echo ""
echo -e "目标 VPS: ${YELLOW}$TARGET_IP${NC}"
echo ""

# 检测包管理器并安装依赖
install_deps() {
    if command -v apt &> /dev/null; then
        echo -e "${GREEN}检测到 Debian/Ubuntu 系统，正在安装依赖...${NC}"
        apt update -y
        apt install -y curl unzip wget git build-essential
    elif command -v apk &> /dev/null; then
        echo -e "${GREEN}检测到 Alpine 系统，正在安装依赖...${NC}"
        apk add --no-cache curl unzip wget git build-base go
        # 设置 Go 环境变量
        export PATH=$PATH:/usr/lib/go/bin
        export GOPATH=/root/go
        export GOBIN=/usr/local/bin
    else
        echo -e "${RED}不支持的包管理器，请手动安装 curl, unzip, wget, git, build-essential/go${NC}"
        exit 1
    fi
}
install_deps

# 检测系统架构
detect_arch() {
    local arch=$(uname -m)
    case "$arch" in
        x86_64)  echo "amd64" ;;
        aarch64) echo "arm64" ;;
        arm64)   echo "arm64" ;;
        *)       echo "amd64" ;; # 默认尝试 amd64
    esac
}
ARCH_TAG=$(detect_arch)
echo -e "系统架构: ${YELLOW}$ARCH_TAG${NC}"

# 下载或编译 RealiTLScanner
setup_scanner() {
    mkdir -p "$TEMP_DIR"
    cd "$TEMP_DIR"
    
    # 先尝试下载预编译版本
    echo -e "${GREEN}[1/3] 尝试下载 RealiTLScanner...${NC}"
    # 使用已知稳定版本 v0.2.1 (因为 v0.2.3 没有 arm64 版本)
    LATEST_VERSION="v0.2.1"
    DOWNLOAD_URL="https://github.com/XTLS/RealiTLScanner/releases/download/${LATEST_VERSION}/RealiTLScanner_${LATEST_VERSION}_linux_${ARCH_TAG}.zip"
    
    if wget -O scanner.zip "$DOWNLOAD_URL" 2>/dev/null; then
        if unzip -o scanner.zip 2>/dev/null; then
            chmod +x RealiTLScanner
            echo -e "${GREEN}预编译版本下载成功。${NC}"
            return 0
        fi
    fi
    
    # 如果预编译失败或无法运行，尝试编译
    echo -e "${YELLOW}预编译版本不可用，尝试从源码编译...${NC}"
    echo -e "${GREEN}[2/3] 从源码编译 RealiTLScanner...${NC}"
    
    # 克隆仓库
    git clone https://github.com/XTLS/RealiTLScanner.git build_src
    cd build_src
    
    # 编译
    go mod tidy
    CGO_ENABLED=0 go build -o RealiTLScanner
    
    if [ -f "RealiTLScanner" ]; then
        cp RealiTLScanner "$TEMP_DIR/"
        cd "$TEMP_DIR"
        echo -e "${GREEN}源码编译成功。${NC}"
        return 0
    else
        echo -e "${RED}编译失败。${NC}"
        exit 1
    fi
}
setup_scanner

# 安装 cdncheck 工具 (用于后续过滤)
setup_cdncheck() {
    echo -e "${GREEN}[3/3] 安装 cdncheck 工具...${NC}"
    
    # 检查是否已安装
    if command -v cdncheck &> /dev/null; then
        echo -e "${GREEN}cdncheck 已安装。${NC}"
        return 0
    fi
    
    # 尝试使用 go 安装
    if command -v go &> /dev/null; then
        go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest
        # 将 go bin 目录加入 PATH
        export PATH=$PATH:$(go env GOPATH)/bin
        if command -v cdncheck &> /dev/null; then
            echo -e "${GREEN}cdncheck 安装成功。${NC}"
            return 0
        fi
    fi
    
    echo -e "${YELLOW}cdncheck 安装失败，将跳过 CDN 过滤步骤。${NC}"
}
setup_cdncheck

# 开始扫描
echo -e "${GREEN}开始扫描 (线程: $THREADS, 超时: ${TIMEOUT}s)...${NC}"
./RealiTLScanner -addr "$TARGET_IP" -port 443 -thread "$THREADS" -timeout "$TIMEOUT" -out "$OUTPUT_FILE"

# CDN 过滤（如果 cdncheck 可用）
if command -v cdncheck &> /dev/null && [ -f "$OUTPUT_FILE" ]; then
    echo -e "${GREEN}正在过滤套了 CDN 的域名...${NC}"
    > "$FILTERED_OUTPUT"  # 清空或创建文件
    tail -n +2 "$OUTPUT_FILE" | awk -F',' '{print $1}' | while read domain; do
        if [[ -n "$domain" ]]; then
            # 调用 cdncheck 判断，如果没有输出则表示非 CDN 域名
            if ! cdncheck -i "$domain" 2>/dev/null | grep -q '.'; then
                grep "^$domain," "$OUTPUT_FILE" >> "$FILTERED_OUTPUT"
            fi
        fi
    done
    RESULT_FILE="$FILTERED_OUTPUT"
else
    RESULT_FILE="$OUTPUT_FILE"
fi

# 输出结果
if [ -f "$RESULT_FILE" ]; then
    LINE_COUNT=$(wc -l < "$RESULT_FILE")
    if [ "$LINE_COUNT" -gt 1 ]; then
        echo ""
        echo -e "${GREEN}========================================${NC}"
        echo -e "${GREEN}       扫描结果（供您直观查看）${NC}"
        echo -e "${GREEN}========================================${NC}"
        echo -e "共找到 ${YELLOW}$((LINE_COUNT-1))${NC} 个可用域名"
        echo ""
        echo -e "${BLUE}域名                              | 延迟 | 证书详情${NC}"
        echo "----------------------------------|------|-----------------------------"
        tail -n +2 "$RESULT_FILE" | head -20 | awk -F',' '{printf "%-32s | %4s | %s\n", $1, $2, substr($3,1,40)}'
        if [ "$LINE_COUNT" -gt 21 ]; then
            echo "... 还有 $((LINE_COUNT-21)) 行未显示，请查看完整文件。"
        fi
        echo ""
        echo -e "完整结果已保存到: ${YELLOW}$(pwd)/$RESULT_FILE${NC}"
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
