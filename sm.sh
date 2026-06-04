#!/bin/sh
# =====================================================
# REALITY 域名扫描器 - 兼容 Debian / Alpine
# 使用方法: sh scan.sh
# =====================================================

set -e

# 颜色（简单判断终端是否支持）
if [ -t 1 ]; then
    RED=$(printf '\033[0;31m')
    GREEN=$(printf '\033[0;32m')
    YELLOW=$(printf '\033[1;33m')
    NC=$(printf '\033[0m')
else
    RED=''; GREEN=''; YELLOW=''; NC=''
fi

echo "${GREEN}========================================${NC}"
echo "${GREEN}     REALITY 域名扫描器${NC}"
echo "${GREEN}========================================${NC}"

# 1. 获取目标 IP
echo "请选择运行模式："
echo "  1) 自动检测本机公网 IP"
echo "  2) 手动输入目标 IP"
printf "请输入 [1/2]: "
read mode

if [ "$mode" = "1" ]; then
    echo "正在自动检测本机公网 IP..."
    TARGET_IP=$(curl -s -4 ifconfig.me 2>/dev/null || curl -s -4 ipinfo.io/ip)
    if [ -z "$TARGET_IP" ]; then
        echo "${RED}错误：无法自动获取 IP，请检查网络${NC}"
        exit 1
    fi
    echo "检测到 IP: ${YELLOW}$TARGET_IP${NC}"
else
    printf "请输入目标 VPS IP 地址: "
    read TARGET_IP
    if [ -z "$TARGET_IP" ]; then
        echo "${RED}IP 不能为空${NC}"
        exit 1
    fi
fi

# 2. 安装依赖（curl, unzip, wget）
if command -v apk >/dev/null 2>&1; then
    echo "检测到 Alpine Linux，安装依赖..."
    apk update
    apk add --no-cache curl unzip wget
elif command -v apt >/dev/null 2>&1; then
    echo "检测到 Debian/Ubuntu，安装依赖..."
    apt update -y
    apt install -y curl unzip wget
else
    echo "${YELLOW}警告：未检测到 apk 或 apt，请确保已安装 curl, unzip, wget${NC}"
fi

# 3. 创建工作目录
WORKDIR="/tmp/reality_scan_$$"
mkdir -p "$WORKDIR"
cd "$WORKDIR"
echo "工作目录: $WORKDIR"

# 4. 确定系统架构
ARCH=$(uname -m)
case "$ARCH" in
    aarch64|arm64)
        FILE_ARCH="arm64"
        ;;
    x86_64|amd64)
        FILE_ARCH="amd64"
        ;;
    *)
        echo "${YELLOW}未知架构 $ARCH，尝试使用 amd64${NC}"
        FILE_ARCH="amd64"
        ;;
esac
echo "系统架构: $FILE_ARCH"

# 5. 下载 RealiTLScanner (使用稳定版 v0.2.1，支持 arm64)
URL="https://github.com/XTLS/RealiTLScanner/releases/download/v0.2.1/RealiTLScanner_v0.2.1_linux_${FILE_ARCH}.zip"
echo "下载地址: $URL"

for i in 1 2 3; do
    if wget -O scanner.zip "$URL" 2>/dev/null; then
        echo "下载成功"
        break
    else
        echo "下载失败，重试 $i/3"
        sleep 2
    fi
done

if [ ! -f scanner.zip ]; then
    echo "${RED}下载失败，请手动下载 $URL 并解压到 $WORKDIR${NC}"
    exit 1
fi

# 6. 解压
unzip -o scanner.zip >/dev/null 2>&1
chmod +x RealiTLScanner
if [ ! -x ./RealiTLScanner ]; then
    echo "${RED}解压或设置权限失败${NC}"
    exit 1
fi

# 7. 扫描
echo "${GREEN}开始扫描目标 $TARGET_IP ...${NC}"
./RealiTLScanner -addr "$TARGET_IP" -port 443 -thread 100 -timeout 5 -out result.csv

# 8. 输出结果
if [ -f result.csv ]; then
    LINE_COUNT=$(wc -l < result.csv)
    if [ "$LINE_COUNT" -gt 1 ]; then
        echo ""
        echo "${GREEN}========================================${NC}"
        echo "${GREEN}           扫描结果${NC}"
        echo "${GREEN}========================================${NC}"
        echo "共找到 $((LINE_COUNT - 1)) 个域名"
        echo ""
        # 显示前 20 行（首行是标题）
        head -n 21 result.csv | while IFS= read -r line; do
            echo "$line"
        done
        echo ""
        echo "完整结果保存在: ${YELLOW}$WORKDIR/result.csv${NC}"
        echo "你可以使用 cat 或 scp 查看完整文件。"
    else
        echo "${RED}未找到任何可用域名，请尝试其他 VPS IP 或调整参数。${NC}"
    fi
else
    echo "${RED}扫描失败，未生成 result.csv${NC}"
    exit 1
fi

echo "${GREEN}========================================${NC}"
echo "${GREEN}  扫描完成${NC}"
echo "${GREEN}========================================${NC}"}
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
