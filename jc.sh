#!/bin/bash
# REALITY 扫描器一键诊断脚本
echo "===== REALITY 扫描器诊断 ====="

# 1. 检查网络连通性
echo "1. 检查网络连通性和 DNS 解析..."
ping -c 2 google.com >/dev/null 2>&1 && echo "✅ 外网连通" || echo "❌ 网络不通，请检查网络配置"
nslookup github.com >/dev/null 2>&1 && echo "✅ DNS 解析正常" || echo "❌ DNS 解析失败，请检查 /etc/resolv.conf"

# 2. 检查并安装必要工具
echo "2. 检查必要工具..."
for cmd in curl wget unzip; do
    command -v $cmd >/dev/null 2>&1 && echo "✅ $cmd 已安装" || { echo "❌ $cmd 未安装，正在安装..."; command -v apt >/dev/null 2>&1 && apt-get install -y $cmd; command -v apk >/dev/null 2>&1 && apk add $cmd --no-cache; }
done

# 3. 检查端口连通性
echo "3. 检查端口连通性..."
timeout 2 bash -c "echo >/dev/tcp/github.com/443" 2>/dev/null && echo "✅ 443端口可通" || echo "⚠️ 443端口可能被屏蔽"

# 4. 尝试直接下载扫描器
echo "4. 尝试直接下载 RealiTLScanner..."
ARCH=$(uname -m)
case "$ARCH" in
    x86_64) arch="amd64";;
    aarch64) arch="arm64";;
    *) arch="amd64";;
esac
URL="https://github.com/XTLS/RealiTLScanner/releases/download/v0.2.1/RealiTLScanner_v0.2.1_linux_${arch}.zip"
echo "下载地址: $URL"
wget -q -O /tmp/test_download.zip "$URL" && echo "✅ 下载成功" || echo "❌ 下载失败，请检查网络或尝试手动下载"

echo "===== 诊断完成 ====="
