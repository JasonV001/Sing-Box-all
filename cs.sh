cat > /root/jp2ln.sh << 'EOF'
#!/bin/bash
PORT=8080
SIZE=100

echo "🔧 正在准备测速环境..."
if ! command -v python3 &>/dev/null; then
    echo "❌ 未找到python3，请先安装: apt install python3 -y"
    exit 1
fi

# 放行防火墙（如有）
if command -v ufw &>/dev/null; then
    ufw allow $PORT/tcp >/dev/null 2>&1
elif command -v iptables &>/dev/null; then
    iptables -I INPUT -p tcp --dport $PORT -j ACCEPT >/dev/null 2>&1
fi

# 生成测试文件
echo "📦 正在生成 ${SIZE}MB 测试文件..."
dd if=/dev/zero of=/tmp/test.bin bs=1M count=$SIZE status=none

# 获取公网IP
IPV4=$(curl -s -4 ifconfig.me)
IPV6=$(curl -s -6 ifconfig.me 2>/dev/null)

echo "=================================================="
echo "✅ 测速服务已启动！"
echo ""
[ -n "$IPV4" ] && echo "👉 IPv4 测速链接：http://$IPV4:$PORT/test.bin"
[ -n "$IPV6" ] && echo "👉 IPv6 测速链接：http://[$IPV6]:$PORT/test.bin"
echo ""
echo "📌 请在本地浏览器打开上述链接，查看下载速度（单位 MB/s）"
echo "📌 分别测试IPv4和IPv6，对比哪个更快"
echo "📌 按 Ctrl+C 停止服务并自动清理文件"
echo "=================================================="

cd /tmp
python3 -m http.server $PORT
rm -f /tmp/test.bin
EOF

chmod +x /root/jp2ln.sh