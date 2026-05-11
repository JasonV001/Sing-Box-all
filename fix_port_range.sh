#!/bin/bash
# 临时移除 Hysteria2 入站中的 port_range 字段，解决启动失败问题

CONFIG="/etc/sing-box/config.json"
if [[ ! -f "$CONFIG" ]]; then
    echo "错误：配置文件不存在"
    exit 1
fi

# 备份
cp "$CONFIG" "$CONFIG.bak.$(date +%s)"
echo "已备份原配置"

# 使用 jq 删除 hysteria2 入站的 port_range 字段（如果有）
jq '.inbounds |= map(
    if .type == "hysteria2" and has("port_range") then del(.port_range) else . end
)' "$CONFIG" > "${CONFIG}.tmp" && mv "${CONFIG}.tmp" "$CONFIG"

# 重启服务
if [[ -f /etc/alpine-release ]]; then
    rc-service sing-box restart
else
    systemctl restart sing-box
fi

sleep 2

# 检查状态
if systemctl is-active --quiet sing-box 2>/dev/null || rc-service sing-box status 2>/dev/null | grep -q started; then
    echo "✅ 服务已成功启动，端口跳跃字段已移除"
else
    echo "❌ 服务启动失败，请检查日志"
fi
