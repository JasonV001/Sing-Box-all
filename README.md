## 🚀 一键安装

```
wget -O /root/install.sh https://raw.githubusercontent.com/JasonV001/Sing-Box-all/main/install.sh && bash /root/install.sh
```
```
当前出入站配置:
  IPv4 地址: 78.129.249.191
  IPv6 地址: 2001:1b40:5000:1a:cafe:babe:0:1d
  └─ 入站模式: ipv4     出站模式: ipv4

  当前出站: 混合 (直连:3 中转:1 [SOCKS5:1])
  中转列表: 1 个 [SOCKS5:1]
    └─ 使用中转: Reality:28116
  当前节点数: 4
    └─ Reality:2 HTTPS:1 AnyTLS:1 

  [1] 添加/继续添加节点

  [2] 中转配置 (添加/配置/删除)

  [3] 出入站配置 (IPv4/IPv6)

  [4] 配置 / 查看节点

  [5] 重新生成链接文件

  [6] 一键删除脚本并退出

  [0] 退出脚本

请选择 [0-6]:
```

## ✨ 支持协议

| 协议 | 特点 | 推荐度 |
|------|------|--------|
| **Reality** | 抗审查最强，无需证书 | ⭐⭐⭐⭐⭐ |
| **Hysteria2** | 基于QUIC，速度快 | ⭐⭐⭐⭐ |
| **ShadowTLS v3** | TLS伪装，无需证书 | ⭐⭐⭐⭐ |
| **HTTPS** | 标准HTTPS，可过CDN | ⭐⭐⭐ |
| **SOCKS5** | 通用兼容 | ⭐⭐⭐ |
| **AnyTLS** | 通用TLS | ⭐⭐⭐ |

```
查看状态: systemctl status sing-box
查看日志: journalctl -u sing-box -f
重启服务: systemctl restart sing-box
停止服务: systemctl stop sing-box
```
