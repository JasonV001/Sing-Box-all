#!/bin/bash
# 自动为 sing-box install.sh 添加双栈入站支持
# 目标文件：同目录下的 install.sh（或修改 TARGET 变量）

TARGET="./install.sh"
if [[ ! -f "$TARGET" ]]; then
    echo "错误：找不到 $TARGET，请将本脚本放在 install.sh 旁边"
    exit 1
fi

cp "$TARGET" "$TARGET.bak"

echo "1/5 添加 check_ipv6_bindv6only 函数..."
sed -i '/^detect_system()/,/^}$/!b; /^}$/a\
\
# 检查系统是否支持双栈入站\
check_ipv6_bindv6only() {\
    local val\
    val=$(sysctl -n net.ipv6.bindv6only 2>/dev/null)\
    [[ "$val" == "0" ]] && return 0 || return 1\
}' "$TARGET"

echo "2/5 在 get_ip() 末尾插入自动双栈检测..."
sed -i '/^get_ip()/,/^}$/{
/^}$/i\
    # 自动设置入站双栈模式\
    if [[ -z "$INBOUND_IP_MODE" ]]; then\
        if check_ipv6_bindv6only; then\
            INBOUND_IP_MODE="dual"\
            print_info "检测到 bindv6only=0，入站自动设为双栈模式"\
        else\
            if [[ -n "$SERVER_IP" ]]; then\
                INBOUND_IP_MODE="ipv4"\
            elif [[ -n "$SERVER_IPV6" ]]; then\
                INBOUND_IP_MODE="ipv6"\
            else\
                INBOUND_IP_MODE="ipv4"\
            fi\
        fi\
        save_ip_config\
    fi
}' "$TARGET"

echo "3/5 替换 ip_config_menu 函数..."
# 用新的完整函数替换旧的 ip_config_menu（多行替换使用 Python 或 perl 更可靠）
# 这里用 python3 实现
python3 << 'PYEOF'
import re

with open("install.sh", "r") as f:
    content = f.read()

new_function = r'''# ==================== 出入站 IP 配置菜单 ====================
ip_config_menu() {
    while true; do
        clear
        echo -e "${CYAN}╔═══════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║              ${GREEN}出入站 IP 配置${CYAN}                ║${NC}"
        echo -e "${CYAN}╚═══════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "${YELLOW}当前配置:${NC}"
        echo -e "  IPv4 地址: ${GREEN}${SERVER_IP}${NC}"
        [[ -n "$SERVER_IPV6" ]] && echo -e "  IPv6 地址: ${GREEN}${SERVER_IPV6}${NC}"
        echo -e "  入站模式: ${GREEN}${INBOUND_IP_MODE}${NC}"
        echo -e "  出站模式: ${GREEN}${OUTBOUND_IP_MODE}${NC}"

        if check_ipv6_bindv6only; then
            echo -e "${CYAN}  ✓ 系统支持双栈入站 (bindv6only=0)${NC}"
        else
            echo -e "${YELLOW}  ✗ 系统仅 IPv6 入站 (bindv6only=1)${NC}"
        fi
        echo ""
        echo -e "${CYAN}说明:${NC}"
        echo -e "  ${YELLOW}入站${NC}: 控制节点监听的 IP 版本（客户端连接到哪个 IP）"
        echo -e "  ${YELLOW}出站${NC}: 控制服务器对外连接的 IP 版本（访问网站用哪个 IP）"
        echo ""
        echo -e "  ${GREEN}[1]${NC} 设置入站为 IPv4"
        echo -e "  ${GREEN}[2]${NC} 设置入站为 IPv6"
        echo -e "  ${GREEN}[3]${NC} 设置入站为双栈 (自动，推荐)"
        echo -e "  ${GREEN}[4]${NC} 设置出站为 IPv4"
        echo -e "  ${GREEN}[5]${NC} 设置出站为 IPv6"
        echo -e "  ${GREEN}[6]${NC} 设置出站为双栈 (IPv4+IPv6)"
        echo -e "  ${GREEN}[7]${NC} 手动修改 IPv4 地址"
        echo -e "  ${GREEN}[8]${NC} 手动修改 IPv6 地址"
        echo -e "  ${GREEN}[0]${NC} 返回主菜单"
        echo ""
        read -p "请选择 [0-8]: " ip_choice
        
        case $ip_choice in
            1)
                INBOUND_IP_MODE="ipv4"
                save_ip_config
                print_success "入站已设置为 IPv4"
                echo -e "${YELLOW}提示: 需要重新生成配置才能生效${NC}"
                read -p "是否立即重新生成配置? (y/N): " regen
                if [[ "$regen" =~ ^[Yy]$ ]] && [[ -n "$INBOUNDS_JSON" ]]; then
                    generate_config && start_svc
                fi
                ;;
            2)
                if [[ -z "$SERVER_IPV6" ]]; then
                    print_error "未检测到 IPv6 地址，请先手动设置"
                    read -p "按回车继续..." _
                    continue
                fi
                INBOUND_IP_MODE="ipv6"
                save_ip_config
                print_success "入站已设置为 IPv6"
                echo -e "${YELLOW}提示: 需要重新生成配置才能生效${NC}"
                read -p "是否立即重新生成配置? (y/N): " regen
                if [[ "$regen" =~ ^[Yy]$ ]] && [[ -n "$INBOUNDS_JSON" ]]; then
                    generate_config && start_svc
                fi
                ;;
            3)
                if check_ipv6_bindv6only; then
                    INBOUND_IP_MODE="dual"
                    save_ip_config
                    print_success "入站已设置为双栈模式（监听 :: 同时接受 IPv4/IPv6）"
                else
                    print_error "当前系统 bindv6only=1，不支持双栈入站，请先执行 sysctl -w net.ipv6.bindv6only=0"
                    read -p "按回车继续..." _
                    continue
                fi
                echo -e "${YELLOW}提示: 需要重新生成配置才能生效${NC}"
                read -p "是否立即重新生成配置? (y/N): " regen
                if [[ "$regen" =~ ^[Yy]$ ]] && [[ -n "$INBOUNDS_JSON" ]]; then
                    generate_config && start_svc
                fi
                ;;
            4)
                OUTBOUND_IP_MODE="ipv4"
                save_ip_config
                print_success "出站已设置为 IPv4"
                echo -e "${YELLOW}提示: 需要重新生成配置才能生效${NC}"
                read -p "是否立即重新生成配置? (y/N): " regen
                if [[ "$regen" =~ ^[Yy]$ ]] && [[ -n "$INBOUNDS_JSON" ]]; then
                    generate_config && start_svc
                fi
                ;;
            5)
                if [[ -z "$SERVER_IPV6" ]]; then
                    print_error "未检测到 IPv6 地址，请先手动设置"
                    read -p "按回车继续..." _
                    continue
                fi
                OUTBOUND_IP_MODE="ipv6"
                save_ip_config
                print_success "出站已设置为 IPv6"
                echo -e "${YELLOW}提示: 需要重新生成配置才能生效${NC}"
                read -p "是否立即重新生成配置? (y/N): " regen
                if [[ "$regen" =~ ^[Yy]$ ]] && [[ -n "$INBOUNDS_JSON" ]]; then
                    generate_config && start_svc
                fi
                ;;
            6)
                OUTBOUND_IP_MODE="dual"
                save_ip_config
                print_success "出站已设置为双栈 (IPv4+IPv6)"
                echo -e "${YELLOW}提示: 双栈模式将同时使用 IPv4 和 IPv6，由系统自动选择${NC}"
                echo -e "${YELLOW}提示: 需要重新生成配置才能生效${NC}"
                read -p "是否立即重新生成配置? (y/N): " regen
                if [[ "$regen" =~ ^[Yy]$ ]] && [[ -n "$INBOUNDS_JSON" ]]; then
                    generate_config && start_svc
                fi
                ;;
            7)
                read -p "请输入 IPv4 地址: " new_ipv4
                if [[ -n "$new_ipv4" ]]; then
                    SERVER_IP="$new_ipv4"
                    save_ip_config
                    print_success "IPv4 地址已更新: ${SERVER_IP}"
                    echo -e "${YELLOW}提示: 需要重新生成链接文件${NC}"
                fi
                ;;
            8)
                read -p "请输入 IPv6 地址: " new_ipv6
                if [[ -n "$new_ipv6" ]]; then
                    SERVER_IPV6="$new_ipv6"
                    save_ip_config
                    print_success "IPv6 地址已更新: ${SERVER_IPV6}"
                    echo -e "${YELLOW}提示: 需要重新生成链接文件${NC}"
                fi
                ;;
            0)
                break
                ;;
            *)
                print_error "无效选项"
                ;;
        esac
        
        [[ "$ip_choice" != "0" ]] && read -p "按回车继续..." _
    done
}'''

# 匹配原有 ip_config_menu 函数（从函数定义开始到下一个函数或文件结束）
pattern = r'^ip_config_menu\(\)\s*\{.*?\n^(\}|$)'
matches = list(re.finditer(pattern, content, re.MULTILINE | re.DOTALL))
if not matches:
    print("未找到 ip_config_menu 函数")
    exit(1)

content = content[:matches[0].start()] + new_function + content[matches[0].end():]

with open("install.sh", "w") as f:
    f.write(content)
print("ip_config_menu 已替换")
PYEOF

echo "4/5 为所有 setup 函数添加动态监听地址..."
# 在每个 setup_reality/setup_hysteria2/setup_socks5/setup_shadowtls/setup_https/setup_anytls
# 函数体中的 print_info "生成配置文件..." 前面插入 case 块，并将 "listen": "::" 改为 "${LISTEN_ADDR}"
for func in setup_reality setup_hysteria2 setup_socks5 setup_shadowtls setup_https setup_anytls; do
    # 插入 LISTEN_ADDR 定义（在 print_info "生成配置文件..." 之前）
    sed -i "/^${func}()/,/^}$/{
        /print_info \"生成配置文件...\"/i\
    case "\${INBOUND_IP_MODE}" in\
        ipv4) LISTEN_ADDR="0.0.0.0" ;;\
        ipv6) LISTEN_ADDR="::" ;;\
        dual) LISTEN_ADDR="::" ;;\
        *)    LISTEN_ADDR="::" ;;\
    esac
}" "$TARGET"

    # 将 "listen": "::" 替换为 "listen": "${LISTEN_ADDR}" （但不影响 "127.0.0.1" 等）
    sed -i "/^${func}()/,/^}$/{
        s/\"listen\": \"::\"/\"listen\": \"\${LISTEN_ADDR}\"/g
    }" "$TARGET"
done

echo "5/5 清理临时文件..."
echo "补丁执行完毕！原文件备份为 ${TARGET}.bak"
