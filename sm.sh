#!/bin/bash
# Reality Domain Scanner
# 扫描 VPS 所在 IP 段，寻找适合 Reality 协议的 dest 域名
# 要求：TLS 1.3 + H2 + X25519，无 CDN，证书匹配，非共享主机陷阱

set -euo pipefail

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 默认参数
THREADS=20
TIMEOUT=10
OUTPUT_DIR="./reality_scan_results"
LOG_FILE="$OUTPUT_DIR/scan_$(date +%Y%m%d_%H%M%S).log"
SUMMARY_FILE="$OUTPUT_DIR/summary_$(date +%Y%m%d_%H%M%S).txt"

# 依赖检查
check_deps() {
    local missing=()
    for cmd in openssl curl host; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done

    if ! command -v fping &>/dev/null && ! command -v nmap &>/dev/null; then
        echo -e "${YELLOW}警告: 未安装 fping 或 nmap，将使用 ping 逐个扫描（较慢）${NC}"
        echo "建议安装: apt install fping 或 apt install nmap"
    fi

    if [ ${#missing[@]} -ne 0 ]; then
        echo -e "${RED}缺少必要依赖: ${missing[*]}${NC}"
        echo "请安装: apt install openssl curl bind9-host"
        exit 1
    fi
}

# 获取本机公网 IP
get_public_ip() {
    local ip=""
    # 尝试多个 API
    for api in "https://api.ipify.org" "https://icanhazip.com" "https://ifconfig.me"; do
        ip=$(curl -s --max-time 5 "$api" 2>/dev/null || true)
        if [ -n "$ip" ] && [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$ip"
            return 0
        fi
    done
    return 1
}

# 解析网段
parse_subnet() {
    local subnet="$1"
    if [[ "$subnet" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/([0-9]+)$ ]]; then
        local a=${BASH_REMATCH[1]}
        local b=${BASH_REMATCH[2]}
        local c=${BASH_REMATCH[3]}
        local d=${BASH_REMATCH[4]}
        local mask=${BASH_REMATCH[5]}

        if [ "$mask" -eq 24 ]; then
            echo "$a.$b.$c"
        else
            echo -e "${RED}目前仅支持 /24 网段扫描${NC}"
            exit 1
        fi
    else
        echo -e "${RED}网段格式错误，应为 x.x.x.0/24${NC}"
        exit 1
    fi
}

# 扫描存活主机（443端口开放）
scan_alive_hosts() {
    local subnet_prefix="$1"
    local alive_file="$2"

    echo -e "${BLUE}[1/5] 扫描存活主机 (443端口)...${NC}"

    > "$alive_file"

    if command -v nmap &>/dev/null; then
        # 用 nmap 快速扫描
        nmap -Pn -p443 --open -T4 "${subnet_prefix}.0/24" 2>/dev/null |             grep "Nmap scan report for" |             awk '{print $5}' |             grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' > "$alive_file"
    elif command -v fping &>/dev/null; then
        # 用 fping 扫描，然后检查 443
        fping -a -g "${subnet_prefix}.0/24" 2>/dev/null | while read -r ip; do
            if timeout 3 bash -c "</dev/tcp/$ip/443" 2>/dev/null; then
                echo "$ip"
            fi
        done > "$alive_file"
    else
        # 用 bash 内置 /dev/tcp 扫描
        local pids=()
        for i in $(seq 1 254); do
            local ip="${subnet_prefix}.$i"
            (
                if timeout 3 bash -c "</dev/tcp/$ip/443" 2>/dev/null; then
                    echo "$ip" >> "$alive_file"
                fi
            ) &
            pids+=($!)
            if [ ${#pids[@]} -ge $THREADS ]; then
                wait "${pids[0]}"
                pids=("${pids[@]:1}")
            fi
        done
        wait
    fi

    local count=$(wc -l < "$alive_file" | tr -d ' ')
    echo -e "${GREEN}发现 $count 个开放 443 端口的主机${NC}"
}

# 反向 DNS 解析
reverse_dns() {
    local ip="$1"
    local result
    result=$(host "$ip" 2>/dev/null | grep "domain name pointer" | head -1 | awk '{print $NF}' | sed 's/\.$//')
    if [ -n "$result" ] && [[ "$result" =~ \. ]]; then
        echo "$result"
    fi
}

# 检查 TLS 1.3 + H2 + X25519
check_tls() {
    local domain="$1"
    local ip="$2"
    local tmpfile=$(mktemp)

    # 使用 openssl 检查
    echo | timeout $TIMEOUT openssl s_client         -connect "$ip:443"         -servername "$domain"         -alpn h2         -tls1_3         -brief 2>/dev/null > "$tmpfile" || true

    local output=$(cat "$tmpfile")
    rm -f "$tmpfile"

    local has_tls13="false"
    local has_h2="false"
    local has_x25519="false"

    if echo "$output" | grep -q "TLSv1.3"; then
        has_tls13="true"
    fi

    if echo "$output" | grep -q "ALPN protocol: h2"; then
        has_h2="true"
    fi

    if echo "$output" | grep -qi "X25519"; then
        has_x25519="true"
    fi

    echo "${has_tls13}|${has_h2}|${has_x25519}"
}

# 检查 CDN
check_cdn() {
    local domain="$1"
    local tmpfile=$(mktemp)

    # 获取响应头
    curl -sI --connect-timeout 5 --max-time 10         -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"         "https://$domain" 2>/dev/null > "$tmpfile" || true

    local headers=$(cat "$tmpfile" | tr '[:upper:]' '[:lower:]')
    rm -f "$tmpfile"

    local cdn_signs="cloudflare|akamai|fastly|bunnycdn|keycdn|stackpath|cdn77|azureedge|cloudfront|x-cache|via:.*varnish|cf-ray|server:.*cloudflare|server:.*awselb|server:.*gws|server:.*nginx.*cdn|server:.*apache.*cdn"

    if echo "$headers" | grep -qE "$cdn_signs"; then
        echo "true"
    else
        echo "false"
    fi
}

# 检查证书是否匹配域名
check_cert_match() {
    local domain="$1"
    local ip="$2"
    local tmpfile=$(mktemp)

    echo | timeout $TIMEOUT openssl s_client         -connect "$ip:443"         -servername "$domain"         -tls1_3 2>/dev/null |         openssl x509 -noout -subject 2>/dev/null > "$tmpfile" || true

    local subject=$(cat "$tmpfile")
    rm -f "$tmpfile"

    # 检查 CN 或 SAN 是否匹配
    if echo "$subject" | grep -qi "CN = $domain"; then
        echo "true"
    elif echo "$subject" | grep -qi "CN = \*.$domain"; then
        echo "true"
    else
        echo "false"
    fi
}

# 检查国内可访问性（可选）
check_china_accessible() {
    local domain="$1"
    # 使用国内 DNS 解析检查
    local china_ip=$(dig @$domain @114.114.114.114 +short 2>/dev/null | head -1)
    if [ -n "$china_ip" ] && [[ "$china_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "true"
    else
        echo "unknown"
    fi
}

# 检查是否为共享主机（一个IP多个证书）
check_shared_hosting() {
    local ip="$1"
    local domain="$2"
    local tmpfile=$(mktemp)

    # 不带 SNI 获取默认证书
    echo | timeout $TIMEOUT openssl s_client         -connect "$ip:443"         -tls1_3 2>/dev/null |         openssl x509 -noout -subject 2>/dev/null > "$tmpfile" || true

    local default_cert=$(cat "$tmpfile")
    rm -f "$tmpfile"

    # 带 SNI 获取证书
    local tmpfile2=$(mktemp)
    echo | timeout $TIMEOUT openssl s_client         -connect "$ip:443"         -servername "$domain"         -tls1_3 2>/dev/null |         openssl x509 -noout -subject 2>/dev/null > "$tmpfile2" || true

    local sni_cert=$(cat "$tmpfile2")
    rm -f "$tmpfile2"

    # 如果默认证书和 SNI 证书不同，说明可能是共享主机
    if [ -n "$default_cert" ] && [ -n "$sni_cert" ] && [ "$default_cert" != "$sni_cert" ]; then
        echo "shared"
    else
        echo "dedicated"
    fi
}

# 处理单个 IP
process_ip() {
    local ip="$1"
    local domain

    domain=$(reverse_dns "$ip")
    if [ -z "$domain" ]; then
        return
    fi

    echo -e "${BLUE}检查: $ip -> $domain${NC}" >> "$LOG_FILE"

    # 检查 TLS
    local tls_result=$(check_tls "$domain" "$ip")
    local has_tls13=$(echo "$tls_result" | cut -d'|' -f1)
    local has_h2=$(echo "$tls_result" | cut -d'|' -f2)
    local has_x25519=$(echo "$tls_result" | cut -d'|' -f3)

    if [ "$has_tls13" != "true" ] || [ "$has_h2" != "true" ] || [ "$has_x25519" != "true" ]; then
        echo -e "  ${RED}✗ 不满足 TLS 要求 (TLS1.3:$has_tls13 H2:$has_h2 X25519:$has_x25519)${NC}" >> "$LOG_FILE"
        return
    fi

    # 检查 CDN
    local has_cdn=$(check_cdn "$domain")
    if [ "$has_cdn" == "true" ]; then
        echo -e "  ${RED}✗ 检测到 CDN${NC}" >> "$LOG_FILE"
        return
    fi

    # 检查证书匹配
    local cert_match=$(check_cert_match "$domain" "$ip")
    if [ "$cert_match" != "true" ]; then
        echo -e "  ${RED}✗ 证书不匹配${NC}" >> "$LOG_FILE"
        return
    fi

    # 检查共享主机
    local shared=$(check_shared_hosting "$ip" "$domain")
    if [ "$shared" == "shared" ]; then
        echo -e "  ${YELLOW}⚠ 疑似共享主机${NC}" >> "$LOG_FILE"
        # 不直接排除，但标记
    fi

    # 通过所有检查
    echo -e "  ${GREEN}✓ 可用! (TLS1.3 H2 X25519 无CDN 证书匹配)${NC}" >> "$LOG_FILE"

    # 输出到结果
    echo "$domain|$ip|$shared" >> "$SUMMARY_FILE"
    echo -e "${GREEN}[✓] $domain ($ip) - 可用${NC}"
}

# 主函数
main() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}   Reality Domain Scanner${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""

    check_deps

    mkdir -p "$OUTPUT_DIR"

    local subnet=""

    # 获取网段
    if [ $# -eq 1 ]; then
        subnet="$1"
    else
        echo -e "${BLUE}正在获取本机公网 IP...${NC}"
        local my_ip=$(get_public_ip || true)
        if [ -n "$my_ip" ]; then
            echo -e "${GREEN}本机公网 IP: $my_ip${NC}"
            subnet="${my_ip%.*}.0/24"
            echo -e "${YELLOW}将扫描网段: $subnet${NC}"
            echo "如需扫描其他网段，请执行: $0 x.x.x.0/24"
        else
            echo -e "${RED}无法获取公网 IP，请手动指定网段: $0 x.x.x.0/24${NC}"
            exit 1
        fi
    fi

    local subnet_prefix=$(parse_subnet "$subnet")
    local alive_file="$OUTPUT_DIR/alive_hosts.txt"

    echo -e "${BLUE}扫描网段: $subnet${NC}"
    echo -e "${BLUE}结果保存至: $OUTPUT_DIR${NC}"
    echo ""

    # 扫描存活主机
    scan_alive_hosts "$subnet_prefix" "$alive_file"

    if [ ! -s "$alive_file" ]; then
        echo -e "${RED}未发现存活主机，扫描结束${NC}"
        exit 0
    fi

    # 处理每个存活主机
    echo -e "${BLUE}[2/5] 反向 DNS 解析...${NC}"
    echo -e "${BLUE}[3/5] 检查 TLS 1.3 + H2 + X25519...${NC}"
    echo -e "${BLUE}[4/5] 检查 CDN 和证书...${NC}"
    echo -e "${BLUE}[5/5] 生成结果...${NC}"
    echo ""

    > "$SUMMARY_FILE"
    echo "# Reality 可用域名列表" >> "$SUMMARY_FILE"
    echo "# 生成时间: $(date)" >> "$SUMMARY_FILE"
    echo "# 扫描网段: $subnet" >> "$SUMMARY_FILE"
    echo "# 格式: 域名|IP|共享主机状态" >> "$SUMMARY_FILE"
    echo "" >> "$SUMMARY_FILE"

    local total=$(wc -l < "$alive_file" | tr -d ' ')
    local current=0

    while read -r ip; do
        current=$((current + 1))
        echo -e "${BLUE}[$current/$total]${NC} 处理 $ip..."
        process_ip "$ip"
    done < "$alive_file"

    # 输出最终报告
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}扫描完成!${NC}"
    echo -e "${GREEN}========================================${NC}"

    if [ -s "$SUMMARY_FILE" ]; then
        local available=$(grep -c "^[^#]" "$SUMMARY_FILE" 2>/dev/null || echo "0")
        echo -e "${GREEN}发现 $available 个可用域名${NC}"
        echo ""
        echo -e "${YELLOW}可用域名列表:${NC}"
        grep "^[^#]" "$SUMMARY_FILE" | while IFS='|' read -r domain ip shared; do
            echo -e "  ${GREEN}✓ $domain${NC} (IP: $ip, 主机: $shared)"
        done
    else
        echo -e "${YELLOW}未发现满足条件的域名${NC}"
    fi

    echo ""
    echo -e "${BLUE}详细日志: $LOG_FILE${NC}"
    echo -e "${BLUE}结果文件: $SUMMARY_FILE${NC}"
    echo ""
    echo -e "${YELLOW}提示:${NC}"
    echo "  1. 建议从结果中选择 'dedicated'（独立主机）的域名"
    echo "  2. 使用前请手动验证域名内容是否正常（非蜜罐）"
    echo "  3. 建议准备 2-3 个备用域名，定期更换"
    echo "  4. 配置示例:"
    echo '     "dest": "域名:443",'
    echo '     "serverNames": ["域名", "www.域名"]'
}

main "$@"
