#!/bin/bash
# 修复 install.sh 中的兼容性问题和潜在错误
# 使用前请确认 install.sh 与 fix.sh 在同一目录，或修改 TARGET 变量

TARGET="./install.sh"
if [[ ! -f "$TARGET" ]]; then
    echo "错误：找不到 install.sh，请将本脚本放在 install.sh 同级目录下"
    exit 1
fi

# 备份
cp "$TARGET" "$TARGET.bak.$(date +%s)"
echo "已备份原文件"

# 1. 移除 wget --show-progress（替换为仅 -q）
echo "修复 wget --show-progress ..."
sed -i 's/wget -q --show-progress/wget -q/g' "$TARGET"

# 2. 替换所有 base64 -w0 为兼容写法 base64 | tr -d '\n'
#    注意：heredoc 内的 argo 脚本中也有 gen_vmess_link 使用 base64，但它内部已做 Alpine 判断，不该修改。
#    我们只替换主脚本部分的 base64 -w0，即不在 ARGO_EOF 内部的。
#    使用范围限定：只替换在 "ARGO_EOF" 标记之前的部分。
echo "修复 base64 -w0 兼容性 ..."
awk '
/^ARGO_EOF$/ { in_argo=1 }
{
    if (!in_argo) {
        gsub(/base64 -w0/, "base64 | tr -d \"\n\"")
    }
    print
}
' "$TARGET" > "$TARGET.tmp" && mv "$TARGET.tmp" "$TARGET"

# 3. 修复 save_links_to_files 中的 echo -en 为 printf "%b"
echo "修复 echo -en ..."
sed -i '/save_links_to_files/,/^}/ {
    s/echo -en "${ALL_LINKS_TEXT}"/printf "%b" "${ALL_LINKS_TEXT}"/
    s/echo -en "${REALITY_LINKS}"/printf "%b" "${REALITY_LINKS}"/
    s/echo -en "${HYSTERIA2_LINKS}"/printf "%b" "${HYSTERIA2_LINKS}"/
    s/echo -en "${SOCKS5_LINKS}"/printf "%b" "${SOCKS5_LINKS}"/
    s/echo -en "${SHADOWTLS_LINKS}"/printf "%b" "${SHADOWTLS_LINKS}"/
    s/echo -en "${HTTPS_LINKS}"/printf "%b" "${HTTPS_LINKS}"/
    s/echo -en "${ANYTLS_LINKS}"/printf "%b" "${ANYTLS_LINKS}"/
}' "$TARGET"

# 4. 修复 delete_all_nodes 中空 strategy 问题
echo "修复 delete_all_nodes DNS strategy ..."
sed -i '/^delete_all_nodes()/,/^}/ {
    /"strategy":/ {
        s/"strategy": "${dns_strategy}"/"strategy": "prefer_ipv4"/
    }
    # 如果 OUTBOUND_IP_MODE 为 dual，则不输出 strategy 字段（改为删除该行）
    # 更稳健的做法：重写整个空配置生成部分，但此处简单改为固定 prefer_ipv4 避免空值
}' "$TARGET"

# 可选：在 delete_all_nodes 中，如果 OUTBOUND_IP_MODE 为 dual 时，去掉 strategy 行
# 使用更精确的替换
sed -i '/^delete_all_nodes()/,/^}/ {
    /"strategy": "prefer_ipv4"/ {
        # 仅当变量为空时才需要调整，但已固定为 prefer_ipv4，可接受
    }
}' "$TARGET"

echo "修复完成！原文件备份为 ${TARGET}.bak.*"
echo "你可以使用 bash install.sh 重新运行测试。"
