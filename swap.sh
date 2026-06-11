#!/bin/sh
#===============================================================================
# swap.sh - Alpine Linux 兼容版
# 自动判断、交互式创建 Swap，支持卸载恢复原样
# 用法: sudo sh swap.sh          (创建)
#       sudo sh swap.sh remove   (卸载，仅移除脚本创建的 Swap)
#===============================================================================

set -eu

# 颜色 (BusyBox echo 支持 -e)
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

# 记录文件，用于卸载时识别哪些文件是本脚本创建的
RECORD_FILE="/etc/swap_script_files"

# ------------------------------ 函数定义 ------------------------------
die() { echo -e "${RED}[错误]${NC} $1" >&2; exit 1; }
info() { echo -e "${GREEN}[信息]${NC} $1"; }
warn() { echo -e "${YELLOW}[警告]${NC} $1"; }

# 虚拟化检测（无 systemd 兼容）
check_virt() {
    if [ -f /proc/1/cgroup ] && grep -qE 'lxc|openvz' /proc/1/cgroup 2>/dev/null; then
        die "检测到容器环境 (LXC/OpenVZ)，无法创建 Swap。"
    fi
    if [ -f /proc/1/environ ] && grep -q 'container=' /proc/1/environ 2>/dev/null; then
        die "检测到容器环境 (Docker/LXC)，无法创建 Swap。"
    fi
    info "虚拟化环境通过。"
}

# 获取当前所有激活的 swap（读取 /proc/swaps，跳过标题行）
get_swaps() {
    awk 'NR>1 {print $1}' /proc/swaps 2>/dev/null || true
}

# 检查 swap 是否已激活（用于查找空闲文件名）
is_swap_active() {
    local f="$1"
    get_swaps | grep -qxF "$f"
}

# 计算推荐 Swap (MB)
get_recommend_mb() {
    mem_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    mem_mb=$((mem_kb / 1024))
    if [ "$mem_mb" -le 1024 ]; then
        echo "$mem_mb"
    elif [ "$mem_mb" -le 2048 ]; then
        echo $((mem_mb * 3 / 2))
    elif [ "$mem_mb" -le 4096 ]; then
        echo "$mem_mb"
    else
        echo 4096
    fi
}

# 寻找可用文件名 (不覆盖)
find_free_swapfile() {
    base="/swapfile"
    path="$base"
    count=1
    while [ -e "$path" ] || is_swap_active "$path"; do
        path="${base}${count}"
        count=$((count + 1))
        [ $count -gt 100 ] && die "找不到可用文件名，请手动清理。"
    done
    echo "$path"
}

# 安全添加至 fstab（避免重复）
add_to_fstab() {
    file="$1"
    # 转义 file 中的斜杠，用于 grep 精确匹配行首
    escaped=$(printf "%s\n" "$file" | sed 's:/:\\/:g')
    if ! grep -q "^$escaped " /etc/fstab 2>/dev/null; then
        echo "$file none swap sw 0 0" >> /etc/fstab
        info "已添加 $file 到 /etc/fstab"
    else
        warn "$file 在 fstab 中已存在，跳过添加。"
    fi
}

# 从 fstab 中移除某行（卸载时用）
remove_from_fstab() {
    file="$1"
    escaped=$(printf "%s\n" "$file" | sed 's:/:\\/:g')
    # BusyBox sed 支持 -i 但需要备份后缀，这里直接写临时文件
    if grep -q "^$escaped " /etc/fstab 2>/dev/null; then
        sed -i "/^$escaped /d" /etc/fstab 2>/dev/null || {
            # 备用方案：重写文件
            grep -v "^$escaped " /etc/fstab > /etc/fstab.tmp
            mv /etc/fstab.tmp /etc/fstab
        }
        info "已从 fstab 移除 $file"
    fi
}

# 调整 swappiness（交互）
ask_swappiness() {
    echo ""
    echo "建议设置 vm.swappiness = 10，减少 Swap 滥用。"
    echo "直接回车使用 10，输入 0-100 自定义，输入 n 跳过："
    read val
    val="${val:-10}"
    if [ "$val" = "n" ] || [ "$val" = "N" ]; then
        info "跳过 swappiness 设置。"
        return
    fi
    if ! echo "$val" | grep -qE '^[0-9]+$' || [ "$val" -gt 100 ] || [ "$val" -lt 0 ]; then
        warn "无效输入，跳过。"
        return
    fi
    # 临时设置
    sysctl vm.swappiness="$val" 2>/dev/null || warn "临时设置失败"
    # 永久设置
    if grep -q "^vm.swappiness" /etc/sysctl.conf 2>/dev/null; then
        sed -i "s/^vm.swappiness.*/vm.swappiness = $val/" /etc/sysctl.conf
    else
        echo "vm.swappiness = $val" >> /etc/sysctl.conf
    fi
    info "swappiness 永久设置为 $val"
}

# ------------------------------ 卸载模块 ------------------------------
remove_created_swaps() {
    if [ ! -f "$RECORD_FILE" ]; then
        info "未找到脚本创建的 Swap 记录，无需卸载。"
        exit 0
    fi

    echo -e "${YELLOW}将移除以下由本脚本创建的 Swap 文件：${NC}"
    cat -n "$RECORD_FILE"
    echo ""
    printf "确认卸载并删除这些文件？[y/N] "
    read ans
    if ! echo "$ans" | grep -qiE '^y'; then
        info "已取消。"
        exit 0
    fi

    while IFS= read -r file; do
        if [ -e "$file" ]; then
            # 停用 swap
            swapoff "$file" 2>/dev/null || warn "无法停用 $file"
            rm -f "$file" && info "已移除: $file"
        else
            warn "文件不存在，跳过: $file"
        fi
        # 从 fstab 中移除
        remove_from_fstab "$file"
    done < "$RECORD_FILE"

    rm -f "$RECORD_FILE"
    info "卸载完成，所有脚本创建的 Swap 已清理。"
    exit 0
}

# ------------------------------ 主程序 ------------------------------
# 入口判断：卸载模式
if [ "${1:-}" = "remove" ] || [ "${1:-}" = "uninstall" ]; then
    if [ "$(id -u)" -ne 0 ]; then
        die "卸载需要 root 权限。"
    fi
    remove_created_swaps
fi

# 正常运行创建流程
if [ "$(id -u)" -ne 0 ]; then
    die "请使用 root 运行。"
fi
check_virt

# 显示当前状况
echo "============================================="
echo "   当前内存 / Swap 状况"
echo "============================================="
free -h | grep -E 'Mem|Swap'
echo ""

# 已有 Swap 提醒（但不阻止）
if get_swaps | grep -q .; then
    warn "系统已存在 Swap，新文件将追加。"
fi

# 推荐值
RECOMMEND=$(get_recommend_mb)
echo "物理内存大致为 $(free -h | awk '/Mem:/ {print $2}')"
echo "推荐 Swap 大小: ${RECOMMEND} MB"
printf "请输入要创建的 Swap 大小 (MB) [直接回车使用推荐值]: "
read CUSTOM
SWAP_MB="${CUSTOM:-$RECOMMEND}"
if ! echo "$SWAP_MB" | grep -qE '^[0-9]+$' || [ "$SWAP_MB" -le 0 ]; then
    die "输入无效，必须是正整数。"
fi

# 磁盘空间检查
AVAIL_MB=$(df -m / | awk 'NR==2 {print $4}')
if [ "$AVAIL_MB" -lt "$SWAP_MB" ]; then
    die "磁盘空间不足！需要 ${SWAP_MB}MB，/ 仅剩 ${AVAIL_MB}MB。"
fi

# 自动获取文件名
SWAPFILE=$(find_free_swapfile)
info "将使用文件: $SWAPFILE 创建 ${SWAP_MB}MB Swap"
printf "确认继续？[Y/n] "
read CONFIRM
if ! echo "$CONFIRM" | grep -qiE '^(y|)$'; then
    info "已取消。"
    exit 0
fi

# 创建 swap 文件（去掉 status=progress）
info "正在创建，请稍候..."
dd if=/dev/zero of="$SWAPFILE" bs=1M count="$SWAP_MB" 2>/dev/null || {
    # 如果 dd 缺少 status，忽略错误；若真正失败则中止
    if [ $? -ne 0 ]; then
        die "dd 创建文件失败。"
    fi
}
# 确保 dd 输出错误时也会结束
if [ ! -f "$SWAPFILE" ]; then
    die "文件创建失败。"
fi

chmod 600 "$SWAPFILE"
mkswap "$SWAPFILE"
swapon "$SWAPFILE"

# 记录到文件（用于卸载）
echo "$SWAPFILE" >> "$RECORD_FILE"

# fstab
add_to_fstab "$SWAPFILE"

# 结果
info "Swap 创建成功。当前内存状况："
free -h

# swappiness
ask_swappiness

echo ""
echo "============================================="
echo "   全部完成！"
echo "============================================="
    echo -e "${YELLOW}将移除以下由本脚本创建的 Swap 文件：${NC}"
    cat -n "$RECORD_FILE"
    echo ""
    echo -n "确认卸载并删除这些文件？[y/N] "
    read -r ans
    if [[ ! "$ans" =~ ^[Yy]$ ]]; then
        info "已取消。"
        exit 0
    fi

    while IFS= read -r file; do
        if [ -e "$file" ]; then
            swapoff "$file" 2>/dev/null || true
            rm -f "$file" && info "已移除: $file"
        else
            warn "文件不存在，跳过: $file"
        fi
        # 从 fstab 中移除相应行（安全匹配）
        sed -i "\|^$file |d" /etc/fstab 2>/dev/null || true
    done < "$RECORD_FILE"

    rm -f "$RECORD_FILE"
    info "卸载完成，所有脚本创建的 Swap 已清理。"
    exit 0
}

# ------------------------------ 主程序 ------------------------------
# 入口判断
if [ "${1:-}" = "remove" ] || [ "${1:-}" = "uninstall" ]; then
    [ "$(id -u)" -ne 0 ] && die "卸载需要 root 权限。"
    remove_created_swaps
fi

# 正常运行创建流程
[ "$(id -u)" -ne 0 ] && die "请使用 root 运行。"
check_virt

# 显示当前状况
echo "============================================="
echo "   当前内存 / Swap 状况"
echo "============================================="
free -h | grep -E 'Mem|Swap'
echo ""

# 已有 Swap 提醒，但不阻止
if swapon --show | grep -q 'swap'; then
    warn "系统已存在 Swap，新文件将追加。"
fi

# 推荐值
RECOMMEND=$(get_recommend_mb)
echo "物理内存大致为 $(free -h | awk '/Mem:/ {print $2}')"
echo "推荐 Swap 大小: ${RECOMMEND} MB"
echo -n "请输入要创建的 Swap 大小 (MB) [直接回车使用推荐值]: "
read -r CUSTOM
SWAP_MB="${CUSTOM:-$RECOMMEND}"
if ! [[ "$SWAP_MB" =~ ^[0-9]+$ ]] || [ "$SWAP_MB" -le 0 ]; then
    die "输入无效，必须是正整数。"
fi

# 磁盘空间检查
AVAIL_MB=$(df -m / | awk 'NR==2 {print $4}')
[ "$AVAIL_MB" -lt "$SWAP_MB" ] && die "磁盘空间不足！需要 ${SWAP_MB}MB，/ 仅剩 ${AVAIL_MB}MB。"

# 自动获取文件名
SWAPFILE=$(find_free_swapfile)
info "将使用文件: $SWAPFILE 创建 ${SWAP_MB}MB Swap"
echo -n "确认继续？[Y/n] "
read -r CONFIRM
if [[ ! "$CONFIRM" =~ ^([Yy]|"")$ ]]; then
    info "已取消。"
    exit 0
fi

# 创建
info "正在创建 ..."
dd if=/dev/zero of="$SWAPFILE" bs=1M count="$SWAP_MB" status=progress
chmod 600 "$SWAPFILE"
mkswap "$SWAPFILE"
swapon "$SWAPFILE"

# 记录到文件（用于卸载）
echo "$SWAPFILE" >> "$RECORD_FILE"

# fstab
add_to_fstab "$SWAPFILE"

# 结果
info "Swap 创建成功。当前内存状况："
free -h

# swappiness
ask_swappiness

echo ""
echo "============================================="
echo "   全部完成！"
echo "============================================="
