#!/bin/bash
#===============================================================================
# 脚本: setup_swap.sh
# 用途: 在 KVM/Xen/VMware 等全虚拟化 VPS 上交互式创建 Swap 文件
# 要求: root 权限
#===============================================================================

set -euo pipefail

# ------------------------------ 颜色定义 ------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# ------------------------------ 函数定义 ------------------------------

# 输出错误信息并退出
die() {
    echo -e "${RED}[错误]${NC} $1" >&2
    exit 1
}

# 输出提示
info() {
    echo -e "${GREEN}[信息]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[警告]${NC} $1"
}

# 检测虚拟化环境是否支持 Swap 文件
check_virt_support() {
    # 优先使用 systemd-detect-virt
    if command -v systemd-detect-virt &>/dev/null; then
        VIRT=$(systemd-detect-virt 2>/dev/null || true)
        case "$VIRT" in
            openvz|lxc|lxc-libvirt)
                die "检测到容器虚拟化: $VIRT，无法自行创建 Swap 文件。"
                ;;
        esac
        info "虚拟化类型: $VIRT (支持 Swap 文件)"
        return
    fi

    # 备用检测：检查 /proc/1/cgroup
    if grep -E 'lxc|openvz' /proc/1/cgroup &>/dev/null 2>&1; then
        die "检测到容器环境 (OpenVZ/LXC)，不支持创建 Swap 文件。"
    fi

    # 再检查 /proc/1/environ 中的 container 变量
    if grep -q 'container=' /proc/1/environ 2>/dev/null; then
        die "检测到容器环境（未知类型），可能无法创建 Swap 文件。"
    fi

    info "虚拟化环境检测通过（非典型容器）。"
}

# 检查当前是否已有 Swap
check_existing_swap() {
    if swapon --show | grep -q 'swap'; then
        warn "系统当前已启用 Swap："
        swapon --show
        echo -e "${YELLOW}继续操作将添加额外的 Swap 文件，是否继续？[y/N]${NC}"
        read -r ans
        if [[ ! "$ans" =~ ^[Yy]$ ]]; then
            exit 0
        fi
    fi
}

# 获取推荐 Swap 大小 (MB)
get_recommend_swap_mb() {
    # 获取物理内存 (单位 MB)
    local mem_total_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local mem_mb=$((mem_total_kb / 1024))

    # 推荐逻辑：物理内存 ≤ 1024MB -> 推荐等于物理内存
    #           物理内存 ≤ 2048MB -> 推荐 1.5 倍物理内存
    #           物理内存 ≤ 4096MB -> 推荐等于物理内存
    #           更大 -> 推荐 4096MB
    if [ "$mem_mb" -le 1024 ]; then
        echo "$mem_mb"
    elif [ "$mem_mb" -le 2048 ]; then
        echo $((mem_mb * 3 / 2))   # 1.5 倍
    elif [ "$mem_mb" -le 4096 ]; then
        echo "$mem_mb"
    else
        echo 4096
    fi
}

# 确认磁盘空间（根分区 / 的可用空间，单位 MB）
check_disk_space() {
    local required_mb=$1
    local available_mb=$(df -m / | awk 'NR==2 {print $4}')
    if [ "$available_mb" -lt "$required_mb" ]; then
        die "磁盘空间不足！需要 ${required_mb}MB，/ 分区仅剩 ${available_mb}MB。"
    fi
    info "/ 分区可用空间: ${available_mb}MB，满足要求。"
}

# 设置 swappiness
set_swappiness() {
    echo "-------------------------------------"
    echo "建议将 vm.swappiness 设置为 10（较少使用 Swap，保护 SSD）"
    echo "输入 0-100 之间的值，直接回车则设为 10，输入 n 跳过："
    read -r swp_val
    if [ "$swp_val" = "n" ] || [ "$swp_val" = "N" ]; then
        info "跳过 swappiness 设置。"
        return
    fi
    swp_val=${swp_val:-10}
    if ! [[ "$swp_val" =~ ^[0-9]+$ ]] || [ "$swp_val" -gt 100 ]; then
        warn "输入无效，跳过。"
        return
    fi

    sysctl vm.swappiness="$swp_val" 2>/dev/null || warn "临时设置 swappiness 失败"
    if grep -q "^vm.swappiness" /etc/sysctl.conf 2>/dev/null; then
        sed -i "s/^vm.swappiness.*/vm.swappiness = $swp_val/" /etc/sysctl.conf
    else
        echo "vm.swappiness = $swp_val" >> /etc/sysctl.conf
    fi
    info "swappiness 已永久设置为 $swp_val"
}

# ------------------------------ 主流程 ------------------------------

# 1. 必须 root
if [ "$(id -u)" -ne 0 ]; then
    die "请使用 root 用户运行本脚本。"
fi

echo "============================================="
echo "   VPS 虚拟内存 (Swap) 创建脚本"
echo "============================================="

# 2. 检测虚拟化支持
check_virt_support

# 3. 检查已有 Swap
check_existing_swap

# 4. 计算推荐值并交互输入
RECOMMEND=$(get_recommend_swap_mb)
echo ""
echo "当前物理内存: $(free -h | awk '/Mem:/ {print $2}')"
echo "推荐 Swap 大小: ${RECOMMEND}MB （回车直接使用推荐值）"
echo -n "请输入要创建的 Swap 大小 (MB): "
read -r SWAP_MB
SWAP_MB=${SWAP_MB:-$RECOMMEND}

# 输入校验
if ! [[ "$SWAP_MB" =~ ^[0-9]+$ ]] || [ "$SWAP_MB" -le 0 ]; then
    die "输入无效，必须是正整数。"
fi

info "即将创建 ${SWAP_MB}MB 的 Swap 文件..."

# 5. 检查磁盘空间
check_disk_space "$SWAP_MB"

# 6. 创建 Swap 文件
SWAPFILE="/swapfile"
if [ -f "$SWAPFILE" ]; then
    warn "$SWAPFILE 已存在，将被覆盖。继续？[y/N]"
    read -r ans
    if [[ ! "$ans" =~ ^[Yy]$ ]]; then
        exit 0
    fi
    swapoff "$SWAPFILE" 2>/dev/null || true
    rm -f "$SWAPFILE"
fi

info "正在创建 ${SWAP_MB}MB 文件（可能需要几秒）..."
dd if=/dev/zero of="$SWAPFILE" bs=1M count="$SWAP_MB" status=progress
chmod 600 "$SWAPFILE"
mkswap "$SWAPFILE"
swapon "$SWAPFILE"

info "Swap 已启用："
free -h

# 7. 写入 /etc/fstab（如果尚未写入）
if ! grep -q "^$SWAPFILE " /etc/fstab 2>/dev/null; then
    echo "$SWAPFILE none swap sw 0 0" >> /etc/fstab
    info "已添加 $SWAPFILE 到 /etc/fstab，开机自动挂载。"
else
    warn "$SWAPFILE 已存在于 fstab 中，跳过添加。"
fi

# 8. 调整 swappiness（可选）
set_swappiness

echo ""
echo "============================================="
echo "   所有操作完成！当前内存与 Swap 情况："
free -h
echo "============================================="
