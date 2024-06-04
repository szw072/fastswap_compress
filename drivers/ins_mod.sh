echo -e "before\n"

lsmod | grep fast

# 输入任意参数 insmod dram模块: sh insmod.sh 1
if [ "$#" -gt 0 ]; then
    sudo insmod fastswap_dram.ko
else
    sudo insmod fastswap_rdma.ko sport=50000 sip=10.10.10.9 cip=10.10.10.10 nc=20
fi

sudo insmod fastswap.ko

echo -e "after\n"
lsmod | grep fast