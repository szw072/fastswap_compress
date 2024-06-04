echo -e "before\n"
lsmod | grep fast
sudo rmmod fastswap

# 输入任意参数 rmmod dram模块: sh rmmod.sh 1
if [ "$#" -gt 0 ]; then
    sudo rmmod fastswap_dram.ko
else
    sudo rmmod fastswap_rdma
fi

echo -e "after\n"
lsmod | grep fast
