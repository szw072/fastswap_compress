echo -e "before\n"

lsmod | grep fast
sudo insmod fastswap_rdma.ko sport=50000 sip=10.10.10.9 cip=10.10.10.10 nc=20
# sudo insmod fastswap_dram.ko
sudo insmod fastswap.ko

echo -e "after\n"
lsmod | grep fast