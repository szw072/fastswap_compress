echo -e "before\n"
lsmod | grep fast
sudo rmmod fastswap
sudo rmmod fastswap_rdma
# sudo rmmod fastswap_dram

echo -e "after\n"
lsmod | grep fast
