echo -e "before\n"
lsmod | grep fast

sudo rmmod fastswap
# sudo rmmod fastswap_dram
sudo rmmod fastswap_rdma


echo -e "before\n"
lsmod | grep fast