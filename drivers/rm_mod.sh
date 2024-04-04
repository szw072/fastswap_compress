echo -e "before\n"
lsmod | grep fast
sudo rmmod fastswap
sudo rmmod fastswap_rdma
echo -e "after\n"
lsmod | grep fast
