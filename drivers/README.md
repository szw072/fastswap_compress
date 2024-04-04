# 建立RDMA连接
### server
    ./rmserver 50000

### client
    make  
    sh ins_mod.sh

# benchmark测试
 
client创建cgroup

     cd cfm 
     sh setup/init_bench_cgroups.sh  

测试benchmark  

     sudo ./benchmark.py quicksort 0.6 --id 5


