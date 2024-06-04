#ofa_kernel-4.9 -> mlnx-ofed-kernel-4.9
# OFA_DIR ?= /usr/src/ofa_kernel/default
# OFA_INCLUDE := $(OFA_DIR)/include
# OFA_SYMVERS := $(OFA_DIR)/Module.symvers

#判断是否执行 $(MAKE) -C $(KDIR) M=$$PWD 且从$(KDIR)返回当且目录 继续解析kbuild语法 obj-m
# ifneq ($(LINUXINCLUDE),)
# # kbuild part of makefile

# LINUXINCLUDE := \
#   -I$(OFA_INCLUDE) \
#   ${LINUXINCLUDE}



### 4.15.0-smartcompress 没有安装ofa 且dram backend不涉及rdma 所以这里使用/usr/src下的header

ifneq ($(KERNELRELEASE),)

else
# normal makefile

# export KBUILD_EXTRA_SYMBOLS=$(OFA_SYMVERS)
KDIR ?= /lib/modules/`uname -r`/build



all:
#M表示module(kbuild file)存放位置
	$(MAKE) -C $(KDIR) M=$(shell pwd) modules
	

clean:
	$(MAKE) -C $(KDIR) M=$(shell pwd) clean
endif

BACKEND = DRAM

obj-m  := fastswap.o
ifeq ($(BACKEND),)
	obj-m += fastswap_rdma.o
	CFLAGS_fastswap.o=-DBACKEND=2
else
	obj-m += fastswap_dram.o
	CFLAGS_fastswap.o=-DBACKEND=1
endif