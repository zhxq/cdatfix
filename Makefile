KERNEL_PATH ?= /lib/modules/$(shell uname -r)/build
KERNEL_SOURCE_PATH = /home/eeum/linux-6.6.8
ccflags-y := -std=gnu99  -Wno-declaration-after-statement -I$(KERNEL_SOURCE_PATH)/drivers/cxl -I$(KERNEL_SOURCE_PATH)/drivers/cxl/core

obj-m += cdatfix.o

all:
	make -C $(KERNEL_PATH) M=$(shell pwd) modules
	make -C $(KERNEL_PATH) M=$(shell pwd) modules_install
	depmod -A

clean:
	make -C $(KERNEL_PATH) M=$(shell pwd) clean