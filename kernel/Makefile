KERN_DIR := /lib/modules/$(shell uname -r)/build
lhy_firewall-objs := statics.o util.o log.o connection.o rule.o mem_chardev.o firewall_kernel.o
obj-m := lhy_firewall.o
KBUILD_CFLAGS := -O1 -fno-stack-protector -fno-omit-frame-pointer -fno-reorder-blocks-and-partition

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules clean
	rm -rf modules.order
