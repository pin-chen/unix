
obj-m     += kshram.o
ccflags-y += -DEXPORT_SYMTAB

all: check_fork check_msg check_resize
	make -C ../dist/modulebuild M=$(PWD) modules

check_fork: check_fork.c
	$(CROSS_COMPILE)gcc -o $@ $< -Wall -static

check_msg: check_msg.c
	$(CROSS_COMPILE)gcc -o $@ $< -Wall -static

check_resize: check_resize.c
	$(CROSS_COMPILE)gcc -o $@ $< -Wall -static

clean:
	rm -f check_fork check_msg check_resize
	make -C ../dist/modulebuild M=$(PWD) clean

install: all
	mkdir -p ../rootfs/modules
	cp check_fork check_msg check_resize kshram.ko ../rootfs/modules
