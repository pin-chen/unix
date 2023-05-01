.PHONY: hellomod test kshram clean

dist.tar: dist.tbz
	bunzip2 dist.tbz

dist: dist.tar
	tar xvf dist.tar

rootfs: dist
	mkdir rootfs
	cd dist && bunzip2 rootfs.cpio.bz2 && cpio -i -H newc > ../rootfs

load:
	cd rootfs && find . | cpio -o -H newc > ../rootfs.cpio
	bzip2 rootfs.cpio
	mv rootfs.cpio.bz2 dist/

hellomod:
	cd hellomod && make install

kshram:
	cd kshram && make install

test: 
	./qemu.sh
