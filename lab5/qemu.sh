#!/bin/sh
DEBUG=
APPEND="console=ttyS0"

if [ "$1" = "debug" ]; then
	DEBUG="-s -S"
	APPEND="$APPEND nokaslr"
fi

exec qemu-system-x86_64 \
  -smp 2 \
  -kernel ./dist/vmlinuz-* \
  -initrd ./dist/rootfs.cpio.bz2 \
  -append "$APPEND" \
  -serial stdio \
  -monitor none \
  -nographic \
  -no-reboot \
  -cpu qemu64 -nic none \
  -m 96M $DEBUG

