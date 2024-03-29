#!/bin/bash

qemu-system-x86_64 \
	-kernel linux/arch/x86_64/boot/bzImage \
	-drive file=buildroot/output/images/rootfs.ext2,format=raw \
	-net nic \
	-net user,hostfwd=tcp::2222-:22,hostfwd=tcp::9999-:9999,hostfwd=tcp::8000-:8000 \
	-nographic \
	-append "root=/dev/sda console=ttyS0 nokaslr" \
	-s \
	-enable-kvm
