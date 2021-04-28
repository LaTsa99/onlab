#!/bin/bash

qemu-system-aarch64 \
	-machine virt \
	-cpu max \
	-kernel linux/arch/arm64/boot/Image \
	-drive file=buildroot/output/images/rootfs.ext3,format=raw \
	-net user,hostfwd=tcp::2222-:22,hostfwd=tcp::9999-:9999 -net nic \
	-nographic \
	-smp 1 \
	-append "root=/dev/vda console=ttyAMA0" \
	-m 2048 \
	-s
