# onlab

# Installing qemu
sudo apt install qemu qemu-system-x86

mkdir ~/kernel_debug  
// download linux source tar, extract it and rename linux-<version> to linux  
// download buildroot source archive, extract it and rename buildroot-<version> to buildroot
 

From here basically following the steps in the following website:  
https://www.nullbyte.cat/post/linux-kernel-exploit-development-environment/

# Building linux kernel
Configured everything just like on the website, but didnt apply KASan debugger and didn't disable any security features (will disable kaslr in qemu).

# Compiling buildroot
Same as above, selected ext2 fs, made init script and added root and 'user' users by creating shadow and passwd files (passwords are root and user).
Set user home permission in device table:  
echo -e '/home/user\td\t755\t1000\t100\t-\t-\t-\t-\t-' >> <kernel_debug directory>/buildroot/system/device_table.txt  
Added kernel modules:  
(in linux folder) make modules_install INSTALL_MOD_PATH=<kernel_debug directory>/buildroot/overlay  
And finally make source & make

# Boot script and testing
Wrote boot.sh and started it. Then added ssh keys with ssh-copy-id, to be able to copy files (mainly kernel modules) with scp.
Then I wrote hello.c in linux/src/hello, compiled with Makefile and copied hello.ko to the qemu machine with scp.

# GDB
First added python script to gdbinit:  
echo "add-auto-load-safe-path `pwd`/scripts/gdb/vmlinux-gdb.py" >> ~/.gdbinit  

Then started it:  
gdb vmlinux  
gdb> target remote :1234

Here I installed hello.ko (insmod) and copied the address of the module:  
cat /proc/modules | grep hello  

gdb> add-symbols-file src/hello/hello.ko \<address copied\>  
gdb> b \*\<address copied\>  
  
Then I removed hello module (rmmod) and restarted it. Now I got a breakpoint in the init_module function.
