# zer0pts 2020 meowmow writeup  
## Enviornment  
In this challenge we have 4 file given: a linux image, a rootfs file, the program code of a kernel driver and a starting script (these can be found in the original folder). By running the start.sh script, we get a qemu machine running some kind of linux.  
![banner](images/banner.png)  
We can see, that we are a simple user, and our goal is to read a file, that is owned by the root user, so we need to escalate our privileges. For that we need some testing enviornment and we need a way to copy our exploit program onto this machine. To do that, we need to modfy the rootfs.cpio file.  
To unpack this, let's create a folder for it (I used fs) and use the following command while in the target directory:  
```
sudo cpio -idv < ../rootfs.cpio
```  
Now we can play around with the file system. It is important to use sudo for this, because we don't want to mess with the permissions while rebuilding this file and runnign the qemu instance. Before building this image, let's check the init script in the fs. It installs some drivers, that we will use during the exploitation, but there is this line in the code, that changes the current user from root to user. I recommend modifying it for now, because we will have way easier time creating the exploit.  
```bash
setsid /bin/cttyhack setuidgid 0 /bin/sh
#setsid /bin/cttyhack setuidgid 1000 /bin/sh
```  
Now, if we want to build the cpio image from this, navigate to this directory and run the following command:  
```
sudo find ./ | sudo cpio -o --format=newc > ../pwn.cpio
```  
One more step to use this fs is to modify the start.sh script so that it uses this image as the fs:  
```bash
- initrd ./pwn.cpio \
```  
As we already see the start script, it is worth to mention, that we can see here, that many security countermeasures are turned on: SMEP, SMAP, KASLR and KPTI are all turned on. So in the exploit we need to bypass them. But to be able to do that, we need to gather rop gadget addresses, and to do that, we can turn off some countermeasures here (I will turn off KASLR for a while) to make our life easier.  
But now if we run the start script, we can see, that we get the same enviornment and we are root, so we can open the flag file too.  
We will need to be able to debug this kernel module too. For debug reasons, I downloaded the linux kernel with the exact same version that is used here (4.19.98). But we cannot see any config files which can tell us, which configuration was used to build the kernel. Since I couldn't do much, I simply used the defconfig and the only change I made is to generate debug symbols and generate a python file we can use with gdb. For this debug machine I copied the unpacked file system, and put a recompiled version of the kenrel module which contains kernel symbols too. Finally I created a new start script for this too, which is the same as the start.sh, but I changed the linux image and the fs to the debug variants. Furthermore I added the -s switch to the qemu command, so I can debug remotely with gdb.  
## The vulnerability  
Now that we are ready with the enviornment, we can start the exploitation. Since we got the source code of the memo kernel module, it is a good guess, to look for vulnerabilities in there. After an undue amount of reading I finally found the error in this code. Actually two errors: in mod_write and in mod_read:  
```C
static ssize_t mod_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{
  if (filp->f_pos < 0 || filp->f_pos >= MAX_SIZE) return 0;
  if (count < 0) return 0;
  if (count > MAX_SIZE) count = MAX_SIZE - *f_pos;
  if (copy_to_user(buf, &memo[filp->f_pos], count)) return -EFAULT;
  *f_pos += count;
  return count;
}

static ssize_t mod_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{
  if (filp->f_pos < 0 || filp->f_pos >= MAX_SIZE) return 0;
  if (count < 0) return 0;
  if (count > MAX_SIZE) count = MAX_SIZE - *f_pos;
  if (copy_from_user(&memo[filp->f_pos], buf, count)) return -EFAULT;
  *f_pos += count;
  return count;
}
```  
As we can see, these functions do several checks on read/write lengths to make sure we are not overreading/writing the buffer, that is allocated on the heap (memo pointer), But there is a logic error. The driver uses llseek to set the cursor, from which the read or the write should begin. This cursor is the `filp->f_pos`. These functions check, if it is smaller than 0, or greater or equals to the maximum size, which is 1024 bytes. Then it checks, if the read/write length is smaller than 0 or greater than MAX_SIZE. If it is greater, then it is reduced to maximally reach the end of the buffer. BUT  
These functions never check, if the cursor+count sum is greater than the max size. Because of this, and because we have an lseek operation on this file, we can set the cursor to the MAX_SIZE-1 byte of the buffer, and read/write the length of MAX_SIZE, and this way we are able to read almost the whole 1024 byte struct which comes after this struct in the kmalloc-1024 bin (because this buffer is 1024 bytes long). Thus we have a kmalloc overflow vulnerability.  

## Plan on controlling the RIP  
