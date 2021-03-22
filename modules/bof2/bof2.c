#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include "bof2.h"

#define OUT 0
#define IN 1

MODULE_LICENSE("GPL");

static int major_num;
static int device_open_count = 0;

int copy_user(void *kernel_ptr, void *user_ptr, unsigned long size, unsigned short dir){
	if(dir == OUT){
		return copy_to_user(user_ptr, kernel_ptr, size);
	}
	else{
		return copy_from_user(kernel_ptr, user_ptr, size);
	}
}

// prototypes for device functions
static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static long device_ioctl(struct file *, unsigned int, unsigned long);

// struct that holds device file operations
static struct file_operations file_ops = {
	.open = device_open,
	.release = device_release,
	.unlocked_ioctl = device_ioctl
};

static long device_ioctl(struct file *filp, unsigned int cmd, unsigned long arg){
	int error_count = 0;
	unsigned long size;
    void (*fn)(void);
	int msg_buffer[256] = {0};

	switch(cmd){
		case IOCTL_WRITE:{
			printk(KERN_INFO "Stack write\n");

			get_user(size, (unsigned long *)arg);

			error_count = copy_user(msg_buffer,(unsigned long *)(arg+8), size * sizeof(int), IN);
			if(error_count == 0){
				return 0;
			}else{
				return -EFAULT;
			}

			break;
				 }
		case IOCTL_READ:{
			printk(KERN_INFO "Stack read\n");

			get_user(size, (unsigned long*)arg);

			//error_count = copy_to_user((unsigned long*)(arg+8), msg_ptr, size);
			error_count = copy_user(msg_buffer, (unsigned long*)(arg+8), size * sizeof(int), OUT);
			
			if(error_count == 0){
				return 0;
			}else{
				return -EFAULT;
			}

			break;
		}
        case IOCTL_FUNC:{
            printk(KERN_INFO "Call func\n");
            fn = (void (*)(void))arg;
            fn();
            break;
        }
		default:
			printk(KERN_INFO "Unknown cmd %d\n", cmd);
	}

	return 0;

}

static int device_open(struct inode *inode, struct file *file){
	if(device_open_count){
		return -EBUSY;
	}

	device_open_count++;
	try_module_get(THIS_MODULE);
	return 0;
}

static int device_release(struct inode *inod, struct file *file){
	device_open_count--;
	module_put(THIS_MODULE);
	return 0;
}

int bof_init(void){
	major_num = register_chrdev(0, "bof", &file_ops);
	if(major_num < 0){
		printk(KERN_ALERT "Could not register device: %d\n", major_num);
		return major_num;
	} else {
		printk(KERN_INFO "BOF module loaded with device major number %d\n", major_num);
		return 0;
	}
}

void bof_cleanup(void){
	unregister_chrdev(major_num, "bof");
	printk(KERN_INFO "Goodbye then\n");
}

module_init(bof_init);
module_exit(bof_cleanup);
