#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include "heap.h"

#define OUT 0
#define IN 1

#define MAX_ALLOC 4 * 4096

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
	void *allocated = NULL;
	struct iomalloc *iom = NULL;

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
		case IOCTL_KMALLOC:{
			printk(KERN_INFO "Allocating kernel memory\n");
			
			iom = (struct iomalloc*)arg;

			if(iom->size > MAX_ALLOC)
				return -EOVERFLOW;

			allocated = kmalloc(iom->size, GFP_KERNEL);
			iom->addr = allocated;
			break;
		}
		case IOCTL_KFREE:{
			printk(KERN_INFO "Freeing kernel memory\n");
			kfree((const void*)arg);
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

int heap_init(void){
	major_num = register_chrdev(0, "heap", &file_ops);
	if(major_num < 0){
		printk(KERN_ALERT "Could not register device: %d\n", major_num);
		return major_num;
	} else {
		printk(KERN_INFO "HEAP module loaded with device major number %d\n", major_num);
		return 0;
	}
}

void heap_cleanup(void){
	unregister_chrdev(major_num, "heap");
	printk(KERN_INFO "Goodbye then\n");
}

module_init(heap_init);
module_exit(heap_cleanup);
