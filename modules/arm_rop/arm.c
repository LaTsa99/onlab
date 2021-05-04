#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <asm/uaccess.h>

#define IOCTL_WRITE 0
#define IOCTL_READ 1

#define OUT 0
#define IN 1

#define MAX_ALLOC 4 * 4096

MODULE_LICENSE("GPL");

static int major_num;
static int device_open_count = 0;

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
	unsigned long size;
	int msg_buffer[128] = {0};

	switch(cmd){
		case IOCTL_WRITE:{
			printk(KERN_INFO "Stack write\n");

			size = ((unsigned long*)arg)[0];
			memcpy(&msg_buffer, (void*)((unsigned long*)arg)[1], size);

			break;
				 }
		case IOCTL_READ:{
			printk(KERN_INFO "Stack read\n");

			size = ((unsigned long*)arg)[0];
			memcpy((void*)((unsigned long*)arg)[1], &msg_buffer, size);
			
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

int arm_init(void){
	major_num = register_chrdev(0, "arm", &file_ops);
	if(major_num < 0){
		printk(KERN_ALERT "Could not register device: %d\n", major_num);
		return major_num;
	} else {
		printk(KERN_INFO "ARM module loaded with device major number %d\n", major_num);
		return 0;
	}
}

void arm_cleanup(void){
	unregister_chrdev(major_num, "arm");
	printk(KERN_INFO "Goodbye then\n");
}

module_init(arm_init);
module_exit(arm_cleanup);