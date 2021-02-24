#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <asm/uaccess.h>

MODULE_LICENSE("GPL");

static int major_num;
static char msg_buffer[256] = {0};
static short size_of_message;
static char *msg_ptr;
static int device_open_count = 0;

// prototypes for device functions
static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char *, size_t, loff_t *);

// struct that holds device file operations
static struct file_operations file_ops = {
	.read = device_read,
	.write = device_write,
	.open = device_open,
	.release = device_release
};

static ssize_t device_read(struct file *flip, char *buffer, size_t len, loff_t *offset){
	int error_count = 0;

	error_count = copy_to_user(buffer, msg_ptr, size_of_message);

	if(error_count == 0){
		return (size_of_message=0);
	} else {
		return -EFAULT;
	}
}

static ssize_t device_write(struct file *flip, const char *buffer, size_t len, loff_t *offset){
	sprintf(msg_buffer, "%s", buffer);
	size_of_message = strlen(msg_buffer);
	return len;
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

int hello2_init(void){
	msg_ptr = msg_buffer;
	major_num = register_chrdev(0, "hello2", &file_ops);
	if(major_num < 0){
		printk(KERN_ALERT "Could not register device: %d\n", major_num);
		return major_num;
	} else {
		printk(KERN_INFO "hello2 module loaded with device major number %d\n", major_num);
		return 0;
	}
}

void hello2_cleanup(void){
	unregister_chrdev(major_num, "hello2");
	printk(KERN_INFO "Goodbye then\n");
}

module_init(hello2_init);
module_exit(hello2_cleanup);
