#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("olyan van?");

int init_module(void){
	printk(KERN_INFO "Hello, this is LaTsa\n");
	return 0;
}

void cleanup_module(void){
	printk(KERN_INFO "Goodbye then\n");
}
