#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/pgtable.h>
#include <asm/page.h>

#define VA2PA 0

MODULE_LICENSE("GPL");

static int major_num;
static int device_open_count = 0;
static struct mm_struct *mm;

static int device_open(struct inode*, struct file*);
static int device_release(struct inode*, struct file*);
static long device_ioctl(struct file*, unsigned int, unsigned long);

static struct file_operations file_ops = {
	.open = device_open,
	.release = device_release,
	.unlocked_ioctl = device_ioctl
};

static long device_ioctl(struct file *filp, unsigned int cmd, unsigned long arg){
	pgd_t *pgd = NULL;
	p4d_t *p4d = NULL;
	pud_t *pud = NULL;
	pmd_t *pmd = NULL;
	pte_t *pte = NULL;
	unsigned long va = ((unsigned long*)arg)[0];
	unsigned long *ret = ((unsigned long**)arg)[1];
	unsigned long page_addr, page_offset, pa;

	switch(cmd){
		case VA2PA:{
			pgd = pgd_offset(mm, va);
			if(!pgd_none(*pgd)){
				p4d = p4d_offset(pgd, va);
				if(!p4d_none(*p4d)){
					pud = pud_offset(p4d, va);
					if(!pud_none(*pud)){
						pmd = pmd_offset(pud, va);
						if(!pmd_none(*pmd)){
							pte = pte_offset_kernel(pmd, va);
							if(!pte_none(*pte)){
								if(pte_present(*pte)){
									page_addr = pte_val(*pte) & PAGE_MASK;
									page_addr &= 0x7fffffffffffffULL;
									page_offset = va & ~PAGE_MASK;
									pa = page_addr | page_offset;
									printk(KERN_INFO "Physical address: 0x%lx\n", pa);
									*ret = pa;
									return 0;
								} else {
									printk(KERN_ALERT "pte not present\n");
								}
							} else {
								printk(KERN_ALERT "pte none\n");
							}
						} else {
							printk(KERN_ALERT "pmd none\n");
						}
					} else {
						printk(KERN_ALERT "pud none\n");
					}
				} else {
					printk( KERN_ALERT "p4d none\n");
				}
			} else{
				printk(KERN_ALERT "pgd none\n");
			}
			return 0;
		}
		default:
			printk(KERN_INFO "Unknown command %d\n", cmd);
	}

	return -EAGAIN;
}

static int device_open(struct inode* inode, struct file *file){
	if(device_open_count){
		return -EBUSY;
	}

	device_open_count++;
	try_module_get(THIS_MODULE);

	mm = current->mm;

	return 0;
}

static int device_release(struct inode* inode, struct file *file){
	device_open_count--;
	module_put(THIS_MODULE);
	return 0;
}

int vapa_init(void){
	major_num = register_chrdev(0, "vapa", &file_ops);
	if(major_num < 0){
		printk(KERN_ALERT "Could not register device: %d\n", major_num);
		return major_num;
	}else{
		printk(KERN_INFO "VAPA module loaded with device major number %d\n", major_num);
		return 0;
	}
}

void vapa_cleanup(void){
	unregister_chrdev(major_num, "vapa");
	printk(KERN_INFO "Goodbye then\n");
}

module_init(vapa_init);
module_exit(vapa_cleanup);