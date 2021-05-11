#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/pgtable.h>
#include <asm/page.h>

#include "vapa.h"

#define VA2PA 0

MODULE_LICENSE("GPL");

static int major_num;
static int device_open_count = 0;
static struct mm_struct *mm;
static void check(unsigned long entry, unsigned long mask, const char* str);
static void analyze(unsigned long virtual, struct mm_struct *mm, unsigned short flags);

static int device_open(struct inode*, struct file*);
static int device_release(struct inode*, struct file*);
static long device_ioctl(struct file*, unsigned int, unsigned long);

static struct file_operations file_ops = {
	.open = device_open,
	.release = device_release,
	.unlocked_ioctl = device_ioctl
};

static long device_ioctl(struct file *filp, unsigned int cmd, unsigned long arg){
	struct translate_mem* payload = (struct translate_mem*)arg;

	switch(cmd){
		case VA2PA:{
			analyze(payload->virtual, mm, payload->flags);
			break;
		}
		default:
			printk(KERN_INFO "Unknown command %d\n", cmd);
	}

	return 0;
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

/*
/ Flags:
/ 0x0000 - all info
/ 0x0001 - pgd info
/ 0x0002 - p4d info
/ 0x0004 - pud info
/ 0x0008 - pmd info
/ 0x0010 - pte info
/ 0x0020 - physical address
*/
static void analyze(unsigned long virtual, struct mm_struct *mm, unsigned short flags){
	pgd_t *pgd = NULL;
	p4d_t *p4d = NULL;
	pud_t *pud = NULL;
	pmd_t *pmd = NULL;
	pte_t *pte = NULL;
	unsigned long page_addr, page_offset, physical;

	pgd = pgd_offset(mm, virtual);
	if(pgd_none(*pgd)){
		printk(KERN_ALERT "pgd none");
		return;
	}

	p4d = p4d_offset(pgd, virtual);
	if(p4d_none(*p4d)){
		printk(KERN_ALERT "p4d none");
		return;
	}

	pud = pud_offset(p4d, virtual);
	if(pud_none(*pud)){
		printk(KERN_ALERT "pud none");
		return;
	}

	pmd = pmd_offset(pud, virtual);
	if(pmd_none(*pmd)){
		printk(KERN_ALERT "pmd none");
		return;
	}

	pte = pte_offset_kernel(pmd, virtual);
	if(pte_none(*pte)){
		printk(KERN_ALERT "pte none");
		return;
	}

	if(!pte_present(*pte)){
		printk(KERN_ALERT "pte not present");
		return;
	}

	page_addr = pte_val(*pte) & PAGE_MASK;
	page_addr &= 0x7fffffffffffffULL;
	page_offset = virtual & ~PAGE_MASK;
	physical = page_addr | page_offset;

	printk("***********************************************\n");
	printk("***************MEMORY INFO*********************\n");
	printk("***********************************************\n");
	if(flags & INFO_PGD){
		printk("----------------PGD INFO-----------------------\n");
		printk("pgd entry:\t0x%016lx\n", (unsigned long)pgd->pgd);
	}
	if(flags & INFO_P4D){
		printk("----------------P4D INFO-----------------------\n");
		printk("p4d entry:\t0x%016lx\n", (unsigned long)p4d->pgd.pgd);
	}
	if(flags & INFO_PUD){
		printk("----------------PUD INFO-----------------------\n");
		printk("pud entry:\t0x%016lx\n", (unsigned long)pud->pud);
		check((unsigned long)pud->pud, (unsigned long)PUD_TYPE_TABLE, "PUD_TYPE_TABLE");
		check((unsigned long)pud->pud, (unsigned long)PUD_TABLE_BIT, "PUD_TABLE_BIT");
		check((unsigned long)pud->pud, (unsigned long)PUD_TYPE_MASK, "PUD_TYPE_MASK");
		check((unsigned long)pud->pud, (unsigned long)PUD_TYPE_SECT, "PUD_TYPE_SECT");
		check((unsigned long)pud->pud, (unsigned long)PUD_SECT_RDONLY, "PUD_SECT_RDONLY");
	}
	if(flags & INFO_PMD){
		printk("----------------PMD INFO-----------------------\n");
		printk("pmd entry:\t0x%016lx\n", (unsigned long)pmd->pmd);
		check((unsigned long)pmd->pmd, (unsigned long)PMD_TYPE_MASK, "PMD_TYPE_MASK");
		check((unsigned long)pmd->pmd, (unsigned long)PMD_TYPE_TABLE, "PMD_TYPE_TABLE");
		check((unsigned long)pmd->pmd, (unsigned long)PMD_TYPE_SECT, "PMD_TYPE_SECT");
		check((unsigned long)pmd->pmd, (unsigned long)PMD_TABLE_BIT, "PMD_TABLE_BIT");
		check((unsigned long)pmd->pmd, (unsigned long)PMD_SECT_VALID, "PMD_SECT_VALID");
		check((unsigned long)pmd->pmd, (unsigned long)PMD_SECT_USER, "PMD_SECT_VALID");
		check((unsigned long)pmd->pmd, (unsigned long)PMD_SECT_RDONLY, "PMD_SECT_RDONLY");
		check((unsigned long)pmd->pmd, (unsigned long)PMD_SECT_S, "PMD_SECT_S");
		check((unsigned long)pmd->pmd, (unsigned long)PMD_SECT_AF, "PMD_SECT_AF");
		check((unsigned long)pmd->pmd, (unsigned long)PMD_SECT_NG, "PMD_SECT_NG");
		check((unsigned long)pmd->pmd, (unsigned long)PMD_SECT_CONT, "PMD_SECT_CONT");
		check((unsigned long)pmd->pmd, (unsigned long)PMD_SECT_PXN, "PMD_SECT_PXN");
		check((unsigned long)pmd->pmd, (unsigned long)PMD_SECT_UXN, "PMD_SECT_UXN");
		printk("PMD_ATTRINDX   :\t0x%x", (unsigned int)(((unsigned long)pmd->pmd & PMD_ATTRINDX_MASK) >> 2));
	}
	if(flags & INFO_PTE){
		printk("----------------PTE INFO-----------------------\n");
		printk("page table entry:\t0x%016lx\n", (unsigned long)(pte->pte));
		check((unsigned long)pte->pte, (unsigned long)PTE_VALID, "PTE_VALID");
		check((unsigned long)pte->pte, (unsigned long)PTE_TYPE_MASK, "PTE_TYPE_MASK");
		check((unsigned long)pte->pte, (unsigned long)PTE_TYPE_PAGE, "PTE_TYPE_PAGE");
		check((unsigned long)pte->pte, (unsigned long)PTE_TABLE_BIT, "PTE_TABLE_BIT");
		check((unsigned long)pte->pte, (unsigned long)PTE_USER, "PTE_USER");
		check((unsigned long)pte->pte, (unsigned long)PTE_RDONLY, "PTE_RDONLY");
		check((unsigned long)pte->pte, (unsigned long)PTE_SHARED, "PTE_SHARED");
		check((unsigned long)pte->pte, (unsigned long)PTE_AF, "PTE_AF");
		check((unsigned long)pte->pte, (unsigned long)PTE_NG, "PTE_NG");
		check((unsigned long)pte->pte, (unsigned long)PTE_GP, "PTE_GP");
		check((unsigned long)pte->pte, (unsigned long)PTE_DBM, "PTE_DBM");
		check((unsigned long)pte->pte, (unsigned long)PTE_CONT, "PTE_CONT");
		check((unsigned long)pte->pte, (unsigned long)PTE_PXN, "PTE_PXN");
		check((unsigned long)pte->pte, (unsigned long)PTE_UXN, "PTE_UXN");
		check((unsigned long)pte->pte, (unsigned long)PTE_ADDR_LOW, "PTE_ADDR_LOW");
#ifdef PTR_ADDR_HIGH
		check((unsigned long)pte->pte, (unsigned long)PTE_ADDR_HIGH, "PTR_ADDR_HIGH");
#endif
		check((unsigned long)pte->pte, (unsigned long)PTE_ADDR_LOW, "PTE_ADDR_MASK");
		printk("PTE_ATTRINDX   :\t0x%x", (unsigned int)(((unsigned long)pte->pte & PTE_ATTRINDX_MASK) >> 2));

	}
	printk("-------------PHYSICAL ADDRESS------------------\n");
	printk("virtual address:\t\t0x%016lx\n", (unsigned long)virtual);
	printk("physical address:\t0x%016lx\n", physical);
	return;
}

static void check(unsigned long entry, unsigned long mask, const char* str){
	if(entry & mask){
		printk("%-15s:\t[+]\n", str);
	}else{
		printk("%-15s:\t[-]\n", str);
	}
}