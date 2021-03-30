#ifndef HEAP_H
#define HEAP_H


#include <linux/ioctl.h>

#define IOCTL_MAGIC 0x33
#define IOCTL_READ		_IOWR(IOCTL_MAGIC, 0, unsigned long)
#define IOCTL_WRITE		_IOWR(IOCTL_MAGIC, 1, unsigned long)
#define IOCTL_FUNC		_IOWR(IOCTL_MAGIC, 2, unsigned long)
#define IOCTL_KMALLOC	_IOWR(IOCTL_MAGIC, 3, unsigned long)
#define IOCTL_KFREE		_IOWR(IOCTL_MAGIC, 4, unsigned long)
#define IOCTL_RW_HEAP	_IOWR(IOCTL_MAGIC, 5, unsigned long)

struct iomalloc{
	size_t size;
	void* addr;
};

struct iorw{
	size_t size;
	void* from;
	void* to;
};	

#endif