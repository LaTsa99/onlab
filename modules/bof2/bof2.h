#ifndef BOF2_H
#define BOF2_H


#include <linux/ioctl.h>

#define IOCTL_MAGIC 0x33
#define IOCTL_READ 		_IOWR(IOCTL_MAGIC, 0, unsigned long)
#define IOCTL_WRITE 	_IOWR(IOCTL_MAGIC, 1, unsigned long)
#define IOCTL_FUNC      _IOWR(IOCTL_MAGIC, 2, unsigned long)

#endif