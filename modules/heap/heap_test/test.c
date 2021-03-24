#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>

#include "../heap.h"

int main(){
	int fd;
	int ret;

	printf("[+] Opening device file...\n");

	fd = open("/dev/heap", O_RDWR);
	if(fd < 0){
		printf("[-] Failed to open device file\n");
		perror("Opening file");
		exit(-1);
	}

	printf("[+] Allocating memory in kernel heap...\n");

	struct iomalloc *iom = (struct iomalloc*)malloc(sizeof(struct iomalloc));
	if(iom == NULL){
		printf("[-] Failed to create payload struct\n");
		close(fd);
		exit(-1);
	}

	iom->size = 4096;
	iom->addr = NULL;

	ret = ioctl(fd, IOCTL_KMALLOC, iom);
	if(ret < 0){
		printf("[-] Failed to allocate memory\n");
		close(fd);
		free(iom);
		exit(-1);
	}

	printf("[+] Address of allocated memory: %p\n", iom->addr);
	printf("[+] Freeing allocated memory\n");

	ioctl(fd, IOCTL_KFREE, iom->addr);
	printf("[+] Memory freed\n");

	close(fd);
	free(iom);
}