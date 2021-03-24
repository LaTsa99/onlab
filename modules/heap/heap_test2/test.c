#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>

#include "../heap.h"

int cmpfunc(const void *a, const void *b){
	return (*(unsigned long*)a - *(unsigned long*)b);
}

int main(int argc, char **argv){
	int fd;
	int ret;
	int num_of_allocs;
	unsigned long *addresses;
	struct iomalloc *iom;

	if(argc != 2){
		printf("Usage: test <num of allocs>\n");
		exit(-1);
	}

	num_of_allocs = atoi(argv[1]);

	addresses = (unsigned long *)malloc(num_of_allocs * sizeof(unsigned long));
	if(addresses == NULL){
		printf("[-] Failed to allocate addresses array\n");
		exit(-1);
	}


	printf("[+] Opening device file...\n");

	fd = open("/dev/heap", O_RDWR);
	if(fd < 0){
		printf("[-] Failed to open device file\n");
		perror("Opening file");
		free(addresses);
		exit(-1);
	}

	iom = (struct iomalloc*)malloc(sizeof(struct iomalloc));
	if(iom == NULL){
		printf("[-] Failed to allocate payload struct\n");
		close(fd);
		free(addresses);
		exit(-1);
	}

	iom->size = 128;
	iom->addr = NULL;

	printf("[+] Allocating addresses...\n");

	for(int i = 0; i < num_of_allocs; i++){
		ret = ioctl(fd, IOCTL_KMALLOC, iom);
		if(ret < -0){
			printf("[-] Failed to allocate kernel memory\n");
			close(fd);
			free(iom);
			free(addresses);
			exit(-1);
		}

		addresses[i] = (unsigned long)iom->addr;
	}

	//qsort(addresses, num_of_allocs, sizeof(unsigned long), cmpfunc);
	printf("[+] Allocated addresses:\n");
	for(int i = 0; i < num_of_allocs; i++){
		printf("\t%p\n", (void*)addresses[i]);
		ioctl(fd, IOCTL_KFREE, addresses[i]);
	}

	close(fd);
	free(iom);
	free(addresses);
}