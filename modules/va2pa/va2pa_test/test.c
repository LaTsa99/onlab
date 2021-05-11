#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "../vapa.h"

int main(void){
	int fd;
	int *dummy;
	unsigned long ret;
	struct translate_mem *payload;

	fd = open("/dev/vapa", O_RDWR);
	if(fd < 0){
		printf("[-] Failed to open device file\n");
		exit(-1);
	}

	dummy = (int*)malloc(sizeof(int));
	payload = (struct translate_mem*)malloc(sizeof(struct translate_mem));
	payload->virtual = dummy;
	payload->flags = INFO_PUD | INFO_PMD | INFO_PTE;
	printf("virtual address: 0x%016lx\n", (unsigned long)dummy);
	ret = (unsigned long)ioctl(fd, 0, (unsigned long)payload);

	free(dummy);
	free(payload);
	close(fd);
	return 0;
}