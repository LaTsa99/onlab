#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>


int main(void){
	int fd;
	int *dummy;
	unsigned long ret;

	fd = open("/dev/vapa", O_RDWR);
	if(fd < 0){
		printf("[-] Failed to open device file\n");
		exit(-1);
	}

	dummy = (int*)malloc(sizeof(int));

	ret = (unsigned long)ioctl(fd, 0, (unsigned long)dummy);
	printf("Virtual address: 0x%016lx\n", (unsigned long)dummy);
	printf("Physical address: 0x%016lx\n", ret);

	free(dummy);

	return 0;
}