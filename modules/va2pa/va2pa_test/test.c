#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>

struct iostruct{
	unsigned long addr;
	unsigned long* phys;
};

int main(void){
	int fd;
	int *dummy;
	unsigned long ret;
	unsigned long *phys;
	struct iostruct *io;

	fd = open("/dev/vapa", O_RDWR);
	if(fd < 0){
		perror("opening device file");
		exit(-1);
	}

	io = (struct iostruct*)malloc(sizeof(struct iostruct));

	dummy = (int*)malloc(sizeof(int));
	phys = (unsigned long*)malloc(sizeof(unsigned long));
	*phys = 0x0;

	io->addr = (unsigned long)dummy;
	io->phys = phys;

	ret = (unsigned long)ioctl(fd, 0, (unsigned long)io);
	if(ret < 0){
		perror("ioctl");
		free(io);
		free(dummy);
		free(phys);
		close(fd);
		return 0;
	}
	printf("Virtual address: 0x%016lx\n", (unsigned long)dummy);
	printf("Physical address: 0x%016lx\n", *(io->phys));

	free(io);
	free(dummy);
	free(phys);
	close(fd);

	return 0;
}