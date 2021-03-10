#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>

#define WRITE_STACK 0
#define READ_STACK 1

#define MAX_MSG 256

typedef struct read_write_stack{
	unsigned long size;
	char msg[MAX_MSG];
} read_write_stack;

int main(){
	int fd;
	long ret;
	char msg[128] = {0};
	int msg_size = 0;
	strncpy(msg, "HELLO", 5);

	read_write_stack* payload = (read_write_stack*)malloc(sizeof(unsigned long) + MAX_MSG);
	msg_size = strlen(msg);
	strncpy(payload->msg, msg, msg_size);
	payload->size = msg_size;
	printf("[+] Opening device file for writing...\n");
	fd = open("/dev/bof", O_RDWR);
	if(fd < 0){
		printf("[-] Failed to open device file\n");
		exit(-1);
	}

	printf("[+] Sending payload to the device file...\n");
	ret = ioctl(fd, WRITE_STACK, (unsigned long)payload);
	if(ret < 0){
		printf("[-] Failed to write to kernel stack\n");
		exit(-1);
	}else{
		printf("[+] Successfully written to kernel stack\n");
	}

	read_write_stack* receiver = (read_write_stack*)malloc(sizeof(unsigned long) + sizeof(char*));
	receiver->size = msg_size;

	printf("[+] Trying to read from kernel stack...\n");
	ret = ioctl(fd, READ_STACK, (unsigned long)receiver);
	if(ret < 0){
		printf("[-] Failed to read from kernel stack\n");
		exit(-1);
	}else{
		printf("[+] Received message: %s\n", receiver->msg);
	}

	free(payload);
	free(receiver);
	
	return 0;
}
