#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#define BUFFER_LEN 256
static char receive[BUFFER_LEN];

int main(){
	int ret, fd;
	char str_to_send[BUFFER_LEN];
	
	printf("[+] Opening device file for writing...\n");
	fd = open("/dev/hello2", O_RDWR);
	if(fd < 0){
		printf("[-] Failed to open device file\n");
		exit(-1);
	}

	printf("String to send to module:\n");
      	scanf("%[^\n]%*c", str_to_send);
	
	printf("[+] Writing message to the device file...\n");
	ret = write(fd, str_to_send, strlen(str_to_send));
	if(ret < 0){
		printf("[-] Failed to write into the device file\n");
		exit(-1);
	}

	printf("[+] Messafe successfully written into the device file!\n\n\n");

	printf("[+] Reading from from the device file...\n");
	ret = read(fd, receive, BUFFER_LEN);
	if(ret < 0){
		printf("[-] Failed to read message from the device file\n");
		exit(-1);
	}

	printf("[+] The message is: %s\n", receive);
	return 0;
}
