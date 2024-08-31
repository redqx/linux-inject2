#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/user.h>
#include <wait.h>

#include "utils.h" //自定义的工具类
#include "ptrace.h" //自定义的ptrace.h

/*
 * injectSharedLibrary()
 *
 * This is the code that will actually be injected into the target process.
 * This code is responsible for loading the shared library into the target
 * process' address space.  First, it calls malloc() to allocate a buffer to
 * hold the filename of the library to be loaded. Then, it calls
 * __libc_dlopen_mode(), libc's implementation of dlopen(), to load the desired
 * shared library. Finally, it calls free() to free the buffer containing the
 * library name. Each time it needs to give control back to the injector
 * process, it breaks back in by executing an "int $3" instruction. See the
 * comments below for more details on how this works.
 *
 */

// void injectSharedLibrary(long mallocaddr, long freeaddr, long dlopenaddr) // 这几个参数没用
void injectSharedLibrary()
{
	// here are the assumptions I'm making about what data will be located
	// where at the time the target executes this code:
	//
	//   rdi = address of malloc() in target process
	//   rsi = address of free() in target process
	//   rdx = address of __libc_dlopen_mode() in target process
	//   rcx = size of the path to the shared library we want to load

	// save addresses of free() and __libc_dlopen_mode() on the stack for later use
	asm(
		// rsi is going to contain the address of free(). it's going to get wiped
		// out by the call to malloc(), so save it on the stack for later
		"push %rsi \n"
		// same thing for rdx, which will contain the address of _dl_open()
		"push %rdx"
	);

	// char* lib_soname = malloc( xx_length )
	asm(
		
		"push %r9 \n" // save previous value of r9, because we're going to use it to call malloc()
		"mov %rdi,%r9 \n" // r9 = malloc()
		"mov %rcx,%rdi \n" // rdi = lenght(libso_name)
		"callq *%r9 \n" // call malloc()
		"pop %r9 \n" //pop the previous value of r9 off the stack
		"int $3" // 暂停一下,injector处理一下新开辟的内容rax, 往内存rax中写入libso_name
	);
	//继续运行 f9

	// call __libc_dlopen_mode() to load the shared library
	// __libc_dlopen_mode()无法直接通过dlsym()找到, 在静态的libc.so.6中也无法直接找到, __libc_dlopen_mode()好像是3个参数
	// 所以换位dlopen打开吧....
	asm(
		// get the address of __libc_dlopen_mode() off of the stack so we can call it
		"pop %rdx \n" // rdx = dlopen
		"push %r9 \n" // as before, save the previous value of r9 on the stack
		"mov %rdx,%r9 \n" //r9 = dlopen
		"mov %rax,%rdi \n" // rax = rdi = lib_soname
		"movabs $1,%rsi \n" // rsi = 1 = RTLD_LAZY
		"callq *%r9 \n" // call dlopen_mode
		"pop %r9 \n" // restore old r9 value
		"int $3" //暂停,让injector处理一下
	);

	// call free() to free the buffer we allocated earlier.
	//
	// Note: I found that if you put a nonzero value in r9, free() seems to
	// interpret that as an address to be freed, even though it's only
	// supposed to take one argument. As a result, I had to call it using a
	// register that's not used as part of the x64 calling convention. I
	// chose rbx.
	// 下面的free()函数感觉不一定要释放,^-^...
	asm(
		// at this point, rax should still contain our malloc()d buffer from earlier.
		// we're going to free it, so move rax into rdi to make it the first argument to free().
		//"mov %rax,%rdi \n" // rdi = rax = dlopen() ????
		"pop %rsi \n" // rsi = free()
		"push %rbx \n" // save previous rbx value
		"mov %rsi,%rbx \n" // rbx = rsi = free
		"xor %rsi,%rsi \n" // zero out rsi, because free() might think that it contains something that should be freed
		// break in so that we can check out the arguments right before making the call
		"int $3 \n" // 修改rdi为libso_path
		"callq *%rbx \n"// call free()
		"pop %rbx"// restore previous rbx value
	);

	//最后停止
	asm(
		"int $3 \n"
	);

	// we already overwrote the RET instruction at the end of this function
	// with an INT 3, so at this point the injector will regain control of
	// the target's execution.
}

/*
 * injectSharedLibrary_end()
 *
 * This function's only purpose is to be contiguous to injectSharedLibrary(),
 * so that we can use its address to more precisely figure out how long
 * injectSharedLibrary() is.
 *
 */

void injectSharedLibrary_end()
{

}

int main(int argc, char** argv)
{
	if(argc < 4)
	{
		usage(argv[0]);
		return 1;
	}

	char* command = argv[1];
	char* commandArg = argv[2];
	char* libname = argv[3];
	char* libPath = realpath(libname, NULL); // 通过libcname获取libso的完整路径

	char* processName = NULL;
	pid_t target_pid = 0;

	if(!libPath)
	{
		fprintf(stderr, "can't find file \"%s\"\n", libname);
		return 1;
	}

	if(!strcmp(command, "-n")) // 通过进程名去获取进程的pid
	{
		processName = commandArg;
		target_pid = findProcessByName(processName);
		if(target_pid == -1)
		{
			fprintf(stderr, "doesn't look like a process named \"%s\" is running right now\n", processName);
			return 1;
		}

		printf("targeting process \"%s\" with pid %d\n", processName, target_pid);
	}
	else if(!strcmp(command, "-p"))//直接从参数获取pid
	{
		target_pid = atoi(commandArg);
		printf("targeting process with pid %d\n", target_pid);
	}
	else
	{
		usage(argv[0]);
		return 1;
	}

	int libPathLength = strlen(libPath) + 1;
	int mypid = getpid();
	long mylibcaddr = getlibcaddr(mypid); //

	// find the addresses of the syscalls that we'd like to use inside the
	// target, as loaded inside THIS process (i.e. NOT the target process)
	long mallocAddr = getFunctionAddress("malloc");
	long freeAddr = getFunctionAddress("free");
	// long dlopenAddr = getFunctionAddress("__libc_dlopen_mode");//无法直接获取 __libc_dlopen_mode()
	long dlopenAddr = getFunctionAddress("dlopen");

	// use the base address of libc to calculate offsets for the syscalls
	// we want to use
	long libc_mallocOffset = mallocAddr - mylibcaddr;
	long libc_freeOffset = freeAddr - mylibcaddr;
	long libc_dlopenOffset = dlopenAddr - mylibcaddr;


	// get the target process' libc address and use it to find the
	// addresses of the syscalls we want to use inside the target process
	long remote_LibcAddr = getlibcaddr(target_pid);
	long remote_MallocAddr = remote_LibcAddr + libc_mallocOffset;
	long remote_FreeAddr = remote_LibcAddr + libc_freeOffset;
	long remote_DlopenAddr = remote_LibcAddr + libc_dlopenOffset;

	struct user_regs_struct oldregs, regs;
	memset(&oldregs, 0, sizeof(struct user_regs_struct));
	memset(&regs, 0, sizeof(struct user_regs_struct));

	ptrace_attach(target_pid); //附加调试目标进程,并等待子进程的停止, 目标进程收到被调试的信息后,会停下来
	ptrace_getregs(target_pid, &oldregs);//获取当前target寄存器信息
	memcpy(&regs, &oldregs, sizeof(struct user_regs_struct));

	// find a good address to copy code to
	// long addr = freespaceaddr(target) + sizeof(long); // 寻找第一块可写的内存,一般是代码段
	long remote_mem_rwx = freespaceaddr(target_pid) + 0xf00 ; //直接放远一点

	// now that we have an address to copy code to, set the target's rip to
	// it. we have to advance by 2 bytes here because rip gets incremented
	// by the size of the current instruction, and the instruction at the
	// start of the function to inject always happens to be 2 bytes long.
	regs.rip = remote_mem_rwx + 2; //实际执行的地方是 rip - 2, 所以我们指向的地方得是rip + 2
	// pass arguments to my function injectSharedLibrary() by loading them
	// into the right registers. note that this will definitely only work
	// on x64, because it relies on the x64 calling convention, in which
	// arguments are passed via registers rdi, rsi, rdx, rcx, r8, and r9.
	// see comments in injectSharedLibrary() for more details.
	regs.rdi = remote_MallocAddr;
	regs.rsi = remote_FreeAddr;
	regs.rdx = remote_DlopenAddr;
	regs.rcx = libPathLength;
	if(regs.rsp&0xf)
	{
		//高版本Linux中, 调用dlopen或者__libc_dlopen_mode前,保证rsp是16的倍数
		regs.rsp = regs.rsp - 8;
		//这个点卡了我2天,草!cao!
	}
	ptrace_setregs(target_pid, &regs);
	printf("[inject]: change target process status\n");

	// figure out the size of injectSharedLibrary() so we know how big of a buffer to allocate. 
	size_t injectSharedLibrary_size = (intptr_t) injectSharedLibrary_end - (intptr_t)injectSharedLibrary; //按照我的修改方式,导致下面多复制了一些字节

	// also figure out where the RET instruction at the end of
	// injectSharedLibrary() lies so that we can overwrite it with an INT 3
	// in order to break back into the target process. note that on x64,
	// gcc and clang both force function addresses to be word-aligned,
	// which means that functions are padded with NOPs. as a result, even
	// though we've found the length of the function, it is very likely
	// padded with NOPs, so we need to actually search to find the RET.
	// intptr_t injectSharedLibrary_ret = (intptr_t)findRet(injectSharedLibrary_end) - (intptr_t)injectSharedLibrary;

	// back up whatever data used to be at the address we want to modify.
	char* backup = malloc(injectSharedLibrary_size * sizeof(char));
	ptrace_read(target_pid, remote_mem_rwx, backup, injectSharedLibrary_size);

	// set up a buffer to hold the code we're going to inject into the
	// target process.
	char* newcode = malloc(injectSharedLibrary_size * sizeof(char));
	memset(newcode, 0, injectSharedLibrary_size * sizeof(char));

	// copy the code of injectSharedLibrary() to a buffer.
	memcpy(newcode, (char*)injectSharedLibrary + 4, injectSharedLibrary_size);
	/*
.text:0000563A66E30F44 55                            push    rbp
.text:0000563A66E30F45 48 89 E5                      mov     rbp, rsp ; 跳过这几个字节
.text:0000563A66E30F48 56                            push    rsi
.text:0000563A66E30F49 52                            push    rdx
.text:0000563A66E30F4A 41 51                         push    r9
.text:0000563A66E30F4C 49 89 F9                      mov     r9, rdi
.text:0000563A66E30F4F 48 89 CF                      mov     rdi, rcx
.text:0000563A66E30F52 41 FF D1                      call    r9
	 */

	// overwrite the RET instruction with an INT 3.
	// newcode[injectSharedLibrary_ret] = INTEL_INT3_INSTRUCTION;

	// copy injectSharedLibrary()'s code to the target address inside the
	// target process' address space.
	ptrace_write(target_pid, remote_mem_rwx, newcode, injectSharedLibrary_size);//写入shellcode

	// now that the new code is in place, let the target run our injected
	// code.
	ptrace_f9(target_pid,1); // 准备执行shellcode,参数已经放入寄存器中, 同时等待target的int中断
	printf("[inject]: write shellcode and run malloc()\n");

	// at this point, the target should have run malloc(). check its return
	// value to see if it succeeded, and bail out cleanly if it didn't.
	//struct user_regs_struct malloc_regs;
	memset(&regs, 0, sizeof(struct user_regs_struct));
	ptrace_getregs(target_pid, &regs);//
	unsigned long long remote_malloc_buf = regs.rax;//获取malloc函数返回地址, 虽然在x64下,long是8字节, 但regs.rax却是long long类型
	printf("[inject]: get remote addr for malloc() = %x\n",remote_malloc_buf);
	if(remote_malloc_buf == 0)
	{
		fprintf(stderr, "malloc() failed to allocate memory\n");
		restoreStateAndDetach(target_pid, remote_mem_rwx, backup, injectSharedLibrary_size, oldregs);
		free(backup);
		free(newcode);
		return 1;
	}

	// if we get here, then malloc likely succeeded, so now we need to copy
	// the path to the shared library we want to inject into the buffer
	// that the target process just malloc'd. this is needed so that it can
	// be passed as an argument to __libc_dlopen_mode later on.

	// read the current value of rax, which contains malloc's return value,
	// and copy the name of our shared library to that address inside the
	// target process.
	ptrace_write(target_pid, remote_malloc_buf, libPath, libPathLength);//往remote_malloc_buf写入libpath

	// continue the target's execution again in order to call
	// __libc_dlopen_mode.
	ptrace_f9(target_pid,1);
	printf("[inject]: write libpath to remote process memory buffer and run dlopen(): %s\n",libPath);

	// check out what the registers look like after calling dlopen. 
	//struct user_regs_struct dlopen_regs;
	memset(&regs, 0, sizeof(struct user_regs_struct));
	ptrace_getregs(target_pid, &regs);
	unsigned long long remote_libso_addr = regs.rax; //获取dlopen函数返回值

	// if rax is 0 here, then __libc_dlopen_mode failed, and we should bail
	// out cleanly.
	printf("[inject]: get remote %s at =%x\n",libname,remote_libso_addr);
	if(remote_libso_addr == 0)
	{
		fprintf(stderr, "__libc_dlopen_mode() failed to load %s\n", libname); //查看有没有加载成功
		restoreStateAndDetach(target_pid, remote_mem_rwx, backup, injectSharedLibrary_size, oldregs);
		free(backup);
		free(newcode);
		return 1;
	}

	// now check /proc/pid/maps to see whether injection was successful.
	if(checkloaded(target_pid, libname))
	{
		printf("[inject]: \"%s\" successfully injected\n", libname);
	}
	else
	{
		fprintf(stderr, "could not inject \"%s\"\n", libname);
	}
	ptrace_f9(target_pid,1);//执行到准备free

	// as a courtesy, free the buffer that we allocated inside the target
	// process. we don't really care whether this succeeds, so don't
	// bother checking the return value.
	ptrace_getregs(target_pid, &regs);
	regs.rdi = remote_libso_addr; //free(rdi = remote_libso_addr)
	ptrace_setregs(target_pid, &regs);
	ptrace_f9(target_pid,1); //执行到最后的int3

	// at this point, if everything went according to plan, we've loaded
	// the shared library inside the target process, so we're done. restore
	// the old state and detach from the target.
	restoreStateAndDetach(target_pid, remote_mem_rwx, backup, injectSharedLibrary_size, oldregs);
	printf("[inject]: detach from pid = %d\n", target_pid);
	free(backup);
	free(newcode);

	return 0;
}
