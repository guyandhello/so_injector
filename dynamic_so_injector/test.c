#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <dirent.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string.h>

#define LIBDL_NAME ("libdl.so.2")

unsigned long long
findLibrary(const char* library, pid_t pid)
{
    char mapFilename[1024];
    char buffer[9076];
    FILE* fd;
    unsigned long long addr = 0;

    if (pid == -1)
    {
        snprintf(mapFilename, sizeof(mapFilename), "/proc/self/maps");
    }
    else
    {
        snprintf(mapFilename, sizeof(mapFilename), "/proc/%d/maps", pid);
    }

    fd = fopen(mapFilename, "r");
    if (!fd)
    {
        printf("[!] Error opening maps file %s\n", mapFilename);
        exit(1);
    }

    while (fgets(buffer, sizeof(buffer), fd))
    {
        if (strstr(buffer, library))
        {
            addr = strtoull(buffer, NULL, 16);
            break;
        }
    }

    fclose(fd);
    return addr;
}

void*
find_dlopen(int pid)
{
    unsigned long long remoteLib, localLib;
    void* dlopenAddr = NULL;
    void* handle = NULL;
    Dl_info info;
    const char* libraryName;

    handle = dlopen(LIBDL_NAME, RTLD_LAZY);
    if (handle == NULL)
    {
        printf("[!] Error opening %s\n", LIBDL_NAME);
        exit(1);
    }
    printf("[*] %s loaded at address %p\n", LIBDL_NAME, handle);

    dlopenAddr = dlsym(handle, "dlopen");
    if (dlopenAddr == NULL)
    {
        printf("[!] Error locating dlopen() function\n%s", dlerror());
        exit(1);
    }
    printf("[*] dlopen() found at address %p\n", dlopenAddr);

    if (!dladdr(dlopenAddr, &info) || info.dli_fname == NULL)
    {
        printf("[!] Could not discover shared object containing dlopen()\n");
        exit(1);
    }
    libraryName = info.dli_fname;
    printf("[*] dlopen() is in %s\n", libraryName);

    remoteLib = findLibrary(libraryName, pid);
    if (remoteLib == 0)
    {
        printf("[!] Could not find %s in target process %d\n", libraryName, pid);
        exit(1);
    }
    printf("[*] %s located in PID %d at address %p\n", libraryName, pid, (void*)remoteLib);

    localLib = findLibrary(libraryName, -1);
    if (localLib == 0)
    {
        printf("[!] Could not find %s in our process\n", libraryName);
        exit(1);
    }

    dlopenAddr = (void*)(remoteLib + ((unsigned long long)dlopenAddr - localLib));
    printf("[*] dlopen() offset in %s found to be 0x%llx bytes\n", libraryName,
           (unsigned long long)((unsigned long long)dlopenAddr - remoteLib));
    printf("[*] dlopen() in target process at address 0x%llx\n", (unsigned long long)dlopenAddr);
    return dlopenAddr;
}

void*
freeSpaceAddr(pid_t pid)
{
    FILE* fp;
    char filename[30];
    char line[850];
    unsigned long start;
    char perms[5];

    sprintf(filename, "/proc/%d/maps", pid);
    if ((fp = fopen(filename, "r")) == NULL)
    {
        printf("[!] Error, could not open maps file for process %d\n", pid);
        exit(1);
    }

    while (fgets(line, sizeof(line), fp) != NULL)
    {
        unsigned long dummy;
        if (sscanf(line, "%lx-%lx %4s", &start, &dummy, perms) != 3)
            continue;

        if (strchr(perms, 'x') != NULL)
        {
            break;
        }
    }

    fclose(fp);
    return (void*)start;
}

int
attachAll(pid_t pid, pid_t* tids, int max_tids)
{
    char taskPath[64];
    DIR* taskDir;
    struct dirent* entry;
    int count = 0;
    int status;

    snprintf(taskPath, sizeof(taskPath), "/proc/%d/task", pid);
    taskDir = opendir(taskPath);
    if (!taskDir)
    {
        perror("[!] opendir task");
        exit(1);
    }

    while ((entry = readdir(taskDir)) != NULL)
    {
        if (entry->d_name[0] == '.')
            continue;

        pid_t tid = atoi(entry->d_name);
        if (tid <= 0)
            continue;

        if (count >= max_tids)
            break;

        if (ptrace(PTRACE_ATTACH, tid, NULL, NULL) == -1)
        {
            perror("[!] PTRACE_ATTACH");
            closedir(taskDir);
            exit(1);
        }

        waitpid(tid, &status, __WALL | WUNTRACED);
        tids[count++] = tid;
    }

    closedir(taskDir);
    return count;
}

void
detachAll(pid_t* tids, int count)
{
    int i;

    for (i = 0; i < count; i++)
    {
        ptrace(PTRACE_DETACH, tids[i], NULL, NULL);
    }
}

void
ptraceRead(int pid, unsigned long long addr, void* data, int len)
{
    long word;
    int i;
    char* ptr = (char*)data;

    for (i = 0; i < len; i += sizeof(word))
    {
        word = ptrace(PTRACE_PEEKTEXT, pid, addr + i, NULL);
        if (word == -1 && errno != 0)
        {
            printf("[!] Error reading process memory\n");
            exit(1);
        }
        memcpy(ptr + i, &word, sizeof(word));
    }
}

void
ptraceWrite(int pid, unsigned long long addr, void* data, int len)
{
    long word;
    int i;
    int remain;

    for (i = 0; i < len; i += sizeof(word))
    {
        remain = len - i;
        if (remain >= (int)sizeof(word))
        {
            memcpy(&word, (char*)data + i, sizeof(word));
        }
        else
        {
            long original = ptrace(PTRACE_PEEKTEXT, pid, addr + i, NULL);
            if (original == -1 && errno != 0)
            {
                printf("[!] Error reading process memory for partial write\n");
                exit(1);
            }
            word = original;
            memcpy((char*)&word, (char*)data + i, remain);
        }

        if (ptrace(PTRACE_POKETEXT, pid, addr + i, word) == -1)
        {
            printf("[!] Error writing to process memory\n");
            exit(1);
        }
    }
}

void
injectme(void) {
    asm("call *%rax\n"
        "int $0x03\n");
}

void
inject(int pid, void* dlopenAddr, char* lib_path)
{
    struct user_regs_struct oldregs, regs;
    pid_t tids[256];
    int thread_count;
    int status;
    unsigned char* oldcode;
    void* freeaddr;
    int lib_path_size = 0;
    int code_size;

    thread_count = attachAll(pid, tids, sizeof(tids) / sizeof(tids[0]));

    ptrace(PTRACE_GETREGS, pid, NULL, &oldregs);
    memcpy(&regs, &oldregs, sizeof(struct user_regs_struct));

    static const unsigned char inject_stub[] = { 0xFF, 0xD0, 0xCC };
    const int stub_size = sizeof(inject_stub);

    lib_path_size = strnlen(lib_path, 256) + 1;
    code_size = lib_path_size + 8 + stub_size;

    oldcode = malloc(code_size);
    if (!oldcode)
    {
        printf("[!] Failed to allocate backup buffer\n");
        exit(1);
    }

    freeaddr = freeSpaceAddr(pid);

    ptraceRead(pid, (unsigned long long) freeaddr, oldcode, code_size);

    ptraceWrite(pid, (unsigned long long) freeaddr, lib_path, lib_path_size);
    printf("Finished writing into memory\n");
    ptraceWrite(pid, (unsigned long long) freeaddr + lib_path_size,
        "\x90\x90\x90\x90\x90\x90\x90\x90", 8);
    printf("Finished writing into memory 2\n");
    ptraceWrite(pid, (unsigned long long) freeaddr + lib_path_size + 8,
        (void*)inject_stub, stub_size);
    printf("Finished writing into memory 3\n");

    // Update RIP to point to our code
    regs.rip = (unsigned long long) freeaddr + lib_path_size + 8;

    // Update RAX to point to dlopen()
    regs.rax = (unsigned long long) dlopenAddr;

    // Update RDI to point to our library name string
    regs.rdi = (unsigned long long) freeaddr;

    // Set RSI as RTLD_LAZY for the dlopen call
    regs.rsi = 2;			// RTLD_LAZY
    // Align RSP to 16 bytes before the call instruction
    regs.rsp &= ~0xFULL;
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);

    printf("Finished setting registers\n");
    // Continue execution
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    waitpid(pid, &status, WUNTRACED);
    printf("Finished PTRACE_CONT\n");

    if (WIFSTOPPED(status) && WSTOPSIG(status) != SIGTRAP)
    {
        printf("[!] Target stopped by signal %d\n", WSTOPSIG(status));
    }

    // Ensure that we are returned because of our int 0x3 trap
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
    {
        // Get process registers, indicating if the injection suceeded
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        if (regs.rax != 0x0)
        {
            printf("[*] Injected library loaded at address %p\n", (void*)regs.rax);
        }
        else
        {
            printf("[!] Library could not be injected\n");
            free(oldcode);
            detachAll(tids, thread_count);
            return;
        }

        //// Now We Restore The Application Back To It's Original State ////

        ptraceWrite(pid, (unsigned long long) freeaddr, oldcode, code_size);
        free(oldcode);

        // Set registers back to original value
        ptrace(PTRACE_SETREGS, pid, NULL, &oldregs);

        // Resume execution in original place
        detachAll(tids, thread_count);
    }
    else
    {
        if (WIFSTOPPED(status))
        {
            ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            printf("[!] Target stopped by signal %d at RIP 0x%llx, RAX 0x%llx, RDI 0x%llx, RSI 0x%llx\n",
                   WSTOPSIG(status), (unsigned long long)regs.rip,
                   (unsigned long long)regs.rax,
                   (unsigned long long)regs.rdi,
                   (unsigned long long)regs.rsi);
        }
        else if (WIFSIGNALED(status))
        {
            printf("[!] Target terminated by signal %d\n", WTERMSIG(status));
        }
        else if (WIFEXITED(status))
        {
            printf("[!] Target exited with status %d\n", WEXITSTATUS(status));
        }

        printf("[!] Fatal Error: Process stopped for unknown reason\n");
        free(oldcode);
        detachAll(tids, thread_count);
        exit(1);
    }
}

int
main(int argc, char** argv)
{
    void* dlopenAddr = NULL;
    pid_t pid;

    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <pid> <library.so>\n", argv[0]);
        return 1;
    }

    pid = atoi(argv[1]);
    if (pid <= 0)
    {
        fprintf(stderr, "[!] Invalid PID: %s\n", argv[1]);
        return 1;
    }

    dlopenAddr = find_dlopen(pid);
    inject(pid, dlopenAddr, argv[2]);
    return 0;
}
