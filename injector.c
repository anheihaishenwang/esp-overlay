#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <stdint.h>

#define TARGET_PKG "com.tencent.tmgp.sgame"
#define HOOK_LIB_PATH "/data/local/tmp/libviewheight_hook.so"

pid_t find_pid(const char *pkg) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "pidof %s", pkg);
    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;
    pid_t pid = -1;
    fscanf(fp, "%d", &pid);
    pclose(fp);
    return pid;
}

uintptr_t get_module_base(pid_t pid, const char *name) {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *fp = fopen(maps_path, "r");
    if (!fp) return 0;
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, name) && strstr(line, "r-xp")) {
            uintptr_t start;
            sscanf(line, "%lx", &start);
            fclose(fp);
            return start;
        }
    }
    fclose(fp);
    return 0;
}

int inject_so(pid_t pid, const char *so_path) {
    // Find libc.so base in target
    uintptr_t libc_base = get_module_base(pid, "libc.so");
    if (!libc_base) {
        fprintf(stderr, "[!] Cannot find libc.so in target\n");
        return -1;
    }

    // Find dlopen offset in local libc
    void *local_libc = dlopen("libc.so", RTLD_NOW);
    void *local_dlopen = dlsym(local_libc, "dlopen");
    uintptr_t dlopen_offset = (uintptr_t)local_dlopen - (uintptr_t)local_libc;
    uintptr_t remote_dlopen = libc_base + dlopen_offset;
    dlclose(local_libc);

    printf("[+] libc base: 0x%lx, dlopen: 0x%lx\n", libc_base, remote_dlopen);

    // Write so_path to target memory using process_vm_writev
    char *path_copy = strdup(so_path);
    size_t path_len = strlen(so_path) + 1;
    
    // Find writable anon region
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *fp = fopen(maps_path, "r");
    if (!fp) { free(path_copy); return -1; }
    
    uintptr_t remote_addr = 0;
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "rw-p") && strstr(line, "[anon]")) {
            uintptr_t start, end;
            sscanf(line, "%lx-%lx", &start, &end);
            if (end - start >= 4096) {
                remote_addr = start;
                break;
            }
        }
    }
    fclose(fp);
    if (!remote_addr) { free(path_copy); return -1; }

    printf("[+] Writing path to 0x%lx\n", remote_addr);

    struct iovec local_iov = { .iov_base = path_copy, .iov_len = path_len };
    struct iovec remote_iov = { .iov_base = (void*)remote_addr, .iov_len = path_len };
    ssize_t written = process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0);
    free(path_copy);
    if (written != path_len) {
        perror("process_vm_writev path");
        return -1;
    }

    // Prepare registers for dlopen call
    // We'll use ptrace to set up the call
    struct user_pt_regs {
        uint64_t regs[31];
        uint64_t sp;
        uint64_t pc;
        uint64_t pstate;
    } regs;

    struct iovec reg_iov = { .iov_base = &regs, .iov_len = sizeof(regs) };
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &reg_iov) == -1) {
        perror("GETREGSET");
        return -1;
    }

    // Save original regs
    struct user_pt_regs orig_regs = regs;

    // Set up dlopen(so_path, RTLD_NOW)
    regs.regs[0] = remote_addr;  // x0 = path
    regs.regs[1] = 2;            // x1 = RTLD_NOW
    regs.pc = remote_dlopen;

    if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &reg_iov) == -1) {
        perror("SETREGSET");
        return -1;
    }

    // Execute
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
        perror("CONT");
        return -1;
    }
    int status;
    waitpid(pid, &status, 0);

    // Get result
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &reg_iov) == -1) {
        perror("GETREGSET after");
    }
    uintptr_t handle = regs.regs[0];
    printf("[+] dlopen returned: 0x%lx\n", handle);

    // Restore registers
    ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &orig_regs);
    
    return handle ? 0 : -1;
}

int call_set_height(pid_t pid, float height) {
    // Find the hook library base in target
    uintptr_t hook_base = get_module_base(pid, "libviewheight_hook.so");
    if (!hook_base) {
        fprintf(stderr, "[!] Hook library not loaded in target\n");
        return -1;
    }

    // Find set_target_height offset locally
    void *local_handle = dlopen(HOOK_LIB_PATH, RTLD_NOW);
    if (!local_handle) {
        fprintf(stderr, "[!] Cannot dlopen local hook: %s\n", dlerror());
        return -1;
    }
    void *local_func = dlsym(local_handle, "set_target_height");
    if (!local_func) {
        fprintf(stderr, "[!] Cannot find set_target_height: %s\n", dlerror());
        dlclose(local_handle);
        return -1;
    }
    uintptr_t offset = (uintptr_t)local_func - (uintptr_t)local_handle;
    uintptr_t remote_func = hook_base + offset;
    dlclose(local_handle);

    printf("[+] Hook base: 0x%lx, set_target_height: 0x%lx\n", hook_base, remote_func);

    // Read the function to verify
    struct iovec local_iov = { .iov_base = malloc(16), .iov_len = 16 };
    struct iovec remote_iov = { .iov_base = (void*)remote_func, .iov_len = 16 };
    process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
    printf("[+] Function bytes: ");
    for (int i = 0; i < 16; i++) printf("%02x ", ((uint8_t*)local_iov.iov_base)[i]);
    printf("\n");
    free(local_iov.iov_base);

    // Prepare registers for call
    struct user_pt_regs {
        uint64_t regs[31];
        uint64_t sp;
        uint64_t pc;
        uint64_t pstate;
    } regs;

    struct iovec reg_iov = { .iov_base = &regs, .iov_len = sizeof(regs) };
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &reg_iov) == -1) return -1;

    struct user_pt_regs orig_regs = regs;

    // ARM64: float in x0 (lower 32 bits)
    uint32_t height_bits;
    memcpy(&height_bits, &height, sizeof(float));
    regs.regs[0] = height_bits;
    regs.pc = remote_func;

    if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &reg_iov) == -1) return -1;
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) return -1;
    
    int status;
    waitpid(pid, &status, 0);
    
    ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &orig_regs);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <height>\n", argv[0]);
        return 1;
    }

    float height = atof(argv[1]);
    pid_t pid = find_pid(TARGET_PKG);
    if (pid <= 0) {
        fprintf(stderr, "[!] Game not running\n");
        return 1;
    }
    printf("[+] Found game PID: %d\n", pid);
    printf("[+] Target height: %.1f\n", height);

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ATTACH");
        return 1;
    }
    int status;
    waitpid(pid, &status, 0);

    int result = 0;
    if (inject_so(pid, HOOK_LIB_PATH) == 0) {
        if (call_set_height(pid, height) == 0) {
            printf("[+] Height set successfully!\n");
        } else {
            result = 1;
        }
    } else {
        result = 1;
    }

    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return result;
}
