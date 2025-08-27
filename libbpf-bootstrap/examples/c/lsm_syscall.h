#ifndef LSM_SYSCALL_H
#define LSM_SYSCALL_H

/*------------------------------------DEFINE------------------------------------------*/

#define MAX_CALLSTACK_DEPTH 8
#define MAX_FUNC_NAME_LEN 32
#define MAX_FUNCTIONS 32
#define MAX_DETAILS_NAME_LEN 256
#define MAX_FILE_NAME_LEN 128
#define MAX_SYSCALL 16
#define MAX_PROG 100


#define SYSCALL_WRITE 1
#define SYSCALL_FORK 57
#define SYSCALL_SOCKET 41
#define SYSCALL_CONNECT 42
#define SYSCALL_BIND 49
#define SYSCALL_LISTEN 50
#define SYSCALL_EXECVE 59
#define SYSCALL_KILL 62
#define SYSCALL_UNAME 63
#define SYSCALL_RENAME 82
#define SYSCALL_RMDIR 84
#define SYSCALL_UNLINK 87
#define SYSCALL_CHMOD 90
#define SYSCALL_CHOWN 92
#define SYSCALL_OPENAT 257
#define SYSCALL_UNLINKAT 263
#define SYSCALL_PTRACE 101
#define SYSCALL_MMAP 9
#define SYSCALL_READ 0
#define SYSCALL_NEWFSTATAT 262


#define PROFILE_MODE 1111
#define MONITOR_MODE 5555
#define SANDBOX_MODE 9999


#define DEBUG_MODE 0
#define LSM_ENABLE 0


#define GET_MODE 0


#define VIOLATION 9

#define MAY_WRITE 0x2

/*------------------------------------STRUCTS-----------------------------------------*/


struct callstack {
    char stack[MAX_CALLSTACK_DEPTH][MAX_FUNC_NAME_LEN];
    int depth;
};

struct syscall {
    int id;
    char name[MAX_FUNC_NAME_LEN];
    int pid;
    char details[MAX_DETAILS_NAME_LEN];
};

struct function {
    char name[MAX_FUNC_NAME_LEN];
    struct syscall syscalls[MAX_SYSCALL];
    int syscall_count[MAX_SYSCALL];
    int depth;
};

struct mode {
    int mode_id;
};


#endif /* LSM_SYSCALL_H */