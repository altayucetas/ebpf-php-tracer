#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>

/*------------------------------------DEFINE------------------------------------------*/

#define MAX_CALLSTACK_DEPTH 8
#define MAX_FUNC_NAME_LEN 32

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

#define GET_MODE 0

/*------------------------------------STRUCTS-----------------------------------------*/

struct callstack { // 260 byte
    char stack[MAX_CALLSTACK_DEPTH][MAX_FUNC_NAME_LEN];
    int depth;
};

struct syscall { // 44 byte
    int id;
    char name[MAX_FUNC_NAME_LEN];
    int pid;
};

struct mode { // 4 byte
    int mode_id;
};

/*------------------------------------MAPS-----------------------------------------*/

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, struct callstack);
} func_stacks SEC(".maps");

/*
    0 for GET_MODE
*/

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, int);
} configs SEC(".maps");

/*------------------------------------RING BUFFERS-----------------------------------------*/

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ring_buff SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 8);
} user_ringbuf SEC(".maps");

/*------------------------------------HELPERS-----------------------------------------*/

int tracepoint_calls(int syscall_id) {

    u64 pid_tgid;
    struct callstack *stack;
    struct syscall *syscall_buff;
    struct task_struct *task;
    int *mode;
    int get_mode = GET_MODE;

    mode = bpf_map_lookup_elem(&configs, &get_mode);
    if (!mode)
        return 0;

    if(syscall_id == SYSCALL_EXECVE) {
        task = (struct task_struct *)bpf_get_current_task();
        if (!task)
            return 0;
        u32 parent_tgid = BPF_CORE_READ(task, real_parent, tgid);
        u32 parent_pid = BPF_CORE_READ(task, real_parent, pid);
        pid_tgid = (u64)parent_tgid << 32;
        pid_tgid += parent_pid;
    } else {
        pid_tgid = bpf_get_current_pid_tgid();
    }
    
    stack = bpf_map_lookup_elem(&func_stacks, &pid_tgid);
    if(!stack)
        return 0;

    /*if(syscall_id == SYSCALL_EXECVE) {
        bpf_printk("Execve called by pid: %d, and %d\n", pid_tgid, bpf_get_current_pid_tgid()>>32);
    }*/

    //#pragma unroll

    for(int i=0; i < stack->depth && i < MAX_CALLSTACK_DEPTH; i++) {
        if(i == stack->depth - 1) {
            syscall_buff = bpf_ringbuf_reserve(&ring_buff, sizeof(*syscall_buff), 0);
            if(!syscall_buff){
                bpf_printk("Failed to reserve space in ring buffer\n");
                return 0;
            }
            syscall_buff->id = syscall_id;
            syscall_buff->pid = bpf_get_current_pid_tgid() >> 32;
            bpf_probe_read_kernel_str(syscall_buff->name, MAX_FUNC_NAME_LEN, stack->stack[i]);
            bpf_printk("Function %s at depth %d\n", stack->stack[i], i);
            //__builtin_memcpy(syscall_buff->name, stack->stack[i], MAX_FUNC_NAME_LEN);
            bpf_ringbuf_submit(syscall_buff, 0);
        }
    }

    return 0;
}

static long extract_context(struct bpf_dynptr *dynptr, int *context) {

    struct mode *mode;
    int get_mode = GET_MODE;
    mode = bpf_dynptr_data(dynptr, 0, sizeof(*mode));
    if (!mode)
        return 0;

    *context = mode->mode_id;

    bpf_printk("Context value inside callback is: %d", *context);

    bpf_map_update_elem(&configs, &get_mode, &mode->mode_id, BPF_NOEXIST);
    /*int *val = bpf_map_lookup_elem(&configs, &get_mode);
    if(!val)
        return 0;

    bpf_printk("Context value updated in map is: %d", *val);*/

    return 0;
}


/*------------------------------------PHP FUNCTIONS-----------------------------------------*/


//SEC("usdt//usr/local/php83/bin/php:php:function__entry")
SEC("usdt//root/Tools/php/bin/php:php:function__entry")
int BPF_USDT(fentry, char *function_name, char *request_file, int lineno, char *classname, char *scope){

    struct callstack *stack = NULL;
    u64 pid_tgid;
    int idx;

    pid_tgid = bpf_get_current_pid_tgid();

    struct callstack temp_stack = {0};
    bpf_map_update_elem(&func_stacks, &pid_tgid, &temp_stack, BPF_NOEXIST);
    stack = bpf_map_lookup_elem(&func_stacks, &pid_tgid);
    if(!stack)
        return 0;

    idx = stack->depth;

    if(idx < 0 || idx >= MAX_CALLSTACK_DEPTH) {
        bpf_printk("Invalid stack depth: %d\n", idx);
        return 0;
    }

    bpf_probe_read_user_str(stack->stack[idx], MAX_FUNC_NAME_LEN, function_name);

    stack->depth++;

    bpf_printk("Function %s entered, current depth: %d\n", function_name, stack->depth);

    int val = 0;
    int mode_id = bpf_user_ringbuf_drain(&user_ringbuf, extract_context, &val, 0);
    //bpf_printk("Mode ID received: %d, val is : %d\n", mode_id, val);

    return 0;
}

SEC("usdt//root/Tools/php/bin/php:php:function__return")
int BPF_USDT(fexit, char *function_name, char *request_file, int lineno, char *classname, char *scope){
    
    struct callstack *stack = NULL;
    u64 pid_tgid;

    pid_tgid = bpf_get_current_pid_tgid();

    stack = bpf_map_lookup_elem(&func_stacks, &pid_tgid);
    if(!stack) {
        return 0;
    }

    if(stack->depth > 0 && stack->depth <= MAX_CALLSTACK_DEPTH) {
        stack->depth--;
        __builtin_memset(stack->stack[stack->depth], 0, MAX_FUNC_NAME_LEN);
    }

    bpf_printk("Function %s returned, current depth: %d\n", function_name, stack->depth);

    return 0;
}


/*------------------------------------SYSCALLS-----------------------------------------*/

SEC("tracepoint/syscalls/sys_enter_openat")
int openat(struct trace_event_raw_sys_enter *ctx) {
    return tracepoint_calls(SYSCALL_OPENAT);
}

SEC("tracepoint/syscalls/sys_enter_write")
int write(struct trace_event_raw_sys_enter *ctx) {
    return tracepoint_calls(SYSCALL_WRITE);
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int unlinkat(struct trace_event_raw_sys_enter *ctx) {
    return tracepoint_calls(SYSCALL_UNLINKAT);
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int unlink(struct trace_event_raw_sys_enter *ctx) {
    return tracepoint_calls(SYSCALL_UNLINK);
}

SEC("tracepoint/syscalls/sys_enter_execve")
int execve(struct trace_event_raw_sys_enter *ctx) {
    return tracepoint_calls(SYSCALL_EXECVE);
}

SEC("tracepoint/syscalls/sys_enter_fork")
int fork(struct trace_event_raw_sys_enter *ctx) {
    return tracepoint_calls(SYSCALL_FORK);
}

SEC("tracepoint/syscalls/sys_enter_chmod")
int chmod(struct trace_event_raw_sys_enter *ctx) {
    return tracepoint_calls(SYSCALL_CHMOD);
}

SEC("tracepoint/syscalls/sys_enter_chown")
int chown(struct trace_event_raw_sys_enter *ctx) {
    return tracepoint_calls(SYSCALL_CHOWN);
}

SEC("tracepoint/syscalls/sys_enter_rename")
int rename(struct trace_event_raw_sys_enter *ctx) {
    return tracepoint_calls(SYSCALL_RENAME);
}

SEC("tracepoint/syscalls/sys_enter_rmdir")
int rmdir(struct trace_event_raw_sys_enter *ctx) {
    return tracepoint_calls(SYSCALL_RMDIR);
}

SEC("tracepoint/syscalls/sys_enter_newuname")
int uname(struct trace_event_raw_sys_enter *ctx) {
    return tracepoint_calls(SYSCALL_UNAME);
}

SEC("tracepoint/syscalls/sys_enter_socket")
int socket(struct trace_event_raw_sys_enter *ctx) {
    return tracepoint_calls(SYSCALL_SOCKET);
}

SEC("tracepoint/syscalls/sys_enter_connect")
int connect(struct trace_event_raw_sys_enter *ctx) {
    return tracepoint_calls(SYSCALL_CONNECT);
}

SEC("tracepoint/syscalls/sys_enter_bind")
int bind(struct trace_event_raw_sys_enter *ctx) {
    return tracepoint_calls(SYSCALL_BIND);
}

SEC("tracepoint/syscalls/sys_enter_listen")
int listen(struct trace_event_raw_sys_enter *ctx) {
    return tracepoint_calls(SYSCALL_LISTEN);
}

SEC("tracepoint/syscalls/sys_enter_kill")
int kill(struct trace_event_raw_sys_enter *ctx) {
    return tracepoint_calls(SYSCALL_KILL);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";