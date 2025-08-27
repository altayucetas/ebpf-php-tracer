#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>

/*------------------------------------DEFINE------------------------------------------*/

#define MAX_CALLSTACK_DEPTH 8
#define MAX_FUNC_NAME_LEN 32
#define MAX_FUNCTIONS 32

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

#define MAX_SYSCALL 16

#define PROFILE_MODE 1111
#define MONITOR_MODE 5555
#define SANDBOX_MODE 9999

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

struct functions {
    char name[MAX_FUNC_NAME_LEN];
    int syscalls[MAX_SYSCALL];
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

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_FUNCTIONS);
    __type(key, u32);
    __type(value, struct functions);
} allowed_func_syscalls SEC(".maps");

/*------------------------------------RING BUFFERS-----------------------------------------*/

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} syscall_info SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256);
} sandbox_info SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 8);
} mode_info SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 256 * 1024);
} profile_info SEC(".maps");



/*------------------------------------HELPERS-----------------------------------------*/

int check_string(const char *str1, const char *str2, size_t n) {
    for(int i=0; i<n; i++) {
        if(str1[i] != str2[i])
            return -1;
    }
    return 0;
}

int check_sandbox_violation(int syscall_id, u64 pid_tgid) {
    struct callstack *stack;

    stack = bpf_map_lookup_elem(&func_stacks, &pid_tgid);
    if(!stack)
        return 0;

    if(stack->depth <= 0 || stack->depth > MAX_CALLSTACK_DEPTH)
        return 0;
    
    int current_depth = stack->depth - 1;
    if(current_depth < 0 || current_depth >= MAX_CALLSTACK_DEPTH)
        return 0;
    
    for(int i = 0; i < MAX_FUNCTIONS; i++) {
        struct functions *func;
        u32 key = i;
        func = bpf_map_lookup_elem(&allowed_func_syscalls, &key);
        if(!func)
            continue;

        if(check_string(func->name, stack->stack[current_depth], MAX_FUNC_NAME_LEN) == 0) {
            for(int j = 0; j < MAX_SYSCALL; j++) {
                if(func->syscalls[j] == syscall_id) {
                    return 1;
                }
                if(func->syscalls[j] == 0)
                    break;
            }
            bpf_printk("Sandbox violation: Function %s called syscall id %d\n", func->name, syscall_id);
            return 9;
        }
    }

    bpf_printk("Sandbox violation: %s called syscall id %d\n", stack->stack[current_depth], syscall_id);
    return 9;
}

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

    if(*mode == SANDBOX_MODE)
        if(check_sandbox_violation(syscall_id, pid_tgid) == 9) {
            int ret = bpf_send_signal(9);
            int current_depth = stack->depth - 1;
            struct syscall *sandbox_syscall;

            if(current_depth < 0 || current_depth >= MAX_CALLSTACK_DEPTH)
                return 0;

            sandbox_syscall = bpf_ringbuf_reserve(&sandbox_info, sizeof(*sandbox_syscall), 0);
            if (!sandbox_syscall) {
                bpf_printk("Failed to reserve space in sandbox syscall ring buffer\n");
                return 0;
            }
            sandbox_syscall->id = syscall_id;
            sandbox_syscall->pid = pid_tgid >> 32;
            __builtin_memcpy(sandbox_syscall->name, stack->stack[current_depth], MAX_FUNC_NAME_LEN);
            bpf_ringbuf_submit(sandbox_syscall, 0);
            return 0;
        }

    //#pragma unroll

    for(int i=0; i < stack->depth && i < MAX_CALLSTACK_DEPTH; i++) {
        if(i == stack->depth - 1) {
            syscall_buff = bpf_ringbuf_reserve(&syscall_info, sizeof(*syscall_buff), 0);
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


static long extract_profile_context(struct bpf_dynptr *dynptr, int *context) {
    
    struct functions *func;
    struct functions *temp_func = NULL;
    func = bpf_dynptr_data(dynptr, 0, sizeof(*func) * MAX_FUNCTIONS);
    if (!func)
        return 0;
    
    for(int i=0; i<MAX_FUNCTIONS; i++) {
        if(func[i].name[0] != '\0') {
            u32 key = i;
            bpf_map_update_elem(&allowed_func_syscalls, &key, &func[i], BPF_ANY);
            temp_func = bpf_map_lookup_elem(&allowed_func_syscalls, &key);
            if(!temp_func)
                continue;
            bpf_printk("Function: %s, Syscall ids: ", temp_func->name);
            for(int j=0; j<MAX_SYSCALL; j++) {
                if(func[i].syscalls[j] != 0) {
                    if(j != 0)
                        bpf_printk(", ");
                    bpf_printk("%d", temp_func->syscalls[j]);

                }
            }
            bpf_printk("\n");
        }
    }

    return 0;
}

/*------------------------------------PHP FUNCTIONS-----------------------------------------*/

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

    if(idx == 0) {
        int pro_val = 0;
        int profile_val = bpf_user_ringbuf_drain(&profile_info, extract_profile_context, &pro_val, 0);
    }

    stack->depth++;

    bpf_printk("Function %s entered, current depth: %d\n", function_name, stack->depth);

    int val = 0;
    int mode_id = bpf_user_ringbuf_drain(&mode_info, extract_context, &val, 0);

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