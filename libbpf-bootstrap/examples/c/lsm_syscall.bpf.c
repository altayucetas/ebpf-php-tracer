#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>
#include "lsm_syscall.h"

/*------------------------------------MAPS-----------------------------------------*/

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PROG);
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
    __type(value, struct function);
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
	__uint(max_entries, 256 * 1024);
} profile_info SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 8);
} mode_info SEC(".maps");

/*------------------------------------HELPERS-----------------------------------------*/

static __always_inline int check_string(const char *str1, const char *str2, size_t n) {
    for(int i=0; i<n; i++) {
        if(str1[i] != str2[i])
            return -1;
    }
    return 0;
}

int set_details(struct trace_event_raw_sys_enter *ctx, char *dest_syscall, int syscall_id) {
    if(!ctx || !dest_syscall)
        return -1;

    switch(syscall_id) {

        case SYSCALL_UNLINKAT:
        case SYSCALL_WRITE:
        case SYSCALL_OPENAT:
            bpf_probe_read_user_str(dest_syscall, MAX_DETAILS_NAME_LEN, (const char *)ctx->args[1]);
            break;
        
        case SYSCALL_UNLINK:
        case SYSCALL_EXECVE:
        case SYSCALL_CHMOD:
        case SYSCALL_CHOWN:
        case SYSCALL_RMDIR:
            bpf_probe_read_user_str(dest_syscall, MAX_DETAILS_NAME_LEN, (const char *)ctx->args[0]);
            break;

        case SYSCALL_RENAME: {
            char *first_argument = (char *)ctx->args[0];
            char *second_argument = (char *)ctx->args[1];
            int size_of_first_argument = 0;
            for(int i=0; i<MAX_FILE_NAME_LEN; i++) {
                char c;
                if(bpf_probe_read_user(&c, sizeof(c), &first_argument[i]) < 0)
                    break;
                if(c == '\0') {
                    size_of_first_argument = i + 1;
                    break;
                }
            }
            bpf_printk("Oldname size: %d\n", size_of_first_argument);
            bpf_probe_read_user_str(dest_syscall, size_of_first_argument, first_argument);
            bpf_probe_read_kernel_str(dest_syscall + size_of_first_argument - 1, 2, " ");
            bpf_probe_read_user_str(dest_syscall + size_of_first_argument, MAX_DETAILS_NAME_LEN - size_of_first_argument - 1, second_argument);
            break;
        }  


        default: {
            //bpf_printk("No parameters set for syscall id %d\n", syscall_id);
            __builtin_memset(dest_syscall, 0, MAX_DETAILS_NAME_LEN);
        }
    }

    return 0;
}

static __always_inline int check_sandbox_violation(int syscall_id, u64 pid_tgid) {
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
        struct function *func;
        u32 key = i;
        func = bpf_map_lookup_elem(&allowed_func_syscalls, &key);
        if(!func)
            continue;

        if(check_string(func->name, stack->stack[current_depth], MAX_FUNC_NAME_LEN) == 0) {
            for(int j = 0; j < MAX_SYSCALL; j++) {
                if(func->syscalls[j].id == syscall_id) {
                    return 1;
                }
                if(func->syscalls[j].id == 0)
                    break;
            }
            //bpf_printk("Sandbox violation: Function %s called syscall id %d\n", func->name, syscall_id);
            return VIOLATION;
        }
    }

    bpf_printk("Sandbox violation: %s called syscall id %d\n", stack->stack[current_depth], syscall_id);
    return VIOLATION;
}

static __always_inline int tracepoint_calls(struct trace_event_raw_sys_enter *ctx, int syscall_id) {

    u64 pid_tgid;
    struct callstack *stack;
    struct syscall *syscall_buff;
    struct task_struct *task;
    int *mode;
    int get_mode = GET_MODE;

    mode = bpf_map_lookup_elem(&configs, &get_mode);
    if (!mode)
        return 0;

    if(syscall_id == SYSCALL_EXECVE || syscall_id == SYSCALL_FORK 
       ) {
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
        if(check_sandbox_violation(syscall_id, pid_tgid) == VIOLATION) {
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
            return -EPERM;
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
            set_details(ctx, syscall_buff->details, syscall_id);
            //bpf_printk("Function %s at depth %d\n", stack->stack[i], i);
            bpf_ringbuf_submit(syscall_buff, 0);
        }
    }

    return 0;
}

static long extract_mode_context(struct bpf_dynptr *dynptr, int *context) {

    struct mode *mode;
    int get_mode = GET_MODE;
    mode = bpf_dynptr_data(dynptr, 0, sizeof(*mode));
    if (!mode)
        return 0;

    *context = mode->mode_id;

    //bpf_printk("Context value inside callback is: %d", *context);

    bpf_map_update_elem(&configs, &get_mode, &mode->mode_id, BPF_NOEXIST);
    /*int *val = bpf_map_lookup_elem(&configs, &get_mode);
    if(!val)
        return 0;

    bpf_printk("Context value updated in map is: %d", *val);*/

    return 0;
}

static long extract_profile_context(struct bpf_dynptr *dynptr, int *context) {

    struct function *func, *temp_func = NULL;
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
            
            //bpf_printk("Function: %s, Syscall ids: ", temp_func->name);
            for(int j=0; j<MAX_SYSCALL; j++) {
                if(func[i].syscalls[j].id != 0) {
                    if(j != 0)
                        bpf_printk(", ");
                    bpf_printk("%d", temp_func->syscalls[j].id);

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

    //bpf_printk("Function %s entered, current depth: %d\n", function_name, stack->depth);

    int val = 0;
    int mode_id = bpf_user_ringbuf_drain(&mode_info, extract_mode_context, &val, 0);

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

    //bpf_printk("Function %s returned, current depth: %d\n", function_name, stack->depth);

    return 0;
}


#if LSM_ENABLE == 0

/*------------------------------------SYSCALLS-----------------------------------------*/

SEC("tracepoint/syscalls/sys_enter_read")
int read(struct trace_event_raw_sys_enter *ctx) {
    int ret = tracepoint_calls(ctx, SYSCALL_READ);
    if(ret == -EPERM){
        int zero_size = 0;
        bpf_printk("Unauthorized read attempt detected and size zeroed");
        bpf_probe_write_user((int*)ctx->args[2], &zero_size, sizeof(zero_size));
    }
    return ret;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int openat(struct trace_event_raw_sys_enter *ctx) {
    int ret = tracepoint_calls(ctx, SYSCALL_OPENAT);
    if(ret == -EPERM){
        char dummy_file[] = "/dev/null";
        bpf_printk("Unauthorized openat attempt detected and redirected to /dev/null");
        bpf_probe_write_user((char*)ctx->args[1], dummy_file, sizeof(dummy_file));
    }
    return ret;
}

SEC("tracepoint/syscalls/sys_enter_write")
int write(struct trace_event_raw_sys_enter *ctx) {
    int ret = tracepoint_calls(ctx, SYSCALL_WRITE);
    if(ret == -EPERM){
        int zero_size = 0;
        bpf_printk("Unauthorized write attempt detected and size zeroed");
        bpf_probe_write_user((int*)ctx->args[2], &zero_size, sizeof(zero_size));
    }
    return ret;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int unlinkat(struct trace_event_raw_sys_enter *ctx) {
    int ret = tracepoint_calls(ctx, SYSCALL_UNLINKAT);
    if(ret == -EPERM){
        char dummy_file[] = "/tmp/dshakjhdkashdjka.txt";
        bpf_printk("Unauthorized unlink attempt detected and filename changed");
        bpf_probe_write_user((char*)ctx->args[1], dummy_file, sizeof(dummy_file));
    }
    return ret;
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int unlink(struct trace_event_raw_sys_enter *ctx) {
    int ret = tracepoint_calls(ctx, SYSCALL_UNLINK);
    if(ret == -EPERM){
        char dummy_file[] = "/tmp/dshakjhdkashdjka.txt";
        bpf_printk("Unauthorized unlink attempt detected and filename changed");
        bpf_probe_write_user((char*)ctx->args[0], dummy_file, sizeof(dummy_file));
    }
    return ret;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int execve(struct trace_event_raw_sys_enter *ctx) {
    int ret = tracepoint_calls(ctx, SYSCALL_EXECVE);
    if(ret == -EPERM){
        char dummy_file[] = "/bin/true";
        bpf_printk("Unauthorized execve attempt detected and filename changed");
        bpf_probe_write_user((char*)ctx->args[0], dummy_file, sizeof(dummy_file));
    }
    return ret;
}

SEC("tracepoint/syscalls/sys_enter_fork")
int fork(struct trace_event_raw_sys_enter *ctx) {
    return tracepoint_calls(ctx, SYSCALL_FORK);
}

SEC("tracepoint/syscalls/sys_enter_chmod")
int chmod(struct trace_event_raw_sys_enter *ctx) {
    int ret = tracepoint_calls(ctx, SYSCALL_CHMOD);
    if(ret == -EPERM){
        char dummy_file[] = "/tmp/dshakjhdkashdjka.txt";
        bpf_printk("Unauthorized chmod attempt detected and filename changed");
        bpf_probe_write_user((char*)ctx->args[0], dummy_file, sizeof(dummy_file));
    }
    return ret;
}

SEC("tracepoint/syscalls/sys_enter_chown")
int chown(struct trace_event_raw_sys_enter *ctx) {
    int ret = tracepoint_calls(ctx, SYSCALL_CHOWN);
    if(ret == -EPERM){
        char dummy_file[] = "/tmp/dshakjhdkashdjka.txt";
        bpf_printk("Unauthorized chown attempt detected and filename changed");
        bpf_probe_write_user((char*)ctx->args[0], dummy_file, sizeof(dummy_file));
    }
    return ret;
}

SEC("tracepoint/syscalls/sys_enter_rename")
int rename(struct trace_event_raw_sys_enter *ctx) {
    int ret = tracepoint_calls(ctx, SYSCALL_RENAME);
    if(ret == -EPERM){
        char dummy_file[] = "/tmp/dshakjhdkashdjka.txt";
        bpf_printk("Unauthorized rename attempt detected and filename changed");
        bpf_probe_write_user((char*)ctx->args[0], dummy_file, sizeof(dummy_file));
        bpf_probe_write_user((char*)ctx->args[1], dummy_file, sizeof(dummy_file));
    }
    return ret;
}

SEC("tracepoint/syscalls/sys_enter_rmdir")
int rmdir(struct trace_event_raw_sys_enter *ctx) {
    int ret = tracepoint_calls(ctx, SYSCALL_RMDIR);
    if(ret == -EPERM){
        char dummy_file[] = "/tmp/dshakjhdkashdjka";
        bpf_printk("Unauthorized rmdir attempt detected and filename changed");
        bpf_probe_write_user((char*)ctx->args[0], dummy_file, sizeof(dummy_file));
    }
    return ret;
}

SEC("tracepoint/syscalls/sys_enter_newuname")
int uname(struct trace_event_raw_sys_enter *ctx) {
    return tracepoint_calls(ctx, SYSCALL_UNAME);
}

SEC("tracepoint/syscalls/sys_enter_socket")
int socket(struct trace_event_raw_sys_enter *ctx) {
    int ret = tracepoint_calls(ctx, SYSCALL_SOCKET);
    if(ret == -EPERM){
        int zero_domain = 0;
        bpf_printk("Unauthorized socket attempt detected and domain zeroed");
        bpf_probe_write_user((int*)ctx->args[0], &zero_domain, sizeof(zero_domain));
    }
    return ret;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int connect(struct trace_event_raw_sys_enter *ctx) {
    int ret = tracepoint_calls(ctx, SYSCALL_CONNECT);
    if(ret == -EPERM){
        int zero_len = 0;
        bpf_printk("Unauthorized connect attempt detected and address length zeroed");
        bpf_probe_write_user((int*)ctx->args[2], &zero_len, sizeof(zero_len));
    }
    return ret;
}

SEC("tracepoint/syscalls/sys_enter_bind")
int bind(struct trace_event_raw_sys_enter *ctx) {
    int ret = tracepoint_calls(ctx, SYSCALL_BIND);
    if(ret == -EPERM){
        int zero_size = 0;
        bpf_printk("Unauthorized bind attempt detected and address length zeroed");
        bpf_probe_write_user((int*)ctx->args[2], &zero_size, sizeof(zero_size));
    }
    return ret;
}

SEC("tracepoint/syscalls/sys_enter_listen")
int listen(struct trace_event_raw_sys_enter *ctx) {
    int ret = tracepoint_calls(ctx, SYSCALL_LISTEN);
    if(ret == -EPERM){
        int backlog = 0;
        bpf_printk("Unauthorized listen attempt detected and backlog set to 0");
        bpf_probe_write_user((int*)ctx->args[1], &backlog, sizeof(backlog));
    }
    return ret;
}

SEC("tracepoint/syscalls/sys_enter_kill")
int kill(struct trace_event_raw_sys_enter *ctx) {
    int ret = tracepoint_calls(ctx, SYSCALL_KILL);
    if(ret == -EPERM){
        int signal = 99999;
        bpf_printk("Unauthorized kill attempt detected and signal changed to invalid");
        bpf_probe_write_user((int*)ctx->args[1], &signal, sizeof(signal));
    }
    return ret;
}

SEC("tracepoint/syscalls/sys_enter_mmap")
int mmap(struct trace_event_raw_sys_enter *ctx) {
    int ret = tracepoint_calls(ctx, SYSCALL_MMAP);
    if(ret == -EPERM){
        int zero_size = 0;
        bpf_probe_write_user((int*)ctx->args[1], &zero_size, sizeof(zero_size));
        bpf_printk("Unauthorized mmap detected and length zeroed");
    }
    return ret;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int ptrace(struct trace_event_raw_sys_enter *ctx) {
    int ret = tracepoint_calls(ctx, SYSCALL_PTRACE);
    if(ret == -EPERM){
        int pid = 999999;
        bpf_probe_write_user((int*)ctx->args[0], &pid, sizeof(pid));
        bpf_printk("Unauthorized ptrace attempt detected and pid changed");
    }
    return ret;
}

SEC("tracepoint/syscalls/sys_enter_newfstatat")
int newfstatat(struct trace_event_raw_sys_enter *ctx) {
    int ret = tracepoint_calls(ctx, SYSCALL_NEWFSTATAT);
    if(ret == -EPERM){
        char dummy_file[] = "/tmp/dshakjhdkashdjka.txt";
        bpf_probe_write_user((char*)ctx->args[0], dummy_file, sizeof(dummy_file));
        bpf_printk("Unauthorized newfstatat attempt detected and filename changed");
    }
    return ret;
}

#else

/*------------------------------------LSM HOOKS-----------------------------------------*/

SEC("lsm/path_unlink")
int BPF_PROG(restrict_unlink, struct path *dir, struct dentry *dentry) {
    int ret_val = tracepoint_calls(SYSCALL_UNLINK);
    if (ret_val == -EPERM) {
        bpf_printk("Return value:: %d, and -EPERM: %d\n", ret_val, -EPERM);
        return -EPERM;
    }
        
    return 0;
}

SEC("lsm/path_rmdir")
int BPF_PROG(restrict_rmdir, struct path *dir, struct dentry *dentry) {
    int ret_val = tracepoint_calls(SYSCALL_RMDIR);
    if (ret_val == -EPERM) {
        bpf_printk("Return value:: %d, and -EPERM: %d\n", ret_val, -EPERM);
        return -EPERM;
    }
        
    return 0;
}

SEC("lsm/path_rename")
int BPF_PROG(restrict_rename, struct path *old_dir, struct dentry *old_dentry,
             struct path *new_dir, struct dentry *new_dentry) {
    int ret_val = tracepoint_calls(SYSCALL_RENAME);
    if (ret_val == -EPERM) {
        bpf_printk("Return value:: %d, and -EPERM: %d\n", ret_val, -EPERM);
        return -EPERM;
    }
        
    return 0;
}

SEC("lsm/path_chmod") // Sadece dosya mevcutsa syscall'ı algılıyor
int BPF_PROG(restrict_chmod, const struct path *path, umode_t mode) {
    bpf_printk("In chmod LSM hook\n");
    int ret_val = tracepoint_calls(SYSCALL_CHMOD);
    if (ret_val == -EPERM) {
        bpf_printk("Return value:: %d, and -EPERM: %d\n", ret_val, -EPERM);
        return -EPERM;
    }
        
    return 0;
}

SEC("lsm/path_chown")
int BPF_PROG(restrict_chown, const struct path *path, u32 uid, u32 gid) {
    int ret_val = tracepoint_calls(SYSCALL_CHOWN);   
    if (ret_val == -EPERM) {
        bpf_printk("Return value:: %d, and -EPERM: %d\n", ret_val, -EPERM);
        return -EPERM;
    }
       
    return 0;
}

SEC("lsm/socket_create")
int BPF_PROG(restrict_socket, int family, int type, int protocol, int kern) {
    int ret_val = tracepoint_calls(SYSCALL_SOCKET);
    if (ret_val == -EPERM) {
        bpf_printk("socket_create: ret_val=%d, -EPERM=%d\n", ret_val, -EPERM);
        return -EPERM;
    }
        
    return 0;
}

SEC("lsm/socket_bind")
int BPF_PROG(restrict_bind, struct socket *sock, struct sockaddr *address, int addrlen) {
    int ret_val = tracepoint_calls(SYSCALL_BIND);
    if (ret_val == -EPERM) {
        bpf_printk("socket_bind: ret_val=%d, -EPERM=%d\n", ret_val, -EPERM);
        return -EPERM;
    }

    return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(restrict_connect, struct socket *sock, struct sockaddr *address, int addrlen) {
    int ret_val = tracepoint_calls(SYSCALL_CONNECT);
    if (ret_val == -EPERM) {
        bpf_printk("socket_connect: ret_val=%d, -EPERM=%d\n", ret_val, -EPERM);
        return -EPERM;
    }
        
    return 0;
}

SEC("lsm/socket_listen")
int BPF_PROG(restrict_listen, struct socket *sock, int backlog) {
    int ret_val = tracepoint_calls(SYSCALL_LISTEN);
    if (ret_val == -EPERM) {
        bpf_printk("socket_listen: ret_val=%d, -EPERM=%d\n", ret_val, -EPERM);
        return -EPERM;
    }
        
    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(restrict_open, struct file *file) {
    int ret_val = tracepoint_calls(SYSCALL_OPENAT);
    if (ret_val == -EPERM) {
        bpf_printk("file_open: ret_val=%d, -EPERM=%d\n", ret_val, -EPERM);
        return -EPERM;
    }

    return 0;
}

SEC("lsm/file_permission")
int BPF_PROG(restrict_write, struct file *file, int mask) {
    if (mask & MAY_WRITE) {
        int ret_val = tracepoint_calls(SYSCALL_WRITE);
        if (ret_val == -EPERM) {
            bpf_printk("file_write: ret_val=%d, -EPERM=%d\n", ret_val, -EPERM);
            return -EPERM;
        }           
    }

    return 0;
}

SEC("lsm/task_alloc")
int BPF_PROG(restrict_task_alloc, struct task_struct *task, unsigned long clone_flags) {
    int ret_val = tracepoint_calls(SYSCALL_FORK);
    if (ret_val == -EPERM) {
        bpf_printk("task_alloc: ret_val=%d, -EPERM=%d\n", ret_val, -EPERM);
        return -EPERM;
    }
    return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(restrict_execve, struct linux_binprm *bprm) {
    int ret_val = tracepoint_calls(SYSCALL_EXECVE);
    if (ret_val == -EPERM) {
        bpf_printk("bprm_check_security: ret_val=%d, -EPERM=%d\n", ret_val, -EPERM);
        return -EPERM;
    }
        
    return 0;
}

SEC("lsm/task_kill") // Sadece pid mevcutsa syscall'ı algılıyor
int BPF_PROG(restrict_kill, struct task_struct *p, struct kernel_siginfo *info,
             int sig, const struct cred *cred) {
    int ret_val = tracepoint_calls(SYSCALL_KILL);
    if (ret_val == -EPERM) {
        bpf_printk("task_kill: ret_val=%d, -EPERM=%d\n", ret_val, -EPERM);
        return -EPERM;
    }
        
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_newuname")
int trace_uname_enter(struct trace_event_raw_sys_enter* ctx) {
    int ret_val = tracepoint_calls(SYSCALL_UNAME);
    if (ret_val == -EPERM) {
        bpf_printk("uname: ret_val=%d, -EPERM=%d\n", ret_val, -EPERM);
        return -EPERM;
    }
        
    return 0;
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(restrict_ptrace, struct task_struct *child, unsigned int mode) {
    int ret_val = tracepoint_calls(SYSCALL_PTRACE);
    if (ret_val == -EPERM) {
        bpf_printk("ptrace_access_check: ret_val=%d, -EPERM=%d\n", ret_val, -EPERM);
        return -EPERM;
    }
    return 0;
}

SEC("lsm/mmap_addr")
int BPF_PROG(restrict_mmap, unsigned long addr) {
    int ret_val = tracepoint_calls(SYSCALL_MMAP);
    if (ret_val == -EPERM) {
        bpf_printk("mmap_addr: ret_val=%d, -EPERM=%d\n", ret_val, -EPERM);
        return -EPERM;
    }
    return 0;
}

SEC("lsm/inode_permission")
int BPF_PROG(restrict_newfstatat, struct inode *inode, int mask) {
    int ret_val = tracepoint_calls(SYSCALL_NEWFSTATAT);
    if (ret_val == -EPERM) {
        bpf_printk("inode_permission: ret_val=%d, -EPERM=%d\n", ret_val, -EPERM);
        return -EPERM;
    }
    return 0;
}

#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";