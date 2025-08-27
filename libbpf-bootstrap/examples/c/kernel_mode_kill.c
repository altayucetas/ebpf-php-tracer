#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "kernel_mode_kill.skel.h"

/*------------------------------------DEFINES------------------------------------------*/

#define MAX_CALLSTACK_DEPTH 8
#define MAX_FUNC_NAME_LEN 32

#define MAX_SYSCALL 16
#define MAX_FUNCTIONS 32

#define DEBUG_MODE 0

#define PROFILE_MODE 1111
#define MONITOR_MODE 5555
#define SANDBOX_MODE 9999

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

/*------------------------------------STRUCTS-----------------------------------------*/

struct callstack {
    char stack[MAX_CALLSTACK_DEPTH][MAX_FUNC_NAME_LEN];
    int depth;
};

struct syscall { // 44 byte
    int id;
    char name[MAX_FUNC_NAME_LEN];
    int pid;
};

struct functions {
    char name[MAX_FUNC_NAME_LEN];
    int syscalls[MAX_SYSCALL];
};

struct mode {
    int mode_id;
};

/*------------------------------------GLOBAL VARIABLES---------------------------------*/

struct functions all_funcs[MAX_FUNCTIONS] = {0};
struct functions sandbox_funcs[MAX_FUNCTIONS] = {0};

char *syscall_names[] = {
    "write", "fork", "socket", "connect", "bind", "listen", "execve", "kill",
    "uname", "rename", "rmdir", "unlink", "chmod", "chown", "openat", "unlinkat"
};

struct mode *mode;

FILE *monitor_file;

/*------------------------------------HELPERS-----------------------------------------*/

static volatile sig_atomic_t exiting;

static void sig_int(int signo) {
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
	return vfprintf(stderr, format, args);
}

int syscall_arr_index(int id) {
    switch(id) {
        case SYSCALL_WRITE:
            return 0;
        case SYSCALL_FORK:
            return 1;
        case SYSCALL_SOCKET:
            return 2;
        case SYSCALL_CONNECT:
            return 3;
        case SYSCALL_BIND:
            return 4;
        case SYSCALL_LISTEN:
            return 5;
        case SYSCALL_EXECVE:
            return 6;
        case SYSCALL_KILL:
            return 7;
        case SYSCALL_UNAME:
            return 8;
        case SYSCALL_RENAME:
            return 9;
        case SYSCALL_RMDIR:
            return 10;
        case SYSCALL_UNLINK:
            return 11;
        case SYSCALL_CHMOD:
            return 12;
        case SYSCALL_CHOWN:
            return 13;
        case SYSCALL_OPENAT:
            return 14;
        case SYSCALL_UNLINKAT:
            return 15;
        default:
            return -1;
    }
}

static int handle_profile_syscall(void *ctx, void *data, size_t data_sz) {
    struct syscall *syscall_buff;
    syscall_buff = data;

    for(int i=0; i<MAX_FUNCTIONS; i++) {
        if(strcmp(syscall_buff->name, all_funcs[i].name) == 0) {
            for(int j=0; j<MAX_SYSCALL; j++) {
                if(all_funcs[i].syscalls[j] == syscall_buff->id) {
                    break;
                }
                else if (all_funcs[i].syscalls[j] == 0) {
                    all_funcs[i].syscalls[j] = syscall_buff->id;
                    int index = syscall_arr_index(syscall_buff->id);
                    if(index != -1)
                        printf("Syscall %s registered, function: %s\n", syscall_names[index], syscall_buff->name);
                    else
                        printf("Unknown syscall registered, function: %s\n", syscall_buff->name);
                    break;
                }
            }
            return 0;
        }
        else if(all_funcs[i].name[0] == '\0') {
            strncpy(all_funcs[i].name, syscall_buff->name, MAX_FUNC_NAME_LEN);
            all_funcs[i].syscalls[0] = syscall_buff->id;
            //printf("Function %s registered with syscall %d\n", all_funcs[i].name, syscall_buff->id);
            int index = syscall_arr_index(syscall_buff->id);
            if(index != -1)
                printf("Syscall %s registered, function: %s\n", syscall_names[index], all_funcs[i].name);
            else
                printf("Unknown syscall registered, function: %s\n", all_funcs[i].name);
            break;
        }
    }
    
    return 0;
}

static int handle_sandbox_syscall(void *ctx, void *data, size_t data_sz) {
    struct syscall *syscall_buff;
    syscall_buff = data;
    int exiting = 0;

    for(int i=0; i<MAX_FUNCTIONS; i++) {
        if(strcmp(syscall_buff->name, sandbox_funcs[i].name) == 0) {
            for(int j=0; j<MAX_SYSCALL; j++) {
                if(sandbox_funcs[i].syscalls[j] == syscall_buff->id) {
                    exiting = 1;
                    break;
                }
                else if (sandbox_funcs[i].syscalls[j] == 0) {
                    printf("Unauthorized syscall executed: %s, function: %s\n", syscall_names[syscall_arr_index(syscall_buff->id)], sandbox_funcs[i].name);
                    printf("Terminating process with pid: %d\n", syscall_buff->pid);
                    //kill(syscall_buff->pid, SIGKILL);
                    exiting = 1;
                    break;
                }
            }
            if(exiting) {
                break;
            }
        }
        else if(sandbox_funcs[i].name[0] == '\0') {
            printf("Unauthorized function executed: %s, syscall: %s\n", syscall_buff->name, syscall_names[syscall_arr_index(syscall_buff->id)]);
            printf("Terminating process with pid: %d\n", syscall_buff->pid);
            //kill(syscall_buff->pid, SIGKILL);
            break;
        }
    }

    return 0;
}

static int handle_monitor_syscall(void *ctx, void *data, size_t data_sz) {
    struct syscall *syscall_buff;
    syscall_buff = data;
    int exiting = 0;

    for(int i=0; i<MAX_FUNCTIONS; i++) {
        if(strcmp(syscall_buff->name, sandbox_funcs[i].name) == 0) {
            for(int j=0; j<MAX_SYSCALL; j++) {
                if(sandbox_funcs[i].syscalls[j] == syscall_buff->id) {
                    exiting = 1;
                    break;
                }
                else if (sandbox_funcs[i].syscalls[j] == 0) {
                    printf("Unauthorized syscall executed: %s, function: %s\n", syscall_names[syscall_arr_index(syscall_buff->id)], sandbox_funcs[i].name);
                    fprintf(monitor_file, "Unauthorized syscall: %s, function: %s, pid: %d\n", syscall_names[syscall_arr_index(syscall_buff->id)], sandbox_funcs[i].name, syscall_buff->pid);
                    break;
                }
            }
            if(exiting) {
                break;
            }
        }
        else if(sandbox_funcs[i].name[0] == '\0') {
            printf("Unauthorized function executed: %s, syscall: %s\n", syscall_buff->name, syscall_names[syscall_arr_index(syscall_buff->id)]);
            fprintf(monitor_file, "Unauthorized function: %s, syscall: %s, pid: %d\n", syscall_buff->name, syscall_names[syscall_arr_index(syscall_buff->id)], syscall_buff->pid);
            break;
        }
    }

    return 0;
}

static int handle_sandbox_kill_info(void *ctx, void *data, size_t data_sz) {
    struct syscall *syscall_buff;
    syscall_buff = data;

    printf("Dangerous operation killed -> function: %s, syscall: %s(%d), pid: %d\n", syscall_buff->name, syscall_names[syscall_arr_index(syscall_buff->id)], syscall_buff->id, syscall_buff->pid);

    return 0;
}

/*------------------------------------MAIN-----------------------------------------*/

int main(int argc, char **argv) {
    
    struct kernel_mode_kill_bpf *skel;
    struct ring_buffer *krb = NULL;
    struct ring_buffer *srb = NULL;
    struct user_ring_buffer *urb = NULL;
    struct user_ring_buffer *pi = NULL;
    FILE *file;
    int err;
    char *filename = "syscall_table.txt";
    char *monitor_filename = "monitor_information.txt";

    if (argc < 2) {
        printf("Invalid mode specified. Use --profile, --sandbox or --monitor.\n");
        return 0;
    }

    if(DEBUG_MODE) {
        libbpf_set_print(libbpf_print_fn);
    } else {
        libbpf_set_print(NULL);
    }

    skel = kernel_mode_kill_bpf__open_and_load();
    if(!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    printf("BPF skeleton opened and loaded successfully\n"); 

    err = kernel_mode_kill_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("BPF skeleton attached successfully\n");

    /*-------------------------------USER RING--------------------------------------*/

    urb = user_ring_buffer__new(bpf_map__fd(skel->maps.mode_info), 
       NULL);

    mode = user_ring_buffer__reserve(urb, sizeof(*mode));
    if(!mode) {
        fprintf(stderr, "Failed to reserve user ring buffer\n");
        goto cleanup;
    }
    
    if(strcmp(argv[1], "--profile") == 0) {
        printf("Command line argument is %s, Profile mode selected\n", argv[1]);
        mode->mode_id = PROFILE_MODE;
    } else if (strcmp(argv[1], "--sandbox") == 0) {
        printf("Command line argument is %s, Sandbox mode selected\n", argv[1]);
        mode->mode_id = SANDBOX_MODE;
    } else if (strcmp(argv[1], "--monitor") == 0) {
        printf("Command line argument is %s, Monitor mode selected\n", argv[1]);
        mode->mode_id = MONITOR_MODE;
    } else {
        printf("Invalid mode specified. Use --profile or --sandbox.\n");
        goto cleanup;
    }

    user_ring_buffer__submit(urb, mode);

    printf("Mode sent to kernel\n");

    /*---------------------------------------------------------------------------*/

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        goto cleanup;
    }

    if(mode->mode_id == PROFILE_MODE) {
        krb = ring_buffer__new(bpf_map__fd(skel->maps.syscall_info), 
            handle_profile_syscall, NULL, NULL);
        if(!krb) {
            fprintf(stderr, "Failed to create kernel ring buffer\n");
            goto cleanup;
        }

        printf("Kernel starts to send information\n");

        while(!exiting) {
            err = ring_buffer__poll(krb, 100);
            if (err == -EINTR)
                break;
            if(err < 0) {
                fprintf(stderr, "Failed to poll ring buffer\n");
                break;
            }
            
        }

        printf("BPF skeleton polling completed successfully\n");

        file = fopen(filename, "w");
        if(!file) {
            fprintf(stderr, "Failed to open file for writing\n");
            goto cleanup;
        }

        printf("Syscall-function file successfully opened for writing\n");

        for(int i=0; i<MAX_FUNCTIONS; i++) {
            if(all_funcs[i].name[0] != '\0') {
                printf("Function: %s, Syscall ids: ", all_funcs[i].name);
                fprintf(file, "%s:", all_funcs[i].name);
                for(int j=0; j<MAX_SYSCALL; j++) {
                    if(all_funcs[i].syscalls[j] != 0) {
                        if(j != 0)
                            fprintf(file, ",");
                        printf("%d ", all_funcs[i].syscalls[j]);
                        fprintf(file, "%d", all_funcs[i].syscalls[j]);
                    }
                }
                printf("\n");
                fprintf(file, "\n");
            }
        }

        printf("Syscall table written to %s\n", filename);

        fclose(file);
    }
    else if (mode->mode_id == SANDBOX_MODE) {

        char line[256];
        char *token;
        int i = 0;
        int j = 0;
        struct functions *sandbox_funcs_ptr = NULL;

        file = fopen(filename, "r");
        if (!file) {
            fprintf(stderr, "Failed to open file for reading\n");
            goto cleanup;
        }

        printf("Syscall-function file successfully opened for reading\n");

        while(fgets(line, sizeof(line), file)) {
            token = strtok(line, ":");
            if(!token)
                break;
            strncpy(sandbox_funcs[i].name, token, MAX_FUNC_NAME_LEN - 1);
            token = strtok(NULL, ",");
            j = 0;
            while(token) {
                sandbox_funcs[i].syscalls[j] = atoi(token);
                token = strtok(NULL, ",");
                j++;
            }
            i++;
        }

        fclose(file);

        printf("Allowed functions and syscalls:\n");
        for(i=0; i<MAX_FUNCTIONS; i++) {
            if(sandbox_funcs[i].name[0] != '\0') {
                printf("Function: %s, Syscall ids: ", sandbox_funcs[i].name);
                for(int j=0; j<MAX_SYSCALL; j++) {
                    if(sandbox_funcs[i].syscalls[j] != 0) {
                        if(j != 0)
                            printf(", ");
                        printf("%d", sandbox_funcs[i].syscalls[j]);
                    }
                }
                printf("\n");
            }
        }

        sandbox_funcs_ptr = sandbox_funcs;

        pi = user_ring_buffer__new(bpf_map__fd(skel->maps.profile_info), 
       NULL);
        sandbox_funcs_ptr = user_ring_buffer__reserve(pi, sizeof(*sandbox_funcs_ptr)*MAX_FUNCTIONS);
        memcpy(sandbox_funcs_ptr, sandbox_funcs, sizeof(*sandbox_funcs)*MAX_FUNCTIONS);
        user_ring_buffer__submit(pi, sandbox_funcs_ptr);

        krb = ring_buffer__new(bpf_map__fd(skel->maps.syscall_info), 
            handle_sandbox_syscall, NULL, NULL);
        if(!krb) {
            fprintf(stderr, "Failed to create kernel ring buffer\n");
            goto cleanup;
        }

        srb = ring_buffer__new(bpf_map__fd(skel->maps.sandbox_info), 
            handle_sandbox_kill_info, NULL, NULL);
        if(!srb) {
            fprintf(stderr, "Failed to create sandbox syscall ring buffer\n");
            goto cleanup;
        }

        printf("Kernel starts to send information\n");

        while(!exiting) {
            err = ring_buffer__poll(krb, 100);
            if (err == -EINTR)
                break;
            if(err < 0) {
                fprintf(stderr, "Failed to poll ring buffer\n");
                break;
            }
            err = ring_buffer__poll(srb, 100);
            if (err == -EINTR)
                break;
            if(err < 0) {
                fprintf(stderr, "Failed to poll ring buffer\n");
                break;
            }

        }
    }
    else if(mode->mode_id == MONITOR_MODE) {
        char line[256];
        char *token;
        int i = 0;
        int j = 0;
    
        file = fopen(filename, "r");
        if (!file) {
            fprintf(stderr, "Failed to open file for reading\n");
            goto cleanup;
        }

        printf("Syscall-function file successfully opened for reading\n");

        while(fgets(line, sizeof(line), file)) {
            token = strtok(line, ":");
            if(!token)
                break;
            strncpy(sandbox_funcs[i].name, token, MAX_FUNC_NAME_LEN - 1);
            token = strtok(NULL, ",");
            j = 0;
            while(token) {
                sandbox_funcs[i].syscalls[j] = atoi(token);
                token = strtok(NULL, ",");
                j++;
            }
            i++;
        }

        if(file)
            fclose(file);

        printf("Allowed functions and syscalls:\n");
        for(i=0; i<MAX_FUNCTIONS; i++) {
            if(sandbox_funcs[i].name[0] != '\0') {
                printf("Function: %s, Syscall ids: ", sandbox_funcs[i].name);
                for(int j=0; j<MAX_SYSCALL; j++) {
                    if(sandbox_funcs[i].syscalls[j] != 0) {
                        if(j != 0)
                            printf(", ");
                        printf("%d", sandbox_funcs[i].syscalls[j]);
                    }
                }
                printf("\n");
            }
        }
        
        monitor_file = fopen(monitor_filename, "w");
        if (!monitor_file) {
            fprintf(stderr, "Failed to open monitor file for writing\n");
            goto cleanup;
        }

        krb = ring_buffer__new(bpf_map__fd(skel->maps.syscall_info), 
            handle_monitor_syscall, NULL, NULL);
        if(!krb) {
            fprintf(stderr, "Failed to create kernel ring buffer\n");
            goto cleanup;
        }

        printf("Kernel starts to send information\n");

        while(!exiting) {
            err = ring_buffer__poll(krb, 100);
            if (err == -EINTR)
                break;
            if(err < 0) {
                fprintf(stderr, "Failed to poll ring buffer\n");
                break;
            }
        }

        printf("All monitoring information has been written to the file: %s\n", monitor_filename);

        if(monitor_file)
            fclose(monitor_file);
    }

cleanup:
    printf("System resources cleaned up\n");
    if (urb)
        user_ring_buffer__free(urb);
    if (pi)
        user_ring_buffer__free(pi);
    if (krb)
        ring_buffer__free(krb);
    if (srb)
        ring_buffer__free(srb);
    kernel_mode_kill_bpf__destroy(skel);
    return err < 0 ? -1 : 0;
}