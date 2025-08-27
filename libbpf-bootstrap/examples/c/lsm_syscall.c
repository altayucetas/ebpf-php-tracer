#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "lsm_syscall.skel.h"
#include "lsm_syscall.h"

/*------------------------------------GLOBAL VARIABLES---------------------------------*/

struct function profile_funcs[MAX_FUNCTIONS] = {0};
struct function sandbox_funcs[MAX_FUNCTIONS] = {0};
struct function monitor_funcs[MAX_FUNCTIONS] = {0};

char *syscall_names[] = {
    "write", "fork", "socket", "connect", "bind", "listen", "execve", "kill",
    "uname", "rename", "rmdir", "unlink", "chmod", "chown", "openat", "unlinkat",
    "ptrace", "mmap", "read", "newfstatat"
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

int get_details(struct syscall *syscall, struct function *funcs, int function_index, int syscall_index) {

    switch (syscall->id) {
        case SYSCALL_READ:
        case SYSCALL_WRITE:
        case SYSCALL_UNLINK:
        case SYSCALL_OPENAT:
        case SYSCALL_EXECVE:
        case SYSCALL_CHMOD:
        case SYSCALL_CHOWN:
        case SYSCALL_RENAME:
        case SYSCALL_RMDIR:
            strcpy(funcs[function_index].syscalls[syscall_index].details, syscall->details);
        
        default:
            break;
        }

    return 0;
}

int return_syscall_arr_index(int id) {
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
        case SYSCALL_PTRACE:
            return 16;
        case SYSCALL_MMAP:
            return 17;
        case SYSCALL_READ:
            return 18;
        case SYSCALL_NEWFSTATAT:
            return 19;
        default:
            return -1;
    }
}

void print_new_syscall_details(struct syscall *syscall, struct function *funcs, int function_index, int syscall_index, int index) {

    if(index != -1) {
        if(profile_funcs[function_index].syscalls[syscall_index].details[0] != '\0') {
            switch (syscall->id) {
                case SYSCALL_WRITE:
                    printf("[PROFILE] Syscall '%s' (ID: %d) has been registered for function '%s' (PID: %d). Written content: %s\n",
                        syscall_names[index], syscall->id,
                        syscall->name, profile_funcs[function_index].syscalls[syscall_index].pid,
                        profile_funcs[function_index].syscalls[syscall_index].details);
                    break;
                case SYSCALL_UNLINK:
                    printf("[PROFILE] Syscall '%s' (ID: %d) has been registered for function '%s' (PID: %d). Deleted file: %s\n",
                        syscall_names[index], syscall->id,
                        syscall->name, profile_funcs[function_index].syscalls[syscall_index].pid,
                        profile_funcs[function_index].syscalls[syscall_index].details);
                    break;
                case SYSCALL_OPENAT:
                    printf("[PROFILE] Syscall '%s' (ID: %d) has been registered for function '%s' (PID: %d). Opened file: %s\n",
                        syscall_names[index], syscall->id,
                        syscall->name, profile_funcs[function_index].syscalls[syscall_index].pid,
                        profile_funcs[function_index].syscalls[syscall_index].details);
                    break;
                case SYSCALL_EXECVE:
                    printf("[PROFILE] Syscall '%s' (ID: %d) has been registered for function '%s' (PID: %d). Executed: %s\n",
                        syscall_names[index], syscall->id,
                        syscall->name, profile_funcs[function_index].syscalls[syscall_index].pid,
                        profile_funcs[function_index].syscalls[syscall_index].details);
                    break;
                case SYSCALL_CHMOD:
                    printf("[PROFILE] Syscall '%s' (ID: %d) has been registered for function '%s' (PID: %d). Changed permissions: %s\n",
                        syscall_names[index], syscall->id,
                        syscall->name, profile_funcs[function_index].syscalls[syscall_index].pid,
                        profile_funcs[function_index].syscalls[syscall_index].details);
                    break;
                case SYSCALL_CHOWN:
                    printf("[PROFILE] Syscall '%s' (ID: %d) has been registered for function '%s' (PID: %d). Changed owner: %s\n",
                        syscall_names[index], syscall->id,
                        syscall->name, profile_funcs[function_index].syscalls[syscall_index].pid,
                        profile_funcs[function_index].syscalls[syscall_index].details);
                    break;
                case SYSCALL_RENAME: {
                    char *old_and_new_name = profile_funcs[function_index].syscalls[syscall_index].details;
                    printf("[PROFILE] Syscall '%s' (ID: %d) has been registered for function '%s' (PID: %d). Renamed file: %s to \n",
                        syscall_names[index], syscall->id,
                        syscall->name, profile_funcs[function_index].syscalls[syscall_index].pid,
                        strtok(old_and_new_name, " "));
                    printf("%s\n", strtok(NULL, " "));
                    break;
                }
                    
                case SYSCALL_RMDIR:
                    printf("[PROFILE] Syscall '%s' (ID: %d) has been registered for function '%s' (PID: %d). Deleted directory: %s\n",
                        syscall_names[index], syscall->id,
                        syscall->name, profile_funcs[function_index].syscalls[syscall_index].pid,
                        profile_funcs[function_index].syscalls[syscall_index].details);
                    break;

                default:
                    break;
                }
            }
        else {
            printf("[PROFILE] Syscall '%s' (ID: %d) has been registered for function '%s' (PID: %d)\n",
                syscall_names[index], syscall->id,
                syscall->name, profile_funcs[function_index].syscalls[syscall_index].pid);
        }
    } else {
        printf("[PROFILE] Unknown syscall (ID: %d) registered for function '%s' (PID: %d)\n",
                syscall->id, syscall->name,
                profile_funcs[function_index].syscalls[syscall_index].pid);
    }
}

void print_new_function_details(struct syscall *syscall, struct function *funcs, int function_index, int index) {

    if(index != -1)
        if(profile_funcs[function_index].syscalls[0].details[0] != '\0')
            switch (syscall->id)
            {
            case SYSCALL_WRITE:
                printf("[PROFILE] Registered new function '%s' (PID: %d) with initial syscall '%s' (ID: %d). Written content: %s\n",
                    profile_funcs[function_index].name, profile_funcs[function_index].syscalls[0].pid,
                    syscall_names[return_syscall_arr_index(profile_funcs[function_index].syscalls[0].id)],
                    profile_funcs[function_index].syscalls[0].id, profile_funcs[function_index].syscalls[0].details);
                break;

            case SYSCALL_UNLINK:
                printf("[PROFILE] Registered new function '%s' (PID: %d) with initial syscall '%s' (ID: %d). Deleted file: %s\n",
                    profile_funcs[function_index].name, profile_funcs[function_index].syscalls[0].pid,
                    syscall_names[return_syscall_arr_index(profile_funcs[function_index].syscalls[0].id)],
                    profile_funcs[function_index].syscalls[0].id, profile_funcs[function_index].syscalls[0].details);
                break;

            case SYSCALL_OPENAT:
                printf("[PROFILE] Registered new function '%s' (PID: %d) with initial syscall '%s' (ID: %d). Opened file: %s\n",
                    profile_funcs[function_index].name, profile_funcs[function_index].syscalls[0].pid,
                    syscall_names[return_syscall_arr_index(profile_funcs[function_index].syscalls[0].id)],
                    profile_funcs[function_index].syscalls[0].id, profile_funcs[function_index].syscalls[0].details);
                break;

            case SYSCALL_EXECVE:
                printf("[PROFILE] Registered new function '%s' (PID: %d) with initial syscall '%s' (ID: %d). Executed command: %s\n",
                    profile_funcs[function_index].name, profile_funcs[function_index].syscalls[0].pid,
                    syscall_names[return_syscall_arr_index(profile_funcs[function_index].syscalls[0].id)],
                    profile_funcs[function_index].syscalls[0].id, profile_funcs[function_index].syscalls[0].details);
                break;
            
            case SYSCALL_CHMOD:
                printf("[PROFILE] Registered new function '%s' (PID: %d) with initial syscall '%s' (ID: %d). Changed permissions: %s\n",
                    profile_funcs[function_index].name, profile_funcs[function_index].syscalls[0].pid,
                    syscall_names[return_syscall_arr_index(profile_funcs[function_index].syscalls[0].id)],
                    profile_funcs[function_index].syscalls[0].id, profile_funcs[function_index].syscalls[0].details);
                break;
            
            case SYSCALL_CHOWN:
                printf("[PROFILE] Registered new function '%s' (PID: %d) with initial syscall '%s' (ID: %d). Changed owner: %s\n",
                    profile_funcs[function_index].name, profile_funcs[function_index].syscalls[0].pid,
                    syscall_names[return_syscall_arr_index(profile_funcs[function_index].syscalls[0].id)],
                    profile_funcs[function_index].syscalls[0].id, profile_funcs[function_index].syscalls[0].details);
                break;

            case SYSCALL_RENAME: {
                char *old_and_new_name = profile_funcs[function_index].syscalls[0].details;
                printf("[PROFILE] Registered new function '%s' (PID: %d) with initial syscall '%s' (ID: %d). Renamed file: %s to \n",
                    profile_funcs[function_index].name, profile_funcs[function_index].syscalls[0].pid,
                    syscall_names[return_syscall_arr_index(profile_funcs[function_index].syscalls[0].id)],
                    profile_funcs[function_index].syscalls[0].id,
                    strtok(old_and_new_name, " "));
                printf("%s\n", strtok(NULL, " "));
                break;
            }

            case SYSCALL_RMDIR:
                printf("[PROFILE] Registered new function '%s' (PID: %d) with initial syscall '%s' (ID: %d). Deleted directory: %s\n",
                    profile_funcs[function_index].name, profile_funcs[function_index].syscalls[0].pid,
                    syscall_names[return_syscall_arr_index(profile_funcs[function_index].syscalls[0].id)],
                    profile_funcs[function_index].syscalls[0].id, profile_funcs[function_index].syscalls[0].details);
                break;

            default:
                break;
            }
            
        else
            printf("[PROFILE] Registered new function '%s' (PID: %d) with initial syscall '%s' (ID: %d)\n",
                profile_funcs[function_index].name, profile_funcs[function_index].syscalls[0].pid,
                syscall_names[return_syscall_arr_index(profile_funcs[function_index].syscalls[0].id)],
                profile_funcs[function_index].syscalls[0].id);
    else
        if(profile_funcs[function_index].syscalls[0].details[0] != '\0')
            printf("[PROFILE] Unknown syscall (ID: %d) registered for new function '%s' (PID: %d)\n",
                profile_funcs[function_index].syscalls[0].id, profile_funcs[function_index].name,
                profile_funcs[function_index].syscalls[0].pid);
}

void parse_from_file(FILE *file, struct function *funcs) {
    char line[256];
    char *token;
    int i = 0, j = 0;

    while(fgets(line, sizeof(line), file)) {
        token = strtok(line, ":");
        if(!token)
            break;
        strncpy(funcs[i].name, token, MAX_FUNC_NAME_LEN - 1);
        token = strtok(NULL, ",");
        j = 0;
        while(token) {
            funcs[i].syscalls[j].id = atoi(token);
            token = strtok(NULL, ",");
            j++;
        }
        i++;
    }
}

void print_allowed_functions(struct function *func, FILE *file) {
    printf("Allowed functions and syscalls:\n");
    for(int i=0; i<MAX_FUNCTIONS; i++) {
        if(func[i].name[0] != '\0') {
            printf("Function: %s, Syscall ids: ", func[i].name);
            if(file) {
                fprintf(file, "%s:", func[i].name);
            }
            for(int j=0; j<MAX_SYSCALL; j++) {
                if(func[i].syscalls[j].id != 0) {
                    if(j != 0) {
                        if(file)
                            fprintf(file, ",");
                        printf(", ");
                    }
                    printf("%d", func[i].syscalls[j].id);
                    if(file) {
                        fprintf(file, "%d", func[i].syscalls[j].id);
                    }
                }
            }
            printf("\n");
            if(file) {
                fprintf(file, "\n");
            }
        }
    }
}

static int handle_profile_syscall(void *ctx, void *data, size_t data_sz) {
    struct syscall *syscall_buff;
    syscall_buff = data;

    for(int i=0; i<MAX_FUNCTIONS; i++) {
        if(strcmp(syscall_buff->name, profile_funcs[i].name) == 0) {
            for(int j=0; j<MAX_SYSCALL; j++) {
                if(profile_funcs[i].syscalls[j].id == syscall_buff->id) {
                    break;
                }
                else if (profile_funcs[i].syscalls[j].id == 0) {
                    profile_funcs[i].syscalls[j].id = syscall_buff->id;
                    profile_funcs[i].syscalls[j].pid = syscall_buff->pid;
                    get_details(syscall_buff, profile_funcs, i, j);
                    int index = return_syscall_arr_index(syscall_buff->id);
                    print_new_syscall_details(syscall_buff, profile_funcs, i, j, index);
                    break;
                }
            }
            return 0;
        }
        else if(profile_funcs[i].name[0] == '\0') {
            strncpy(profile_funcs[i].name, syscall_buff->name, MAX_FUNC_NAME_LEN);
            profile_funcs[i].syscalls[0].id = syscall_buff->id;
            profile_funcs[i].syscalls[0].pid = syscall_buff->pid;
            get_details(syscall_buff, profile_funcs, i, 0);
            int index = return_syscall_arr_index(syscall_buff->id);
            print_new_function_details(syscall_buff, profile_funcs, i, index);
            break;
        }
    }
    
    return 0;
}

static int handle_sandbox_syscall(void *ctx, void *data, size_t data_sz) {
    return 0;
}

static int handle_monitor_syscall(void *ctx, void *data, size_t data_sz) {
    struct syscall *syscall_buff = data;

    for(int i=0; i<MAX_FUNCTIONS; i++) {
        if(strcmp(syscall_buff->name, monitor_funcs[i].name) == 0) {
            for(int j=0; j<MAX_SYSCALL; j++) {
                if(monitor_funcs[i].syscalls[j].id == syscall_buff->id) {
                    if(monitor_funcs[i].syscall_count[j] != 0) {
                        printf("[MONITOR] Unauthorized syscall '%s' (ID: %d) was executed by function '%s' (PID: %d)\n",
                            syscall_names[return_syscall_arr_index(syscall_buff->id)], syscall_buff->id,
                            monitor_funcs[i].name, syscall_buff->pid);
                        monitor_funcs[i].syscall_count[j]++;
                    }
                    break;
                }
                else if(monitor_funcs[i].syscalls[j].id == 0) {
                    //printf("I am here %s\n", syscall_buff->name);
                    printf("[MONITOR] Unauthorized syscall '%s' (ID: %d) was executed by function '%s' (PID: %d)\n",
                        syscall_names[return_syscall_arr_index(syscall_buff->id)], syscall_buff->id,
                        monitor_funcs[i].name, syscall_buff->pid);
                    monitor_funcs[i].syscalls[j].id = syscall_buff->id;
                    monitor_funcs[i].syscalls[j].pid = syscall_buff->pid;
                    monitor_funcs[i].syscall_count[j]++;
                    break;
                }
            }
            break;
        }
        else if(monitor_funcs[i].name[0] == '\0') {
            printf("[MONITOR] Unauthorized function executed: '%s', syscall: '%s' (ID: %d), pid: %d\n",
                syscall_buff->name, syscall_names[return_syscall_arr_index(syscall_buff->id)],
                syscall_buff->id, syscall_buff->pid);
            strncpy(monitor_funcs[i].name, syscall_buff->name, MAX_FUNC_NAME_LEN);
            monitor_funcs[i].syscalls[0].id = syscall_buff->id;
            monitor_funcs[i].syscalls[0].pid = syscall_buff->pid;
            monitor_funcs[i].syscall_count[0]++;
            break;
        }
    }
    return 0;
}

static int handle_sandbox_kill_info(void *ctx, void *data, size_t data_sz) {
    struct syscall *syscall_buff;
    syscall_buff = data;

    printf("[SANDBOX] Syscall '%s' (ID: %d) was blocked for function '%s' (PID: %d)\n",
        syscall_names[return_syscall_arr_index(syscall_buff->id)], syscall_buff->id,
        syscall_buff->name, syscall_buff->pid);
    return 0;
}

/*------------------------------------MAIN-----------------------------------------*/

int main(int argc, char **argv) {
    
    struct lsm_syscall_bpf *skel;
    struct ring_buffer *krb = NULL;
    struct ring_buffer *srb = NULL;
    struct user_ring_buffer *urb = NULL;
    struct user_ring_buffer *pi = NULL;
    FILE *file;
    int err;
    char syscall_result_filename[50];
    sprintf(syscall_result_filename, "%s_syscall_table.txt", argv[0]);
    char monitor_result_filename[50];
    sprintf(monitor_result_filename, "%s_monitor_table.txt", argv[0]);

    if (argc < 2) {
        printf("Invalid mode specified. Use --profile, --sandbox or --monitor.\n");
        return 0;
    }

    if(DEBUG_MODE) {
        libbpf_set_print(libbpf_print_fn);
    } else {
        libbpf_set_print(NULL);
    }

    skel = lsm_syscall_bpf__open_and_load();
    if(!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    printf("BPF skeleton opened and loaded successfully\n"); 

    err = lsm_syscall_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("BPF skeleton attached successfully\n");

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

        printf("Kernel started to send information\n");

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

        file = fopen(syscall_result_filename, "w");
        if(!file) {
            fprintf(stderr, "Failed to open file for writing\n");
            goto cleanup;
        }

        printf("Profile save file successfully opened for writing\n");

        print_allowed_functions(profile_funcs, file);

        printf("Syscall table written to %s\n", syscall_result_filename);

        fclose(file);
    }
    else if (mode->mode_id == SANDBOX_MODE) {

        struct function *sandbox_funcs_ptr = NULL;

        file = fopen(syscall_result_filename, "r");
        if (!file) {
            fprintf(stderr, "Failed to open file for reading\n");
            goto cleanup;
        }

        printf("Profile save file successfully opened for reading\n");

        parse_from_file(file, sandbox_funcs);

        fclose(file);

        print_allowed_functions(sandbox_funcs, NULL);

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

        printf("Kernel started to send information\n");

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
    
        file = fopen(syscall_result_filename, "r");
        if (!file) {
            fprintf(stderr, "Failed to open file for reading\n");
            goto cleanup;
        }

        printf("Profile save file successfully opened for reading\n");

        parse_from_file(file, monitor_funcs);

        if(file)
            fclose(file);

        print_allowed_functions(monitor_funcs, NULL);

        monitor_file = fopen(monitor_result_filename, "w");
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

        printf("Kernel started to send information\n");

        while(!exiting) {
            err = ring_buffer__poll(krb, 100);
            if (err == -EINTR)
                break;
            if(err < 0) {
                fprintf(stderr, "Failed to poll ring buffer\n");
                break;
            }
        }


        for(int i=0; i<MAX_FUNCTIONS; i++) {
            if(monitor_funcs[i].name[0] != '\0') {
                for(int j=0; j<MAX_SYSCALL; j++) {
                    if(monitor_funcs[i].syscall_count[j] != 0) {
                        fprintf(monitor_file, "Function: %s, Syscall: %s, Count: %d, Pid: %d\n", monitor_funcs[i].name, syscall_names[return_syscall_arr_index(monitor_funcs[i].syscalls[j].id)], monitor_funcs[i].syscall_count[j], monitor_funcs[i].syscalls[j].pid);
                    }
                }
            }
        }

        /*------------------------------DEBUG---------------------------------------*/

        /*for(int i=0; i<MAX_FUNCTIONS; i++) {
            if(monitor_funcs[i].name[0] != '\0') {
                printf("Function: %s, Syscall ids: ", monitor_funcs[i].name);
                for(int j=0; j<MAX_SYSCALL; j++) {
                    if(monitor_funcs[i].syscalls[j].id != 0) {
                        if(j != 0)
                            printf(", ");
                        printf("%d", monitor_funcs[i].syscalls[j].id);
                    }
                }
                printf(", syscall_count: ");
                for(int j=0; j<MAX_SYSCALL; j++) {
                    if(monitor_funcs[i].syscall_count[j] != 0) {
                        if(j != 0)
                            printf(", ");
                        printf("%d", monitor_funcs[i].syscall_count[j]);
                    }
                }
                printf(", depth: %d", monitor_funcs[i].depth);
                printf("\n");
            }
        }*/

        /*--------------------------------------------------------------------------*/

        printf("All monitoring information has been written to the file: %s\n", monitor_result_filename);

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
    lsm_syscall_bpf__destroy(skel);
    return err < 0 ? -1 : 0;
}