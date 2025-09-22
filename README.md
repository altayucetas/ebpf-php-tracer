
# eBPF PHP Tracer

This project provides dynamic profiling, threat prevention and monitoring for PHP programs using eBPF technology. With this tool you can create your own secure PHP environment.

The program has 3 modes.

- ``` profile ```: It captures the function and syscalls made by the program. It then links these calls together to create a profile.
- ``` sandbox ```: It monitors the function and syscalls made by the program in real-time. It then compares this activity against a predefined profile to **block** any unauthorized actions.
- ``` monitor ```: It monitors the function and syscalls made by the program in real-time. It then compares this activity against a predefined profile to **log** and **count** any unauthorized actions.

### Project Demo


https://github.com/user-attachments/assets/8366235f-8672-4762-94a5-413b4fa40e51



**Note 1**: If you want to use the _sandbox_ and _monitor_ modes, the _profile_ mode must be run first.

```
./[eBPF Program] --profile
```

**Note 2**: eBPF program is attachted to USDT probes on _/root/Tools/php/bin/php_. Before compilation, you may want to change that.

**Note 3**: To make USDT probes available, you need to define the "_USE_ZEND_DTRACE=1_" environmental variable.

**Note 4**: There is a subtle difference between LSM hooks and tracepoints. With LSM hooks, not every syscall might be captured because they often perform parameter validation before triggering. For example, imagine you try to delete a file named "a", but it doesn't exist. In this scenario, tracepoints will capture your syscall attempt. This is because tracepoints are designed to fire at the entry or exit of a syscall, regardless of the parameters. An LSM hook, on the other hand, might only be triggered after the kernel has performed initial validations, such as checking if the file actually exists. Therefore, while you will always capture the _unlink_ attempt with tracepoints, you may not capture the same _unlink_ call with an LSM hook if the file does not exist.

I completed this project in 3 phases.

### 1. User-mode Kill

This stage aims to kill unauthorized syscalls and functions encountered in sandbox mode in the user-space program. Its advantage is that it allows the user-space program to perform heavy-duty operations, but because the kill signal sent from the user-space program takes time, the program may have already performed the unauthorized activities.

```
cd libbpf-bootstrap/examples/c/
make user_mode_kill
```

### 2. Kernel-mode Kill

This phase ensures that the permissions recorded in the profile phase are transferred to the kernel via buffers, where they are checked. Unauthorized syscalls and functions are terminated with the bpf_send_signal sent from the kernel-space program. This phase is faster because it kill from the kernel-space side, but it also places a burden on the kernel and doesn't prevent the initial unauthorized syscall.

```
cd libbpf-bootstrap/examples/c/
make kernel_mode_kill
```

### 3. LSM Syscall

Two different approaches were used in this step. Before compiling, the LSM enabled section in the _lsm_syscall.h_ header allows you to select which approach to use. The first approach leverages the tracepoints used in previous steps. When an unauthorized function or syscall is encountered, not only does the kernel-space program send a kill signal, but the syscall's parameters are also modified using the bpf_probe_write_user function within eBPF. This solves the problem of executing the first syscall encountered. The other approach uses LSM hooks instead of tracepoints. Because the return values ​​of LSM hooks affect syscalls, unauthorized access can be prevented with -EPERM. 

However, these different approaches have a problem: Tracepoints and LSM hooks are not identical, so a program profiled by one should not be used in sandbox mode by the other, as otherwise, sandboxing may not work effectively. Therefore, whichever approach is preferred, its profile and sandbox should be used, respectively.

Additionally, the quality of the content printed on the screen is also increased in this mode.

```
cd libbpf-bootstrap/examples/c/
make lsm_syscall

```
