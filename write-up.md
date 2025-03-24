# HW1

## **Explanation of my source code**

```sh
- user_space_test_code
------ hide_test.c # hide test code
------ masq_test.c # masquerade test code
------ filter_test.c # filter test code (each process)
------ filter_test_source.c # The process to filter and execve other processes.
------ Makefile # Compile the whole binaries

- rootkit.c # The main kernel module code here.
- rootkit.h
- Makefile
- write-up.md # This file
```

## **Detailed descriptions of how we test the rootkit**

------------

## Preprocessing
```sh
make KDIR=[linux_path] CROSS=aarch64-linux-gnu-
## Then move your rootkit.ko into qemu vm.
sudo insmod rootkit.ko
```
## User Space Code
```sh
cd user_space_test_code
make
```

## Hide
```sh
lsmod # You will see the rootkit module. 
./hide_test
lsmod # You won't see the rootkit module.
./hide_test
lsmod # You will see the rootkit module.
```

## Masquerade
```sh
ps ao pid,comm # You will see 'bash' process
./masq_test bash bas
ps ao pid,comm # You will see 'bash' process to be 'bas'
```

## Syscall Filtering / Unfiltering

- Hook `read`, `write`, `exit` and `exit_group`.
- The code `filter_test_source.c` will filter out the processes for assigned system calls. Then it will `fork` and `execve` the assigned process. The following is the abstract of the main function.
```c
...
int main() {
    prepare_filtering(); // Prepare filter infos for the corresponding processes.

    // Read / Write Test
    filter_read();
    filter_write();

    run_read_processes(); // fork and execve
    run_write_processes();

    unfilter_read();
    unfilter_write();

    run_read_processes();
    run_write_processes();

    // Exit / Write Test
    filter_exit();
    filter_write();

    run_exit_processes();

    unfilter_exit();
    unfilter_write();

    run_exit_processes();
    ...
    return 0;
}
```
- The lists of processes for `read`, `write` and `exit` filtering are of the following.
    - **Read:** `read_filter_1`, `read_filter_2`, `read_filter_3`, `rw_filter_1`, `rw_filter_2`.
    - **Write:** `write_filter_1`, `write_filter_2`, `write_filter_3`, `rw_filter_1`, `rw_filter_2`.
    - **Exit:** `read_filter_1`, `write_filter_1`, `rw_filter_1`.
- To run it, using:
```sh
./filter_test
```

### Details inside the running code
```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include "../rootkit.h"

int a;
int ret;
int main(int argc, char *argv[]) {
    printf("Consider %s:\n", argv[0]);
    scanf("%d", &a);
    printf("Hello World! The number of a is %d\n", a);
    return 0;
}
```
Every process runs the same code segement above. It is a fairly simple `read` and `write` (and `exit`) process, which is in `filter_test.c`.

### Expected Outputs

1. For the first Read / Write Test: The read related processes will raise an error when they try to read. And the write related processes will not print anything. Therefore, we have
```sh
# Read Related Process
read_filter_1: error while loading shared libraries: /lib/aarch64-linux-gnu/libc.so.6: cannot read file data: Error 38
Child process was not terminated by abnormal signal
----------------------
read_filter_2: error while loading shared libraries: /lib/aarch64-linux-gnu/libc.so.6: cannot read file data: Error 38
Child process was not terminated by abnormal signal
----------------------
read_filter_3: error while loading shared libraries: /lib/aarch64-linux-gnu/libc.so.6: cannot read file data: Error 38
Child process was not terminated by abnormal signal
----------------------
rw_filter_1: error while loading shared libraries: /lib/aarch64-linux-gnu/libc.so.6: cannot read file data: Error 38
Child process was not terminated by abnormal signal
----------------------
rw_filter_2: error while loading shared libraries: /lib/aarch64-linux-gnu/libc.so.6: cannot read file data: Error 38
Child process was not terminated by abnormal signal

# Write Related Process
----------------------
# write_filter_1
Child process was not terminated by abnormal signal
----------------------
# write_filter_2
Child process was not terminated by abnormal signal
----------------------
# write_filter_3
Child process was not terminated by abnormal signal
----------------------
rw_filter_1: error while loading shared libraries: /lib/aarch64-linux-gnu/libc.so.6: cannot read file data: Error 38
Child process was not terminated by abnormal signal
----------------------
rw_filter_2: error while loading shared libraries: /lib/aarch64-linux-gnu/libc.so.6: cannot read file data: Error 38
Child process was not terminated by abnormal signal
----------------------
```
comparing to the unfiltered ones
```sh
# Read Related Processes
Consider read_filter_1:
Hello World! The number of a is 5
Child process was not terminated by abnormal signal
----------------------
Consider read_filter_2:
Hello World! The number of a is 5
Child process was not terminated by abnormal signal
----------------------
Consider read_filter_3:
Hello World! The number of a is 5
Child process was not terminated by abnormal signal
----------------------
Consider rw_filter_1:
Hello World! The number of a is 5
Child process was not terminated by abnormal signal
----------------------
Consider rw_filter_2:
Hello World! The number of a is 5
Child process was not terminated by abnormal signal
----------------------

# Write Related Processes
Consider write_filter_1:
Hello World! The number of a is 5
Child process was not terminated by abnormal signal
----------------------
Consider write_filter_2:
Hello World! The number of a is 5
Child process was not terminated by abnormal signal
----------------------
Consider write_filter_3:
Hello World! The number of a is 5
Child process was not terminated by abnormal signal
----------------------
Consider rw_filter_1:
Hello World! The number of a is 5
Child process was not terminated by abnormal signal
----------------------
Consider rw_filter_2:
Hello World! The number of a is 5
Child process was not terminated by abnormal signal
----------------------
```

2. For the Exit / Write Test: The filtered exit process will be sent a signal `SIGTRAP`, which is `signo = 5`. Hence the log will be:
```sh
Consider read_filter_1: 
Hello World! The number of a is 5 # Notice that read_filter_1 is not filtered in this case.
Child process was terminated by signal 5
----------------------
# write_filter_1
Child process was terminated by signal 5
----------------------
# rw_filter_1
Child process was terminated by signal 5
----------------------
```
comparing to the unfiltered ones

```sh
Consider read_filter_1:
Hello World! The number of a is 5
Child process was not terminated by abnormal signal
----------------------
Consider write_filter_1:
Hello World! The number of a is 5
Child process was not terminated by abnormal signal
----------------------
Consider rw_filter_1:
Hello World! The number of a is 5
Child process was not terminated by abnormal signal
----------------------
```






## **Problem from the questions**

-----------

## Question 1

- **Q:** The system call filtering based approach is vulnerable to the so called Returned Oriented Programming (ROP) attack, why is that? Name a concrete attack example in your write-up, and discuss approaches that you could use to address the vulnerabilities.

- **A:** In this kind of system call filtering based approach, we stored our hooked system call function pointers and our own filtered functions (eg: `my_read` and `my_write`) pointers toward the kernel stack memory, which is typically writable by the kernel. Therefore, if the attackers can find loopholes to make the kernel overwrite the return address, they can redirect the return address to their sections of codes (Gadgets). One example is the malicious kernel stack overflow. The attackers can call memory-related system call for lots of time, such as `open`, where the input parameters may be the malicious assembly codes to redirect the return address to their code session. This way, they can esclate their previllages and run everything they want, such as crashing the kernel. To address this issue, we think the best way is to preserve every functions pointers for `read_only` section (or `const`). Although this might sacrifice the power of dynamic update, it is more safe. Also, we could enable `KASLR` to make the attackers more difficult to predict the return address, which would probably reduce the number of successful attacking.

## Question 2

- **Q:** What are the advantages and disadvantages of the filtering approach served by the module in this assignment compared to an approach based on `ptrace`?

- **A:** Using `ptrace` to filter out the system call is an approach happening in user-space program. Two processes (`ptrace` and the target filtered process) will communicate each other, where `ptrace` will monitor the current system call number and not allow the target process to keep running via signal. Hence, the advantage is that the kernel won't be hooked and preserve the same level of safety as the setup before any filtering. Also, since no kernel module is `insmod`-ed, there is almost no way to crash the kernel for a single bug. However, `ptrace` relies on the signal communication between two processes, which will increase the time overhead. Comparing to the kernel module based filtering, which directly overwrite the original system call, it is more inefficient in the terms of run time.


## Reference

### Masquerade

1. kmalloc: https://blog.csdn.net/lu_embedded/article/details/51588902
2. copy_from_user: https://blog.csdn.net/bhniunan/article/details/104088763

### Filter / Unfilter

1. https://blog.csdn.net/weixin_45030965/article/details/129203081
2. https://blog.csdn.net/u013250169/article/details/114374228