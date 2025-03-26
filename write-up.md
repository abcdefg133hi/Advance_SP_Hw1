# HW1

## **Explanation of my source code**

```sh
- user_space_test_code
------ a # The stdin for the process.
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

- **A:**
- In a system call filtering approach that hooks the sys_call_table, attackers can bypass any interception on the table if they employ Return-Oriented Programming (ROP) to manipulate the return address. ROP entails "chaining" executable instruction fragments (gadgets) and, by overwriting stack or return addresses, directly invoking low-level functions (e.g., `vfs_write()`) at the kernel level, without going through the custom hook entries in the sys_call_table. In other words, if exploitable gadgets exist in the kernel that can move register values, call functions, etc., attackers can assemble and place the parameters onto the stack or into registers. They then jump straight to the desired function, effectively circumventing the interception logic placed in the sys_call_table.
- The “malicious kernel stack overflow” or "memory corruption bug" triggered by repeatedly calling system calls like open or read with specially crafted parameters. This leads the kernel to **overwrite the return address** with the starting address of ROP gadgets. By chaining these gadgets, attackers can set up arguments for and then directly call, for instance, one can skip the `my_write` function to `vfs_write()` directly. This may lead to security issues.
- To defend against such attacks, one should not only store function pointers or critical structures in read-only segments (so they cannot be overwritten during runtime), but also adopt higher-level defenses. For instance, one can use Kernel Address Space Layout Randomization (KASLR) to reduce the attacker’s knowledge of kernel addresses, and implementing Control Flow Integrity (CFI) or hardware-assisted protections (e.g., Intel CET or ARM Pointer Authentication) can further obstruct ROP. 

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
3. https://blog.wohin.me/posts/linux-rootkit-04/
4. https://blog.csdn.net/cswhl/article/details/110842196
5. https://blog.csdn.net/anyegongjuezjd/article/details/128322592
6. https://blog.csdn.net/weixin_45030965/article/details/132497956
7. we also discuss with group 13

### ROP Reference
1. https://www.infosecinstitute.com/resources/hacking/return-oriented-programming-rop-attacks/
2. https://www.ibm.com/docs/en/zos/2.4.0?topic=overview-address-space-layout-randomization
