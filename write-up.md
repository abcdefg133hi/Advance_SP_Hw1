# HW1

## **Explanation of my source code**

------------

TODO

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

- Currently only hook `read` and `write`.
- In `filter_test_source.c`, we filtered some processes to disable `read` and some disable `write`. Next, we fork and execve these processes. After that, we enable them again and run again.
- Every process runs a very single code `filter_test.c`.
```sh
./filter_test
```

## **Problem from the questions**

-----------

## Question 1

- **Q:** The system call filtering based approach is vulnerable to the so called Returned Oriented Programming (ROP) attack, why is that? Name a concrete attack example in your write-up, and discuss approaches that you could use to address the vulnerabilities.

- **A:** In this kind of system call filtering based approach, we stored our hooked system call function pointers and our own filtered functions (eg: `my_read` and `my_write`) pointers toward the kernel stack memory, which is typically writable by the kernel. Therefore, if the attackers can find loopholes to make the kernel overwrite the return address, they can redirect the return address to their sections of codes (Gadgets). One example is the malicious kernel stack overflow. The attackers can call memory-related system call for lots of time, such as `open`, where the input parameters may be the malicious assembly codes to redirect the return address to their code session. This way, they can esclate their previllages and run everything they want, such as crashing the kernel. To address this issue, we think the best way is to preserve every functions pointers for `read_only` section (or `const`). Although this might sacrifice the power of dynamic update, it is more safe. Also, we could enable `KASLR` to make the attackers more difficult to predict the return address, which would probably reduce the number of successful attacking.

## Question 2

- **Q:** What are the advantages and disadvantages of the filtering approach served by the module in this assignment compared to an approach based on `ptrace`?

- **A:** Using `ptrace` to filter out the system call is an approach happening in user-space program. Two processes (`ptrace` and the target filtered process) will communicate each other, where `ptrace` will monitor the current system call number and not allow the target process to keep running via signal. Hence, the advantage is that the kernel won't be hooked and preserve the same level of safety as the setup before any filtering. Also, since no kernel module is `insmod`-ed, there is almost no way to crash the kernel for a single bug. However, `ptrace` relies on the signal communication between two processes, which will increase the time overhead. Comparing to the kernel module based filtering, which directly overwrite the original system call, it is more inefficient in the terms of run time.
