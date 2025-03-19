# HW1

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
