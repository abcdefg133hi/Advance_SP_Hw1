#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/prctl.h>

#define IOCTL_ADD_FILTER _IOR('k', 2, struct filter_info)
#define IOCTL_REMOVE_FILTER _IOR('k', 3, struct filter_info)
#define TASK_FILTER_LEN 0x20

struct filter_info {
    int syscall_nr;
    char comm[TASK_FILTER_LEN];
};

int main() {
    int fd = open("/dev/rootkit", O_RDWR);
    struct filter_info info;
    char pname[TASK_FILTER_LEN] = "yoman";
    prctl(PR_SET_NAME, pname);

    // 設定 process 名稱為 "test_process"
    // prctl(PR_SET_NAME, "test_process");

    // Add write filter
    info.syscall_nr = __NR_write;
    strncpy(info.comm, pname, TASK_FILTER_LEN - 1);
    info.comm[TASK_FILTER_LEN - 1] = '\0';
    if (ioctl(fd, IOCTL_ADD_FILTER, &info) < 0) {
        perror("ioctl");
        close(fd);
        return 1;
    }
    // Add read filter
    info.syscall_nr = __NR_read;
    strncpy(info.comm, pname, TASK_FILTER_LEN - 1);
    info.comm[TASK_FILTER_LEN - 1] = '\0';
    ioctl(fd, IOCTL_ADD_FILTER, &info);

    // Add mkdirat filter
    info.syscall_nr = __NR_mkdirat;
    strncpy(info.comm, pname, TASK_FILTER_LEN - 1);
    info.comm[TASK_FILTER_LEN - 1] = '\0';
    ioctl(fd, IOCTL_ADD_FILTER, &info);

    // 此時你的 kernel module 將阻擋以下操作：
    printf("Test Write\n");       // 被阻擋
    char buffer[105];
    read(0, buffer, 100);           // 被阻擋
    mkdir("testdir", 0755);       // 被阻擋

    // Remove filters
    info.syscall_nr = __NR_write;
    ioctl(fd, IOCTL_REMOVE_FILTER, &info);
    info.syscall_nr = __NR_read;
    ioctl(fd, IOCTL_REMOVE_FILTER, &info);
    info.syscall_nr = __NR_mkdirat;
    ioctl(fd, IOCTL_REMOVE_FILTER, &info);

    // 解除後，再次測試（正常執行）：
    printf("Test Write Again\n"); // 成功輸出
    read(0, buffer, 100);           // 成功讀取
    mkdir("testdir2", 0755);      // 成功建立資料夾

    close(fd);
    return 0;
}
