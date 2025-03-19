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



