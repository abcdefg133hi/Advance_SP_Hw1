#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include "../rootkit.h"
 #include <sys/wait.h>


#define __NR_read 63
#define __NR_write 64

#define READ_FILTER_LENGTH 5
#define WRITE_FILTER_LENGTH 5

char read_filter_list[READ_FILTER_LENGTH][TASK_FILTER_LEN]  = {"read_filter_1", "read_filter_2", "read_filter_3", "rw_filter_1", "rw_filter_2"};
char write_filter_list[WRITE_FILTER_LENGTH][TASK_FILTER_LEN] = {"write_filter_1", "write_filter_2", "write_filter_3", "rw_filter_1", "rw_filter_2"};


struct filter_info *read_infos;
struct filter_info *write_infos;

int fd;
void prepare_filtering()
{
    fd = open("/dev/rootkit", O_RDWR);
    read_infos  = (struct filter_info *)malloc(sizeof(struct filter_info) * READ_FILTER_LENGTH);
    write_infos = (struct filter_info *)malloc(sizeof(struct filter_info) * WRITE_FILTER_LENGTH);
    for(int i=0;i<READ_FILTER_LENGTH;i++)
    {
        read_infos[i].syscall_nr = __NR_read;
        strncpy(read_infos[i].comm, read_filter_list[i], TASK_FILTER_LEN-1);
        read_infos[i].comm[TASK_FILTER_LEN - 1] = '\0';
    }
    for(int i=0;i<WRITE_FILTER_LENGTH;i++)
    {
        write_infos[i].syscall_nr = __NR_write;
        strncpy(write_infos[i].comm, write_filter_list[i], TASK_FILTER_LEN-1);
        write_infos[i].comm[TASK_FILTER_LEN - 1] = '\0';
    }
}

void filter_read()
{
    for(int i=0;i<READ_FILTER_LENGTH;i++) 
        ioctl(fd, IOCTL_ADD_FILTER, &read_infos[i]);
}

void filter_write()
{
    for(int i=0;i<WRITE_FILTER_LENGTH;i++) 
        ioctl(fd, IOCTL_ADD_FILTER, &write_infos[i]);
}
void unfilter_read()
{
    for(int i=0;i<READ_FILTER_LENGTH;i++) 
        ioctl(fd, IOCTL_REMOVE_FILTER, &read_infos[i]);
}

void unfilter_write()
{
    for(int i=0;i<WRITE_FILTER_LENGTH;i++) 
        ioctl(fd, IOCTL_REMOVE_FILTER, &write_infos[i]);
}

void create_process(const char *name)
{
    pid_t pid = fork();
    int fd_a = open("a", O_RDONLY);
    dup2(fd_a, STDIN_FILENO);

    int result;
    if (pid == 0) {
        char *args[] = {name, NULL};
        char *env[] = {NULL};
        if (execve(name, args, env) == -1) {
            perror("execve failed");
            exit(EXIT_FAILURE);
        }
    }
    else if (pid < 0) {
        perror("fork failed");
    }
    else {
        int status;
        pid_t child_pid = waitpid(pid, &status, 0);
    }
}

void run_read_processes()
{
    for (int i = 0; i < READ_FILTER_LENGTH; i++) 
    {
        create_process(read_filter_list[i]);
    }
}

void run_write_processes()
{
    for (int i = 0; i < WRITE_FILTER_LENGTH; i++)
    {
        create_process(write_filter_list[i]);
    }
}

int main() {
    prepare_filtering(); 
    ////////////////////
    printf("-----------------------------------------\n");
    fflush(stdout);
    printf("Filter read / write for all the processes.\n");
    fflush(stdout);
    filter_read();
    filter_write();
    /////////////////////
    run_read_processes();
    run_write_processes();
    /////////////////////
    printf("-----------------------------------------\n");
    fflush(stdout);
    unfilter_read();
    unfilter_write();
    /////////////////////
    printf("unFilter read / write for all the processes.\n");
    fflush(stdout);
    run_read_processes();
    run_write_processes();
    ////////////////////
    close(fd);
    free(read_infos);
    free(write_infos);
    return 0;
}



