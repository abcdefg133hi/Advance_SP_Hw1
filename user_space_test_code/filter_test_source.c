#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include "../rootkit.h"
#include <sys/wait.h>
#include <asm/unistd.h>


#define READ_FILTER_LENGTH 5
#define WRITE_FILTER_LENGTH 5
#define EXIT_FILTER_LENGTH 3

char read_filter_list[READ_FILTER_LENGTH][TASK_FILTER_LEN]  = {"read_filter_1", "read_filter_2", "read_filter_3", "rw_filter_1", "rw_filter_2"};
char write_filter_list[WRITE_FILTER_LENGTH][TASK_FILTER_LEN] = {"write_filter_1", "write_filter_2", "write_filter_3", "rw_filter_1", "rw_filter_2"};
char exit_filter_list[EXIT_FILTER_LENGTH][TASK_FILTER_LEN] = {"read_filter_1", "write_filter_1", "rw_filter_1"};


struct filter_info *read_infos;
struct filter_info *write_infos;
struct filter_info *exit_infos;
struct filter_info *exit_group_infos;

int fd;


// Prepare filtering list struct for read, write and exit (exit group).
void prepare_filtering()
{
    fd = open("/dev/rootkit", O_RDWR);
    read_infos  = (struct filter_info *)malloc(sizeof(struct filter_info) * READ_FILTER_LENGTH);
    write_infos = (struct filter_info *)malloc(sizeof(struct filter_info) * WRITE_FILTER_LENGTH);
    exit_infos  = (struct filter_info *)malloc(sizeof(struct filter_info) * EXIT_FILTER_LENGTH);
    exit_group_infos  = (struct filter_info *)malloc(sizeof(struct filter_info) * EXIT_FILTER_LENGTH);
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
    for(int i=0;i<EXIT_FILTER_LENGTH;i++)
    {
        exit_infos[i].syscall_nr = __NR_exit;
        strncpy(exit_infos[i].comm, exit_filter_list[i], TASK_FILTER_LEN-1);
        exit_infos[i].comm[TASK_FILTER_LEN - 1] = '\0';
    }
    for(int i=0;i<EXIT_FILTER_LENGTH;i++)
    {
        exit_group_infos[i].syscall_nr = __NR_exit_group;
        strncpy(exit_group_infos[i].comm, exit_filter_list[i], TASK_FILTER_LEN-1);
        exit_group_infos[i].comm[TASK_FILTER_LEN - 1] = '\0';
    }
}


////// Filter / Unfilter syscall via ioctl ///////
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
void filter_exit()
{
    for(int i=0;i<EXIT_FILTER_LENGTH;i++) 
    {
        ioctl(fd, IOCTL_ADD_FILTER, &exit_infos[i]);
        ioctl(fd, IOCTL_ADD_FILTER, &exit_group_infos[i]);
    }
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
void unfilter_exit()
{
    for(int i=0;i<EXIT_FILTER_LENGTH;i++) 
    {
        ioctl(fd, IOCTL_REMOVE_FILTER, &exit_infos[i]);
        ioctl(fd, IOCTL_REMOVE_FILTER, &exit_group_infos[i]);
    }
}
////// Filter / Unfilter syscall via ioctl ///////


// Create the process to run
void create_process(const char *name)
{
    pid_t pid = fork();
    int fd_a = open("a", O_RDONLY); // The input for scanf
    dup2(fd_a, STDIN_FILENO); // Redirect "a" to STDIN

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
        if (WIFSIGNALED(status)) {
            printf("Child process was terminated by signal %d\n", WTERMSIG(status));
        } else {
            printf("Child process was not terminated by abnormal signal\n");
        }
    }
}

void run_read_processes()
{
    for (int i = 0; i < READ_FILTER_LENGTH; i++) 
    {
        create_process(read_filter_list[i]);
        printf("----------------------\n"); fflush(stdout);
    }
}
void run_write_processes()
{
    for (int i = 0; i < WRITE_FILTER_LENGTH; i++)
    {
        create_process(write_filter_list[i]);
        printf("----------------------\n"); fflush(stdout);
    }
}
void run_exit_processes()
{
    for (int i = 0; i < EXIT_FILTER_LENGTH; i++)
    {
        create_process(exit_filter_list[i]);
        printf("----------------------\n"); fflush(stdout);
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
    printf("Unfilter read / write for all the processes.\n");
    fflush(stdout);
    run_read_processes();
    run_write_processes();
    ////////////////////
    printf("-----------------------------------------\n");
    fflush(stdout);
    printf("Filter write / exit for some of the processes.\n");
    fflush(stdout);
    filter_exit();
    filter_write();
    /////////////////////
    run_exit_processes();
    /////////////////////
    printf("-----------------------------------------\n");
    fflush(stdout);
    unfilter_exit();
    unfilter_write();
    /////////////////////
    printf("Unfilter write / exit for some of the processes.\n");
    fflush(stdout);
    run_exit_processes();
    ////////////////////
    close(fd);
    free(read_infos);
    free(write_infos);
    free(exit_infos);
    return 0;
}



