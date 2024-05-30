/*
 * Adapted from https://github.com/ilammy/ftrace-hook for hook management part.
 */

#define pr_fmt(fmt) "CXLCDAT: " fmt

#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/blkdev.h>
#include <linux/moduleparam.h>
#include <linux/hashtable.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/device.h>
#include <linux/delay.h>
#include <linux/pci.h>
#include <linux/pci-doe.h>
#include <cxlpci.h>
#include <cxlmem.h>
#include <cxl.h>
#include "core.h"
#include "trace.h"

#define HASHTABLE_BITS 16

// From drivers/cxl/core/pci.c
#define CXL_DOE_TABLE_ACCESS_REQ_CODE		0x000000ff
#define CXL_DOE_TABLE_ACCESS_REQ_CODE_READ	0
#define CXL_DOE_TABLE_ACCESS_TABLE_TYPE		0x0000ff00
#define CXL_DOE_TABLE_ACCESS_TABLE_TYPE_CDATA	0
#define CXL_DOE_TABLE_ACCESS_ENTRY_HANDLE	0xffff0000
#define CXL_DOE_TABLE_ACCESS_LAST_ENTRY		0xffff
#define CXL_DOE_PROTOCOL_TABLE_ACCESS 2

struct process_name {
	char* pname;
	struct request* req;
	struct hlist_node node;
};

// Uncomment the following line to enable logging to dmesg.
// #define DEBUG_MODULE

#ifdef DEBUG_MODULE
#define printdbg(fmt, ...) \
	do { printk(fmt, ## __VA_ARGS__); } while (0)
#define printwmodname(fmt, ...) \
	do { pr_info(fmt, ## __VA_ARGS__); } while (0)
#else
#define printdbg(fmt, ...) \
	do { } while (0)
#define printwmodname(fmt, ...) \
	do { } while (0)
#endif

MODULE_DESCRIPTION("CDAT Fixer");
MODULE_AUTHOR("Xiangqun Zhang <xzhang84@syr.edu>");
MODULE_LICENSE("GPL");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
static unsigned long lookup_name(const char *name)
{
	struct kprobe kp = {
		.symbol_name = name
	};
	unsigned long retval;

	if (register_kprobe(&kp) < 0) return 0;
	retval = (unsigned long) kp.addr;
	unregister_kprobe(&kp);
	return retval;
}
#else
static unsigned long lookup_name(const char *name)
{
	return kallsyms_lookup_name(name);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define FTRACE_OPS_FL_RECURSION FTRACE_OPS_FL_RECURSION_SAFE
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
#define ftrace_regs pt_regs

static __always_inline struct pt_regs *ftrace_get_regs(struct ftrace_regs *fregs)
{
	return fregs;
}
#endif

/*
 * There are two ways of preventing vicious recursive loops when hooking:
 * - detect recusion using function return address (USE_FENTRY_OFFSET = 0)
 * - avoid recusion by jumping over the ftrace call (USE_FENTRY_OFFSET = 1)
 */
#define USE_FENTRY_OFFSET 0

/**
 * struct ftrace_hook - describes a single hook to install
 *
 * @name:     name of the function to hook
 *
 * @function: pointer to the function to execute instead
 *
 * @original: pointer to the location where to save a pointer
 *            to the original function
 *
 * @address:  kernel address of the function entry
 *
 * @ops:      ftrace_ops state for this function hook
 *
 * The user should fill in only &name, &hook, &orig fields.
 * Other fields are considered implementation details.
 */
struct ftrace_hook {
	const char *name;
	void *function;
	void *original;

	unsigned long address;
	struct ftrace_ops ops;
};

static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
	hook->address = lookup_name(hook->name);

	if (!hook->address) {
		pr_debug("unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

#if USE_FENTRY_OFFSET
	*((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
	*((unsigned long*) hook->original) = hook->address;
#endif

	return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
	struct pt_regs *regs = ftrace_get_regs(fregs);
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
	regs->ip = (unsigned long)hook->function;
#else
	if (!within_module(parent_ip, THIS_MODULE))
		regs->ip = (unsigned long)hook->function;
#endif
}

/**
 * fh_install_hooks() - register and enable a single hook
 * @hook: a hook to install
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hook(struct ftrace_hook *hook)
{
	int err;

	err = fh_resolve_hook_address(hook);
	if (err)
		return err;

	/*
	 * We're going to modify %rip register so we'll need IPMODIFY flag
	 * and SAVE_REGS as its prerequisite. ftrace's anti-recursion guard
	 * is useless if we change %rip so disable it with RECURSION.
	 * We'll perform our own checks for trace function reentry.
	 */
	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
					| FTRACE_OPS_FL_RECURSION
					| FTRACE_OPS_FL_IPMODIFY;

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("register_ftrace_function() failed: %d\n", err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}

	return 0;
}

/**
 * fh_remove_hooks() - disable and unregister a single hook
 * @hook: a hook to remove
 */
void fh_remove_hook(struct ftrace_hook *hook)
{
	int err;

	err = unregister_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("unregister_ftrace_function() failed: %d\n", err);
	}

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
	}
}

/**
 * fh_install_hooks() - register and enable multiple hooks
 * @hooks: array of hooks to install
 * @count: number of hooks to install
 *
 * If some hooks fail to install then all hooks will be removed.
 *
 * Returns: zero on success, negative error code otherwise.
 */
int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
	int err;
	size_t i;

	for (i = 0; i < count; i++) {
		err = fh_install_hook(&hooks[i]);
		if (err)
			goto error;
	}

	return 0;

error:
	while (i != 0) {
		fh_remove_hook(&hooks[--i]);
	}

	return err;
}

/**
 * fh_remove_hooks() - disable and unregister multiple hooks
 * @hooks: array of hooks to remove
 * @count: number of hooks to remove
 */
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		fh_remove_hook(&hooks[i]);
}

#ifndef CONFIG_X86_64
#error Currently only x86_64 architecture is supported
#endif

/*
 * Tail call optimization can interfere with recursion detection based on
 * return address on the stack. Disable it to avoid machine hangups.
 */
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif


static asmlinkage int (*real_cxl_cdat_get_length)(struct device *dev,
			       struct pci_doe_mb *cdat_doe,
			       size_t *length);

static asmlinkage int fh_cxl_cdat_get_length(struct device *dev,
			       struct pci_doe_mb *cdat_doe,
			       size_t *length){
	return real_cxl_cdat_get_length(dev, cdat_doe, length);
}


static asmlinkage int (*real_cxl_cdat_read_table)(struct device *dev,
			       struct pci_doe_mb *cdat_doe,
			       void *cdat_table, size_t *cdat_length);

static asmlinkage int fh_cxl_cdat_read_table(struct device *dev,
			       struct pci_doe_mb *cdat_doe,
			       void *cdat_table, size_t *cdat_length){
	return real_cxl_cdat_read_table(dev, cdat_doe, cdat_table, cdat_length);
}

static asmlinkage void (*real_read_cdat_data)(struct cxl_port *port);

static asmlinkage void fh_read_cdat_data(struct cxl_port *port)
{

	// printdbg("The process id is %d\n", (int) task_pid_nr(current));
	// printdbg("The process vid is %d\n", (int) task_pid_vnr(current));
	// printdbg("The process group is %d\n", (int) task_tgid_nr(current));
	// printdbg("Writing to new Disk name: %s", rq->rq_disk->disk_name);
	// printdbg("Process name: %s, write_hint: %d, sector: %#llx, data_len: %#x\n", current->comm, rq->write_hint, rq->__sector, rq->__data_len);
	// printwmodname("blk_account_io_start() after\n\n");


		struct cxl_memdev *cxlmd = to_cxl_memdev(port->uport_dev);
	struct device *host = cxlmd->dev.parent;
	struct device *dev = &port->dev;
	struct pci_doe_mb *cdat_doe;
	size_t cdat_length;
	void *cdat_table;
	int rc;

	if (!dev_is_pci(host))
		return;
	cdat_doe = pci_find_doe_mailbox(to_pci_dev(host),
					PCI_DVSEC_VENDOR_ID_CXL,
					CXL_DOE_PROTOCOL_TABLE_ACCESS);
	if (!cdat_doe) {
		dev_dbg(dev, "No CDAT mailbox\n");
		return;
	}

	port->cdat_available = true;

	if (fh_cxl_cdat_get_length(dev, cdat_doe, &cdat_length)) {
		dev_dbg(dev, "No CDAT length\n");
		return;
	}

	cdat_table = devm_kzalloc(dev, cdat_length + sizeof(__le32),
				  GFP_KERNEL);
	if (!cdat_table)
		return;

	rc = fh_cxl_cdat_read_table(dev, cdat_doe, cdat_table, &cdat_length);
	if (rc) {
		/* Don't leave table data allocated on error */
		devm_kfree(dev, cdat_table);
		dev_err(dev, "CDAT data read error\n");
		return;
	}

	port->cdat.table = cdat_table + sizeof(__le32);
	port->cdat.length = cdat_length;
}

#define SYSCALL_NAME(name) (name)

#define HOOK(_name, _function, _original)	\
	{					\
		.name = SYSCALL_NAME(_name),	\
		.function = (_function),	\
		.original = (_original),	\
	}

static struct ftrace_hook demo_hooks[] = {
	HOOK("read_cdat_data",  fh_read_cdat_data,  &real_read_cdat_data),
	HOOK("cxl_cdat_get_length",  fh_cxl_cdat_get_length,  &real_cxl_cdat_get_length),
	HOOK("cxl_cdat_read_table",  fh_cxl_cdat_read_table,  &real_cxl_cdat_read_table),
};

static int fh_init(void)
{
	int err;

	err = fh_install_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
	if (err)
		return err;

	printwmodname("module loaded\n");

	return 0;
}
module_init(fh_init);

static void fh_exit(void)
{
	fh_remove_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));

	printwmodname("module unloaded\n");
}
module_exit(fh_exit);
