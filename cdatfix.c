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

MODULE_IMPORT_NS(CXL);

#define HASHTABLE_BITS 16

// From drivers/cxl/core/pci.c
#define CXL_DOE_TABLE_ACCESS_REQ_CODE		0x000000ff
#define CXL_DOE_TABLE_ACCESS_REQ_CODE_READ	0
#define CXL_DOE_TABLE_ACCESS_TABLE_TYPE		0x0000ff00
#define CXL_DOE_TABLE_ACCESS_TABLE_TYPE_CDATA	0
#define CXL_DOE_TABLE_ACCESS_ENTRY_HANDLE	0xffff0000
#define CXL_DOE_TABLE_ACCESS_LAST_ENTRY		0xffff
#define CXL_DOE_PROTOCOL_TABLE_ACCESS 2

#define CDAT_DOE_REQ(entry_handle) cpu_to_le32				\
	(FIELD_PREP(CXL_DOE_TABLE_ACCESS_REQ_CODE,			\
		    CXL_DOE_TABLE_ACCESS_REQ_CODE_READ) |		\
	 FIELD_PREP(CXL_DOE_TABLE_ACCESS_TABLE_TYPE,			\
		    CXL_DOE_TABLE_ACCESS_TABLE_TYPE_CDATA) |		\
	 FIELD_PREP(CXL_DOE_TABLE_ACCESS_ENTRY_HANDLE, (entry_handle)))


struct process_name {
	char* pname;
	struct request* req;
	struct hlist_node node;
};

// Uncomment the following line to enable logging to dmesg.
#define DEBUG_MODULE

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

static int cxl_cdat_get_length(struct device *dev,
			       struct pci_doe_mb *cdat_doe,
			       size_t *length)
{
	__le32 request = CDAT_DOE_REQ(0);
	__le32 response[2];
	int rc;

	rc = pci_doe(cdat_doe, PCI_DVSEC_VENDOR_ID_CXL,
		     CXL_DOE_PROTOCOL_TABLE_ACCESS,
		     &request, sizeof(request),
		     &response, sizeof(response));
	if (rc < 0) {
		dev_err(dev, "DOE failed: %d", rc);
		return rc;
	}
	if (rc < sizeof(response))
		return -EIO;

	*length = le32_to_cpu(response[1]);
	dev_dbg(dev, "CDAT length %zu\n", *length);

	return 0;
}

static int cxl_cdat_read_table(struct device *dev,
			       struct pci_doe_mb *cdat_doe,
			       void *cdat_table, size_t *cdat_length)
{
	size_t length = *cdat_length + sizeof(__le32);
	__le32 *data = cdat_table;
	int entry_handle = 0;
	__le32 saved_dw = 0;
	do {
		printwmodname("cxl_cdat_read_table() expected length: %lu\n\n", length);
		printwmodname("of which, *cdat_length=%lu, sizeof(__le32)=%lu\n\n", *cdat_length, sizeof(__le32));
		__le32 request = CDAT_DOE_REQ(entry_handle);
		struct cdat_entry_header *entry;
		size_t entry_dw;
		int rc;
		printwmodname("cxl_cdat_read_table() 2\n\n");
		rc = pci_doe(cdat_doe, PCI_DVSEC_VENDOR_ID_CXL,
			     CXL_DOE_PROTOCOL_TABLE_ACCESS,
			     &request, sizeof(request),
			     data, length);
		if (rc < 0) {
			dev_err(dev, "DOE failed: %d", rc);
			return rc;
		}
		printwmodname("cxl_cdat_read_table() 3: checking values\n\n");
		/* 1 DW Table Access Response Header + CDAT entry */
		entry = (struct cdat_entry_header *)(data + 1);
		printwmodname("entry_handle: %d\n", entry_handle);
		printwmodname("rc: %d\n", rc);
		printwmodname("sizeof(__le32): %lu\n", sizeof(__le32));
		if (entry_handle == 0){
			printwmodname("sizeof(struct cdat_header): %lu\n", sizeof(struct cdat_header));
		}else{
			printwmodname("le16_to_cpu(entry->length): %d\n", le16_to_cpu(entry->length));
		}
		
		if ((entry_handle == 0 &&
		     rc != sizeof(__le32) + sizeof(struct cdat_header)) ||
		    (entry_handle > 0 &&
		     (rc < sizeof(__le32) + sizeof(*entry) ||
		      rc != sizeof(__le32) + le16_to_cpu(entry->length))))
			return -EIO;
		printwmodname("cxl_cdat_read_table() 4\n\n");
		/* Get the CXL table access header entry handle */
		entry_handle = FIELD_GET(CXL_DOE_TABLE_ACCESS_ENTRY_HANDLE,
					 le32_to_cpu(data[0]));
		entry_dw = rc / sizeof(__le32);
		/* Skip Header */
		entry_dw -= 1;
		/*
		 * Table Access Response Header overwrote the last DW of
		 * previous entry, so restore that DW
		 */
		*data = saved_dw;
		length -= entry_dw * sizeof(__le32);
		data += entry_dw;
		saved_dw = *data;
		printwmodname("cxl_cdat_read_table() 5\n\n");
	} while (entry_handle != CXL_DOE_TABLE_ACCESS_LAST_ENTRY);

	/* Length in CDAT header may exceed concatenation of CDAT entries */
	*cdat_length -= length - sizeof(__le32);

	return 0;
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

	if (cxl_cdat_get_length(dev, cdat_doe, &cdat_length)) {
		dev_dbg(dev, "No CDAT length\n");
		return;
	}

	cdat_table = devm_kzalloc(dev, cdat_length + sizeof(__le32),
				  GFP_KERNEL);
	if (!cdat_table)
		return;

	rc = cxl_cdat_read_table(dev, cdat_doe, cdat_table, &cdat_length);
	if (rc) {
		/* Don't leave table data allocated on error */
		devm_kfree(dev, cdat_table);
		dev_err(dev, "CDAT data read error - from the kernel module\n");
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
