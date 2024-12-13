#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>

// Prozessinformationsknotenstruktur
struct process_info
{
	pid_t pid;
	char comm[TASK_COMM_LEN];
	struct list_head list;
};

// Kopf der Prozessinformations-Verketteten Liste
static LIST_HEAD(process_list);

// Kprobe f?r kernel_clone
static struct kprobe kp_clone = {
	.symbol_name = "kernel_clone",
};

// Kprobe f?r do_exit
static struct kprobe kp_exit = {
	.symbol_name = "do_exit",
};

// kernel_clone pre_handler
static int handler_pre_clone(struct kprobe *p, struct pt_regs *regs)
{
	struct process_info *new_node;
	
	new_node = kmalloc(sizeof(*new_node), GFP_KERNEL);
	if (!new_node)
	{
		printk(KERN_ERR "[kprobe] Fehler beim Zuweisen von Speicher f?r process_info-Knoten\n");
		return -ENOMEM;
	}

	new_node->pid = current->pid;
	strncpy(new_node->comm, current->comm, TASK_COMM_LEN);

	// Synchronisation absichtlich weggelassen f?r Demonstrationszwecke
	list_add(&new_node->list, &process_list);

	printk(KERN_INFO "[kprobe] Prozess erstellt: %s (pid: %d)\n", current->comm, current->pid);
	return 0;
}

// do_exit pre_handler
static int handler_pre_exit(struct kprobe *p, struct pt_regs *regs)
{
	struct process_info *entry, *tmp;

	// Synchronisation absichtlich weggelassen f?r Demonstrationszwecke
	list_for_each_entry(entry, &process_list, list)
	{
		if (entry->pid == current->pid)
		{
			list_del(&entry->list);
			kfree(entry);
			;
			printk(KERN_INFO "[kprobe] Prozess beendet: %s (pid: %d)\n", current->comm, current->pid);
			break;
		}
	}

	return 0;
}

// Modulinitialisierung
static int __init kprobe_init(void)
{
	int ret;

	// Kprobe f?r kernel_clone registrieren
	kp_clone.pre_handler = handler_pre_clone;
	ret = register_kprobe(&kp_clone);
	if (ret < 0)
	{
		printk(KERN_ERR "[kprobe] Fehler beim Registrieren der Kprobe f?r kernel_clone: %d\n", ret);
		return ret;
	}
	printk(KERN_INFO "[kprobe] Kprobe bei kernel_clone registriert\n");

	// Kprobe f?r do_exit registrieren
	kp_exit.pre_handler = handler_pre_exit;
	ret = register_kprobe(&kp_exit);
	if (ret < 0)
	{
		printk(KERN_ERR "[kprobe] Fehler beim Registrieren der Kprobe f?r do_exit: %d\n", ret);
		unregister_kprobe(&kp_clone);
		return ret;
	}
	printk(KERN_INFO "[kprobe] Kprobe bei do_exit registriert\n");

	return 0;
}

// Modulausgang
static void __exit kprobe_exit(void)
{
	struct process_info *entry, *tmp;

	unregister_kprobe(&kp_clone);
	printk(KERN_INFO "[kprobe] Kprobe f?r kernel_clone abgemeldet\n");

	unregister_kprobe(&kp_exit);
	printk(KERN_INFO "[kprobe] Kprobe f?r do_exit abgemeldet\n");

	// Prozessliste bereinigen
	list_for_each_entry_safe(entry, tmp, &process_list, list)
	{
		list_del(&entry->list);
		kfree(entry);
	}
}

module_init(kprobe_init);
module_exit(kprobe_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Lukax");
MODULE_DESCRIPTION("Linux-Kernel zur Erkennung und Deinstallation von Prozessen mit kprobe_clone und do_exit");
