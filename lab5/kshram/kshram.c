/*
 * Lab problem set for UNIX programming course
 * by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 * License: GPLv2
 */
#include <linux/module.h>	// included for all kernel modules
#include <linux/kernel.h>	// included for KERN_INFO
#include <linux/init.h>		// included for __init and __exit macros
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/errno.h>
#include <linux/sched.h>	// task_struct requried for current_uid()
#include <linux/cred.h>		// for current_uid();
#include <linux/slab.h>		// for kmalloc/kfree
#include <linux/uaccess.h>	// copy_to_user
#include <linux/string.h>
#include <linux/device.h>
#include <linux/cdev.h>

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mm_types.h>

#include "kshram.h"

#define NUM_OF_DEV 8
#define DEBUG 0

static dev_t devnum;
static struct cdev c_dev;
static struct class *clazz;

typedef struct _memory{
	void *begin;
	size_t len;
}memory;

static memory data[NUM_OF_DEV];

static int kshram_dev_open(struct inode *i, struct file *f) {
#if DEBUG
	printk(KERN_INFO "kshram/open: device opened.\n");
#endif
	return 0;
}

static int kshram_dev_close(struct inode *i, struct file *f) {
#if DEBUG
	printk(KERN_INFO "kshram/close: device closed.\n");
#endif
	return 0;
}

static ssize_t kshram_dev_read(struct file *f, char __user *buf, size_t len, loff_t *off) {
#if DEBUG
	printk(KERN_INFO "kshram/read: %zu bytes @ %llu.\n", len, *off);
#endif
	return len;
}

static ssize_t kshram_dev_write(struct file *f, const char __user *buf, size_t len, loff_t *off) {
#if DEBUG
	printk(KERN_INFO "kshram/write: %zu bytes @ %llu.\n", len, *off);
#endif
	return len;
}

static long kshram_dev_ioctl(struct file *fp, unsigned int cmd, unsigned long arg) {
	int index = iminor(fp->f_inode);
#if DEBUG
	printk(KERN_INFO "kshram/ioctl: fp:[%d:%d] cmd=%u arg=%lu.\n", imajor(fp->f_inode), index, cmd, arg);
#endif
	if(cmd == KSHRAM_GETSLOTS){
		return NUM_OF_DEV;
	}else if(cmd == KSHRAM_GETSIZE){
		return data[index].len;
	}else if(cmd == KSHRAM_SETSIZE){
		data[index].len = arg;
		data[index].begin = krealloc(data[index].begin, data[index].len, GFP_KERNEL);
		if(!data[index].begin) return -1;
	}
	return 0;
}

static int kshram_dev_mmap(struct file *fp, struct vm_area_struct *vma) {
	unsigned long pfn;
	int index = iminor(fp->f_inode), ret;
	unsigned long vsize = (vma->vm_end - vma->vm_start);
	unsigned long ksize = data[index].len;
	printk(KERN_INFO "kshram/mmap: idx %d size %lu\n", index, data[index].len);
	if (vsize > ksize) return -EINVAL;
	pfn = page_to_pfn(virt_to_page(data[index].begin));
    if (!pfn) return -ENXIO;
    ret = remap_pfn_range(vma, vma->vm_start, pfn, ksize, vma->vm_page_prot);
    if(ret) return ret;
	return 0;
}

static const struct file_operations kshram_dev_fops = {
	.owner = THIS_MODULE,
	.open = kshram_dev_open,
	.read = kshram_dev_read,
	.write = kshram_dev_write,
	.unlocked_ioctl = kshram_dev_ioctl,
	.mmap = kshram_dev_mmap,
	.release = kshram_dev_close
};

static int kshram_proc_read(struct seq_file *m, void *v) {
	for(int i = 0; i < NUM_OF_DEV; i++){
		seq_printf(m, "%02d: %lu\n", i, data[i].len);
	}
	return 0;
}

static int kshram_proc_open(struct inode *inode, struct file *file) {
	return single_open(file, kshram_proc_read, NULL);
}

static const struct proc_ops kshram_proc_fops = {
	.proc_open = kshram_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static char *kshram_devnode(const struct device *dev, umode_t *mode) {
	if(mode == NULL) return NULL;
	*mode = 0666;
	return NULL;
}

static int __init kshram_init(void)
{
	// create char dev
	if(alloc_chrdev_region(&devnum, 0, NUM_OF_DEV, "updev") < 0)
		return -1;
	if((clazz = class_create(THIS_MODULE, "upclass")) == NULL)
		goto release_region;
	clazz->devnode = kshram_devnode;
	for(int i = 0; i < NUM_OF_DEV; i++){
		char name[20];
    	snprintf(name, sizeof(name), "kshram%d", i);
		if(device_create(clazz, NULL, MKDEV(MAJOR(devnum), MINOR(devnum) + i), NULL, name) == NULL)
			goto release_class;
		data[i].len = 4096;
		data[i].begin = kzalloc(data[i].len, GFP_KERNEL);
		if(!data[i].begin) return -ENOMEM;
		printk(KERN_INFO "kshram%d: %lu bytes allocated @ %llx\n", i, data[i].len, (uint64_t) data[i].begin);
	}
	
	cdev_init(&c_dev, &kshram_dev_fops);
	if(cdev_add(&c_dev, devnum, NUM_OF_DEV) == -1)
		goto release_device;

	// create proc
	proc_create("kshram", 0, NULL, &kshram_proc_fops);

	printk(KERN_INFO "kshram: initialized.\n");
	return 0;    // Non-zero return means that the module couldn't be loaded.

release_device:
	for(int i = 0; i < NUM_OF_DEV; i++){
        char name[20];
        snprintf(name, sizeof(name), "kshram%d", i);
        device_destroy(clazz, MKDEV(MAJOR(devnum), MINOR(devnum) + i));
    }
release_class:
	class_destroy(clazz);
release_region:
	unregister_chrdev_region(devnum, NUM_OF_DEV);
	return -1;
}

static void __exit kshram_cleanup(void)
{
	remove_proc_entry("kshram", NULL);

	cdev_del(&c_dev);
	for(int i = 0; i < NUM_OF_DEV; i++){
        char name[20];
        snprintf(name, sizeof(name), "kshram%d", i);
        device_destroy(clazz, MKDEV(MAJOR(devnum), MINOR(devnum) + i));
		kfree(data[i].begin);
    }
	class_destroy(clazz);
	unregister_chrdev_region(devnum, 1);

	printk(KERN_INFO "kshram: cleaned up.\n");
}

module_init(kshram_init);
module_exit(kshram_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("cps");
MODULE_DESCRIPTION("The unix programming course lab5.");
