#ifndef SOF_H
#define SOF_H

#define STRUCT_FILE_SIZE 232
#define OFFSET_TO_FOP 40
#define OFFSET_TO_PRIVATE_DATA 200

struct file_operations {
	void *owner;
	void *llseek;
	void *read;
	void *write;
	void *read_iter;
	void *write_iter;
	void *iopoll;
	void *iterate;
	void *iterate_shared;
	void *poll;
	void *unlocked_ioctl;
	void *compat_ioctl;
	void *mmap;
	unsigned long mmap_supported_flags;
	void *open;
	void *flush;
	void *release;
	void *fsync;
	void *fasync;
	void *lock;
	void *sendpage;
	void *get_unmapped_area;
	void *check_flags;
	void *flock;
	void *splice_write;
	void *splice_read;
	void *setlease;
	void *fallocate;
	void *show_fdinfo;
	void *copy_file_range;
	void *remap_file_range;
	void *fadvise;
};

struct file{
	unsigned char begin[40];
	struct file_operations *f_op;
	unsigned char between[152];
	void *private_data;
	unsigned char rest[24];
};

#endif