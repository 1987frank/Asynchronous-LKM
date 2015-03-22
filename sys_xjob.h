#ifndef _SYS_XJOB_H
#define _SYS_XJOB_H

#define PAGESIZE 4096

#define DEF_OUT_MODE 0644

#include <linux/linkage.h>
#include <linux/moduleloader.h>

#include <linux/fs.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/quota.h>
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/crypto.h>
#include <linux/mm.h>
#include <linux/kthread.h>
#include <linux/timer.h>
#include <linux/delay.h>
#include <asm/siginfo.h>
#include <linux/pid_namespace.h>
#include <linux/pid.h>
#include <net/sock.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/fs.h>
#include <linux/fs_stack.h>


typedef enum job_type {
	SUBMIT_JOB,	//submit a new job
	REMOVE_JOB,	//remove an already submitted job
  	LIST_JOB	//list all submitted jobs
}JOB_TYPE;



typedef enum job_out_mode {
  	DEL,		//delete existing file
  	RENAME,		//rename existing
  	NEW		//save as a new file
}JOB_OUT_MODE;


typedef enum job_info_action {
  	ENCRYPT,
  	DECRYPT,
  	COMPRESS,
	DECOMPRESS,
	CHECKSUM,
	JOB_REMOVED
}JOB_INFO_ACTION;



struct encrypt_info {
  __user char* 	key;
};

struct user_job_info {
  __user char*	finname;
  __user char*	foutname;
  __user char*  foutrename;
  int maxlen;
  __user void* data;
  JOB_OUT_MODE 		mode;
  JOB_INFO_ACTION 	action;
  JOB_TYPE    		type;

  union {
    struct encrypt_info encrypt;
  }action_param;

};

struct ret_checksum {
  u32 crc;
  int ret;
};

struct ret_enc_dec {
  int ret;
};

struct ret_comp_decomp {
  int ret;
};

struct remove_job {
  int pid;
};

struct return_struct {
  JOB_INFO_ACTION       action;
  union {
    struct ret_checksum ret_cs;
    struct ret_enc_dec ret_ed;
    struct ret_comp_decomp ret_cd;
    struct remove_job ret_rj;
  }rs;
};

struct job_list {
  int pid;
  JOB_INFO_ACTION       action;
};



typedef struct job {
  struct task_struct* 	process_id; //store submitting user-process task struct. Useful for obtaining pid from it later
  struct user_job_info*	info;
} JOB;



typedef struct my_work_t{
  struct work_struct 	my_work;
  struct completion 	comp;
  JOB*   		job;
} my_work_t;


struct queue {
	my_work_t* 	work;
	struct queue*	next;
};

struct shared_queue {
	JOB*			j_arg;
	struct shared_queue*	next;
};


u32 crc32c(u32 crc, const u8 *data, unsigned int length);
int decrypt(char *in_file, char *out_file, char *key);
int encrypt(char *in_file, char *out_file, char *key);
int compress(char *in_file, char *out_file);
int decompress(char *in_file, char *out_file);


static inline struct dentry *lock_parent(struct dentry *dentry)
{
        struct dentry *dir = dget_parent(dentry);
        mutex_lock_nested(&dir->d_inode->i_mutex, I_MUTEX_PARENT);
        return dir;
}

static inline void unlock_dir(struct dentry *dir)
{
        mutex_unlock(&dir->d_inode->i_mutex);
        dput(dir);
}

#endif
