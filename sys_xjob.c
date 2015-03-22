/*#include <linux/linkage.h>
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
*/



#include "sys_xjob.h"

#include "variables.h"

asmlinkage extern long (*sysptr)(void *arg, int argslen);



//static struct workqueue_struct *superio_workqueue;
static struct task_struct *kproducerd;
static struct task_struct *kconsumerd;

#define NETLINK_USER 31

struct sock *nl_sk = NULL; 


static void add_to_shared_queue(struct shared_queue *q)
{
	BUG_ON(!q);
	//BUG_ON(!shared_tail->next);
	q->next = NULL;

	if(shared_tail){
		shared_tail->next = q;
	}
	else {
		shared_head = q;
	}
	
	shared_tail = q;

	return;
}

int  getjoblist(struct job_list **lst)
{
  int err=0;
  my_work_t *wrk;
  int lstno=0;
  struct job_list *temp=NULL;
  struct queue *iter=head;
  mutex_lock(&mutex);
  printk("queue length %d..\n",qlen);
  if(qlen<=0)
    goto out;
  temp=kmalloc(qlen*sizeof(struct job_list),GFP_KERNEL);
  if(!temp) {
    err=-ENOMEM;
    goto out;
  }

    while(iter && lstno<qlen) {
      wrk=iter->work;
      temp[lstno].action=wrk->job->info->action;
      printk("qs...\n");
      temp[lstno].pid=wrk->job->process_id->pid;
      iter=iter->next;
      lstno++;
    }

 out:
    if(!err) {
      *lst=temp;
      err=lstno;
    }
    mutex_unlock(&mutex);
    return err;
}


int removejob(struct job_list jobitem, int process_pid)
{
  int pid;
  //int action;
  int err=0;
  my_work_t *wrk=NULL;
  struct queue *iter=head,*prev=NULL;
  mutex_lock(&mutex);
  if(qlen<=0) {
    err=-EINVAL;
    goto out;
  }
 while(iter) {
   wrk=iter->work;
   //action=wrk->job->info->action;
    pid=wrk->job->process_id->pid;
    if(/*action==jobitem.action &&*/ pid==jobitem.pid) {
      //printk("Removing..job-pid x%d action %d\n",pid,action);
	printk("Removing..job-pid: %d\n",pid);

      if(iter==head) {
	if(head == tail){
        	head = iter->next;
		tail = head;
	}
	else
		head = iter->next;
      }
      else if(iter == tail){
		tail = prev;
		prev->next=iter->next;
      }
      else {
        prev->next=iter->next;
      }

      qlen--;
      break;
    }
    prev=iter;
    iter=iter->next;
 }

 if(iter != NULL){
	struct return_struct ret_struct;
	ret_struct.action = JOB_REMOVED;
	ret_struct.rs.ret_rj.pid = process_pid;

	nl_send_msg(ret_struct, pid);	
 }

 if(iter==NULL)
   err=-EINVAL;

 out:
   mutex_unlock(&mutex);

 if(!err) {

   if(wrk->job->info->finname)
    putname(wrk->job->info->finname);
 if(wrk->job->info)
    kfree(wrk->job->info);

  if(wrk->job)
    kfree(wrk->job);

  if(wrk)
    kfree(wrk);

  if(iter)
    kfree(iter);
 }
 return err;
}

int check_params(struct user_job_info* userji)
{
	int err=0;
	if(userji->action != ENCRYPT &&
		userji->action != DECRYPT && 
		userji->action != COMPRESS &&
		userji->action != DECOMPRESS &&
		userji->action != CHECKSUM &&
		userji->action != JOB_REMOVED)
	{
		printk("invalid user action:%d\n", userji->action);
		err = -EINVAL;
		goto out;
	}


	if(userji->type != SUBMIT_JOB &&
		userji->type != REMOVE_JOB &&
		userji->type != LIST_JOB)
	{
		printk("invalid user type:%d\n", userji->type);
                err = -EINVAL;
                goto out;
	}


	if(userji->mode != DEL &&
        	userji->mode != RENAME &&
		userji->mode != NEW)
	{
		printk("invalid user mode:%d\n", userji->mode);
		err = -EINVAL;
		goto out;
	}

out:
	return err;
}


asmlinkage long xjob(void *arg, int argslen)
{
	void* args_copy;
	struct user_job_info* user_ji = NULL;
        //JOB_INFO* ji = NULL;
	JOB* job = NULL;
	int err = 0;//,i = 0;
	struct shared_queue *q = NULL;

	if (arg == NULL){
                printk("sys_xjob: argument passed is NULL\n");
                err = -EINVAL;
                goto out;
        }

        if(argslen < 0){
		printk("sys_xjob: argslen less than 0:%d\n", argslen);
                err = -EINVAL;
                goto out;
        }

        if(argslen != sizeof(struct user_job_info)){            //check the length passed against the length of structure
                printk("sys_xjob: invalid arg length passed: argslen:%d, size:%d\n", argslen, sizeof(struct user_job_info));
                err = -EINVAL;
                goto out;
        }

        if(!access_ok(VERIFY_READ, arg, argslen)){       //check for bad address range
                printk("sys_xjob: verify area (access_ok) failed for arg\n");
                err = -EFAULT;
                goto out;
        }
	
	args_copy = kmalloc(argslen, GFP_KERNEL);

        if(!args_copy){
                err = -ENOMEM;
                goto out;
        }

        if(copy_from_user(args_copy, arg, argslen)){
                printk("sys_xjob: copy arg from user failed\n");
                err = -EFAULT;
                goto free;
        }

        user_ji = (struct user_job_info *) args_copy;

	err = check_params(user_ji);
	if(err < 0){
		goto free;
	}

	//check temp queue is full
	mutex_lock(&shared_mutex);

        if(shared_qlen >= shared_qmax){
		mutex_unlock(&shared_mutex);
		err = -EBUSY;
		goto free;
	}		

        mutex_unlock(&shared_mutex);


	//Listing jobs
	if(user_ji->type == LIST_JOB){

		struct job_list *lst;
		int len;

		len=getjoblist(&lst);
	        printk("len..%d..\n",len);

		err=len;

          	if(!len)
	            goto free;

	        if(len > user_ji->maxlen)
            	    len=len>user_ji->maxlen;

	        if(copy_to_user(user_ji->data, (void*) lst, len * sizeof(struct job_list))) {
	            err=-EFAULT;
        	    goto free;
          	}
	}
	else if(user_ji->type == REMOVE_JOB){
		if(user_ji->maxlen == 1) {
	            struct job_list *remove_job=(struct job_list*)kmalloc(sizeof(struct job_list)*user_ji->maxlen,GFP_KERNEL);

	            if(!remove_job) {
        	      err=-ENOMEM;
	              goto free;
	            }
	
	            if(copy_from_user(remove_job,user_ji->data,sizeof(struct job_list)*user_ji->maxlen)) {
	              err=-EFAULT;
	              goto free;
	            }
        
		    printk("bfore remove job..\n");

	            err=removejob(*remove_job, current->pid);
        	    //goto free;
          	}
		else {
			err = -EINVAL;
			goto free;
		}	
	}
	//IF JOB TYPE IS SUBMIT JOB
	else if(user_ji->type == SUBMIT_JOB){

	user_ji->finname = getname(user_ji->finname);

	if(IS_ERR(user_ji->finname)){
		printk("sys_xjob: getname err: %ld\n", PTR_ERR(user_ji->finname));
                err = PTR_ERR(user_ji->finname);
                goto free;
	}

	if(user_ji->action != CHECKSUM){
		user_ji->foutname = getname(user_ji->foutname);

		if(IS_ERR(user_ji->foutname)){
	                printk("sys_xjob: getname err: %ld\n", PTR_ERR(user_ji->foutname));
	                err = PTR_ERR(user_ji->foutname);
	                goto freename;
	        }

		if(user_ji->action == ENCRYPT || user_ji->action == DECRYPT){
			user_ji->action_param.encrypt.key = getname(user_ji->action_param.encrypt.key);
	
	        	if(IS_ERR(user_ji->action_param.encrypt.key)){
		                printk("sys_xjob: getname err: %ld\n", PTR_ERR(user_ji->action_param.encrypt.key));
		                err = PTR_ERR(user_ji->action_param.encrypt.key);
		                goto freeout;
		        }

			if(strlen(user_ji->action_param.encrypt.key) > 16){
				printk("sys_xjob: invalid key len : %s\n", user_ji->action_param.encrypt.key);
				err = -EINVAL;
				goto freekey;
			}
		}
	}

	if(user_ji->mode == RENAME){
		printk("sys_xjob: rename given\n");
		user_ji->foutrename = getname(user_ji->foutrename);
                if(IS_ERR(user_ji->foutrename)){
                        printk("sys_xjob: getname err: %ld\n", PTR_ERR(user_ji->foutrename));
                        err = PTR_ERR(user_ji->foutrename);
                        if(user_ji->action == CHECKSUM)
				goto freename;
			else
				goto freeout;
               	}
	}

        job = kmalloc(sizeof(JOB), GFP_KERNEL);
        if(!job){
                err = -ENOMEM;
                goto freeout;
        }

	job->info = user_ji;

	printk("user proces pid:%d\n", current->pid);

	job->process_id = current;

	//push into shared queue
	q = kmalloc(sizeof(struct shared_queue), GFP_KERNEL);

	if (q == NULL) {
   		err = -ENOMEM;
		goto freejob;
	}

	q->j_arg = job;

	mutex_lock(&shared_mutex);

	add_to_shared_queue(q);
	shared_qlen++;

	mutex_unlock(&shared_mutex);

	goto out;

freejob:
	kfree(job);

freekey:
	if(user_ji->action_param.encrypt.key)
	putname(user_ji->action_param.encrypt.key);

freeout:
	if(user_ji->foutname)
	putname(user_ji->foutname);

freename:
	if(user_ji->finname)
	putname(user_ji->finname);
}


free:
        kfree(args_copy);

out:
        return err;

}


int do_mode_op(char *infile, char *outfile, JOB_INFO_ACTION act, JOB_OUT_MODE mode)
{
	int err=0;
	struct file *filp = NULL;
	BUG_ON(!infile);

	if(mode == RENAME){
		struct inode *old_dir=NULL, *new_dir=NULL;
	        struct dentry *old_dentry=NULL, *new_dentry=NULL, *trap=NULL;
		struct file *filp_o = NULL;		
		BUG_ON(!outfile);

		filp = filp_open(infile, O_RDONLY, 0);
		if (!filp || IS_ERR(filp)){
			printk("sys_xjob: open err:%s\n", infile);
			err = PTR_ERR(filp);
			goto out;
		}

		old_dir = filp->f_dentry->d_parent->d_inode;
	        old_dentry = filp->f_dentry;
		filp_close(filp, NULL);

		filp_o = filp_open(outfile, O_RDONLY, 0);
                if (!filp_o || IS_ERR(filp_o)){

			if(PTR_ERR(filp_o) == -ENOENT){
				filp_o = filp_open(outfile, O_CREAT, DEF_OUT_MODE);
				if (!filp_o || IS_ERR(filp_o)){
		                        printk("sys_xjob: open err:%s\n", outfile);
					err = PTR_ERR(filp_o);
	                                goto out;
				}
			}
			else {
	                        err = PTR_ERR(filp_o);
        	                goto out;
			}
                }

		new_dir = filp_o->f_dentry->d_parent->d_inode;
	        new_dentry = filp_o->f_dentry;
		filp_close(filp_o, NULL);
		
		trap = lock_rename(old_dentry->d_parent, new_dentry->d_parent);
	        // source should not be ancestor of target 
	        if (trap == old_dentry){
	            printk("sys_xjob: source is ancestor of target\n");
	            err = -EINVAL;
	            goto out;
	        }
	        // target should not be ancestor of source 
	        if (trap == new_dentry){
	            printk("sys_xjob: target is ancestor of source\n");
	            err = -ENOTEMPTY;
	            goto out;
	        }
		
	        err = vfs_rename(old_dir, old_dentry, new_dir, new_dentry);
	        if(err){
	            printk("sys_xjob: vfs_rename error:%d\n", err);
	        }/*
		else {
		    fsstack_copy_attr_all(new_dentry->d_inode, old_dentry->d_inode);
		}*/
		
	        unlock_rename(old_dentry->d_parent, new_dentry->d_parent);

	}
	else if(mode == DEL){
		struct dentry *lower_dir_dentry=NULL, *old_dentry=NULL;
		struct inode *old_dir=NULL;
		
		filp = filp_open(infile, O_RDONLY, 0);
                if (!filp || IS_ERR(filp)){
                        printk("sys_xjob: open err:%s\n", infile);
                        err = PTR_ERR(filp);
                        goto out;
                }

                old_dir = filp->f_dentry->d_parent->d_inode;
                old_dentry = filp->f_dentry;
                filp_close(filp, NULL);

		lower_dir_dentry = lock_parent(old_dentry);
	    	err = vfs_unlink(old_dir, old_dentry);
	    	unlock_dir(lower_dir_dentry);

		if(err){
			printk("sys_xjob: vfs_unlink err:%d\n", err);
		}
	}

out:
	return err;
}


int get_checksum(char *file, u32 *crc32)
{
        struct file *filp_read = NULL;
        int bytes = 0, err = 0;
        mm_segment_t oldfs;
        char *buffer = NULL;//[16];
	buffer = kmalloc(16, GFP_KERNEL);
	if(!buffer){
		err = -ENOMEM;
		goto out;
	}

        filp_read = filp_open(file, O_RDONLY,0);

	if (filp_read == NULL || IS_ERR(filp_read)){
                err = (int)PTR_ERR(filp_read);
                filp_read = NULL;
                goto out;
        }

        if ( filp_read->f_op->read ){
                do{
                        oldfs = get_fs();
                        set_fs(KERNEL_DS);
                        bytes = vfs_read(filp_read, buffer, 8, &filp_read->f_pos);

                        set_fs(oldfs);

                        if (bytes < 0){
                                err = bytes;
                                goto out;
                        }

                        else if ( bytes > 0){
                                *crc32 = crc32c(*crc32, buffer, bytes);
                        }
                }while(bytes>0);
        }
        else {
                err =  -ENOSYS;
        }

out:
        if(filp_read)
                filp_close(filp_read,NULL);

	if(buffer)
		kfree(buffer);

        return err;

}

void calc_checksum( struct work_struct *work)
{
  JOB* jobp;
  int ret=0;
  u32 crc32=0;
  struct return_struct ret_struct;

  my_work_t *my_work = (my_work_t *)work;

  printk( "sys_xjob: doing my_work\n" );

  jobp=my_work->job;

  printk("Starting checksum %s:\n", jobp->info->finname);
  ret=get_checksum(jobp->info->finname, &crc32);
  printk( "Chksum DONE...FILE: %s, chksum: %u, ret: %d\n", jobp->info->finname, crc32, ret);

  if(!ret){
  ret = do_mode_op(jobp->info->finname, jobp->info->foutrename, jobp->info->action, jobp->info->mode);
  }

  ret_struct.action = CHECKSUM;
  ret_struct.rs.ret_cs.crc = crc32;
  ret_struct.rs.ret_cs.ret = ret;

  nl_send_msg(ret_struct, jobp->process_id->pid);

  if(jobp->info->finname)
    putname(jobp->info->finname);

  if(jobp->info->mode == RENAME){
	if(jobp->info->foutname)
	putname(jobp->info->foutname);
  }

  if(jobp->info)
    kfree(jobp->info);

  if(jobp)
    kfree(jobp);

  complete(&my_work->comp);
  return;

}


int getfilesize(char* fname)
{
  struct file* fin=NULL;
  char *buf=NULL;
  //mm_segment_t oldf;
  int bytes_read=0;
  int total_bytes=0;
  int err=0;

 // oldfs = get_fs();
 // set_fs(KERNEL_DS);

  fin = filp_open(fname, O_RDONLY, 0);

  if(!fin||IS_ERR(fin)){
    printk(KERN_ALERT "Input file %s, Open error %ld\n",fname,(PTR_ERR(fin)));
    err=PTR_ERR(fin);
    goto out;
  }


  fin->f_pos=0;

  buf=kmalloc(PAGE_SIZE,GFP_KERNEL);

  if(!buf) {
    err=-ENOMEM;
    goto out;
  }

  //oldfs = get_fs();
  //set_fs(KERNEL_DS);

  do{
    //Read PAGE_SIZE data from input-file
    bytes_read=vfs_read(fin,buf,PAGE_SIZE,&fin->f_pos);

    if(bytes_read<0){
      err=bytes_read;
      goto out;
    }

    //count the read data
    total_bytes+=bytes_read;
  }while(bytes_read>0);

  //set_fs(oldfs);

if(!err)
  err=total_bytes;

out:

 if(buf)
   kfree(buf);

 if(fin&&!IS_ERR(fin))
   filp_close(fin,NULL);


 return err;

}

void encrypt_job(struct work_struct *work)
{
  JOB* jobp;
  int ret=0;
  struct return_struct ret_struct;

  my_work_t *my_work = (my_work_t *)work;

  printk( "sys_xjob: doing my_work\n" );

  jobp=my_work->job;
  ret_struct.action = -1;

  if(jobp->info->action == ENCRYPT){

  	printk("Starting encrypt job: %s, out: %s\n", jobp->info->finname, jobp->info->foutname);
  	ret=encrypt(jobp->info->finname, jobp->info->foutname, jobp->info->action_param.encrypt.key);
  	printk( "encrypt DONE...FILE: %s, OUT: %s, ret: %d\n", jobp->info->finname, jobp->info->foutname, ret);
  	ret_struct.action = ENCRYPT;

  }
  else if(jobp->info->action == DECRYPT){

  	printk("Starting decrypt job: %s, out: %s\n", jobp->info->finname, jobp->info->foutname);
	ret=decrypt(jobp->info->finname, jobp->info->foutname, jobp->info->action_param.encrypt.key);
  	printk( "decrypt DONE...FILE: %s, OUT: %s, ret: %d\n", jobp->info->finname, jobp->info->foutname, ret);
  	ret_struct.action = DECRYPT;

  }

  if(!ret){
  ret = do_mode_op(jobp->info->finname, jobp->info->foutrename, jobp->info->action, jobp->info->mode);
  }

  ret_struct.rs.ret_ed.ret = ret;

  nl_send_msg(ret_struct, jobp->process_id->pid);

  if(jobp->info->foutname)
    putname(jobp->info->foutname);

  if(jobp->info->action_param.encrypt.key)
    putname(jobp->info->action_param.encrypt.key);

  if(jobp->info->finname)
    putname(jobp->info->finname);

  if(jobp->info)
    kfree(jobp->info);

  if(jobp)
    kfree(jobp);

  complete(&my_work->comp);
  return;

}

void compress_job(struct work_struct *work)
{
  JOB* jobp;
  int ret=0;
  struct return_struct ret_struct;

  my_work_t *my_work = (my_work_t *)work;

  printk( "sys_xjob: doing my_work\n" );

  jobp=my_work->job;
  ret_struct.action = -1;

  if(jobp->info->action == COMPRESS){
	
  	printk("Starting compress job: %s, out: %s\n", jobp->info->finname, jobp->info->foutname);
	ret = compress(jobp->info->finname, jobp->info->foutname);
	printk( "compress DONE...FILE: %s, OUT: %s, ret: %d\n", jobp->info->finname, jobp->info->foutname, ret);
  	ret_struct.action = COMPRESS;

  }
  else if(jobp->info->action == DECOMPRESS){

  	printk("Starting decompress job: %s, out: %s\n", jobp->info->finname, jobp->info->foutname);
  	ret = decompress(jobp->info->finname, jobp->info->foutname);
  	printk( "decompress DONE...FILE: %s, OUT: %s, ret: %d\n", jobp->info->finname, jobp->info->foutname, ret);
  	ret_struct.action = DECOMPRESS;

  }

  if(!ret){
  ret = do_mode_op(jobp->info->finname, jobp->info->foutrename, jobp->info->action, jobp->info->mode);
  }

  ret_struct.rs.ret_cd.ret = ret;

  nl_send_msg(ret_struct, jobp->process_id->pid);

  if(jobp->info->foutname)
    putname(jobp->info->foutname);

  if(jobp->info->finname)
    putname(jobp->info->finname);

  if(jobp->info)
    kfree(jobp->info);

  if(jobp)
    kfree(jobp);

  complete(&my_work->comp);
  return;

}


work_func_t get_work_func(JOB_INFO_ACTION act)
{
	printk("sys_xjob: job info action val: %d\n", act);
        switch(act){
                case ENCRYPT:
		case DECRYPT:
                        return encrypt_job;

		case COMPRESS:
		case DECOMPRESS:
			return compress_job;

		case CHECKSUM:
			return calc_checksum;
    
                default:
                        return NULL;

        }

}


static void nl_send_msg(struct return_struct ret_struct, int pid)
{
    struct nlmsghdr *nlh;
    struct sk_buff *skb_out;
    int msg_size;
    int res;

    printk(KERN_INFO "Entering: %s\n", __FUNCTION__);

    msg_size = sizeof(struct return_struct);//strlen(msg);

    //pid = nlh->nlmsg_pid; // pid of sending process 

    skb_out = nlmsg_new(msg_size, 0);

    if (!skb_out)
    {
        printk(KERN_ERR "Failed to allocate new skb\n");
        return;
    }

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
    //strncpy(nlmsg_data(nlh), msg, msg_size);
    memcpy(nlmsg_data(nlh), &ret_struct, msg_size);

    printk("sending msg action val :%d\n", ret_struct.action);

    res = nlmsg_unicast(nl_sk, skb_out, pid);

    if (res < 0)
        printk(KERN_INFO "Error while sending bak to user\n");

}

static int __init init_sys_xjob(void)
{
	int err;//, ret;
	printk("------------------------------------\n");
        printk("installing new sys_xjob module\n");

        if (sysptr == NULL)
                sysptr = xjob;

	nl_sk=netlink_kernel_create(&init_net, NETLINK_USER, 0, NULL, NULL, THIS_MODULE);  
    	if(!nl_sk)  
    	{   
            printk(KERN_ALERT "Error creating socket.\n");  
            return -10;  
    	}

	mutex_init(&mutex);
	mutex_init(&shared_mutex);

	//INITIALIZE WORK QUEUE
	superio_workqueue = create_workqueue("sys_xjobd");
	printk("sys_xjob: created workqueue\n");
	if (!IS_ERR(superio_workqueue)){
		//creating threads

		kproducerd = kthread_run(add_to_produce, NULL, "kproducerd");

		printk("sys_xjob: created KTHREAD_RUN1\n");
		if (IS_ERR(kproducerd))
	                return PTR_ERR(kproducerd);

		kconsumerd = kthread_run(consume, NULL, "kconsumerd");

		printk("sys_xjob: created KTHREAD_RUN2\n");
                if (IS_ERR(kconsumerd))
                        return PTR_ERR(kconsumerd);

		return 0;
	}

	err = PTR_ERR(superio_workqueue);
	printk(KERN_ERR " create_workqueue failed %d\n", err);
	superio_workqueue = NULL;
	return err;

}
static void  __exit exit_sys_xjob(void)
{
	//KILL THREADS
	kthread_stop(kproducerd);

	kthread_stop(kconsumerd);

	printk("sys_xjob: Threads stopped\n");

	//DESTROY QUEUE

	if (superio_workqueue){
		flush_workqueue( superio_workqueue );
		destroy_workqueue(superio_workqueue);
	}

	mutex_destroy(&mutex);
	mutex_destroy(&shared_mutex);

	netlink_kernel_release(nl_sk);

        if (sysptr != NULL)
                sysptr = NULL;
        printk("removed sys_xjob module\n");
	printk("------------------------------------\n");
}
module_init(init_sys_xjob);
module_exit(exit_sys_xjob);
MODULE_LICENSE("GPL");
