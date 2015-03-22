#ifndef _EX_H
#define _EX_H


extern struct queue *head, *tail;

extern struct mutex mutex;
extern int qlen;
extern int qmax;


extern struct shared_queue *shared_head, *shared_tail;

extern struct mutex shared_mutex;
extern int shared_qlen;
extern int shared_qmax;


extern struct workqueue_struct *superio_workqueue;

extern work_func_t get_work_func(JOB_INFO_ACTION act);

extern void my_encrypt_func(struct work_struct *work);

#endif
