#ifndef _VARS_H
#define _VARS_H


struct queue *head=NULL, *tail=NULL;

struct mutex mutex;
int qlen=0;
int qmax = 10;

struct shared_queue *shared_head=NULL, *shared_tail=NULL;

struct mutex shared_mutex;
int shared_qlen=0;
int shared_qmax=5;


struct workqueue_struct *superio_workqueue;

static void nl_send_msg(struct return_struct ret_struct, int pid);
extern int add_to_produce(void *arg);

extern int consume(void *arg);

#endif
