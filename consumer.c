
#include "sys_xjob.h"

#include "externs.h"

struct queue *remove_first_job(void)
{
	struct queue *q = NULL, *temp = NULL;
	BUG_ON(!head);
	
	if(!head->next){
		q = head;
		head = NULL;
		tail = NULL;
		goto out;
	}
	
	q = head;
	temp = head->next;
	head = temp;

out:
	return q;
}


int consume(void *arg)
{
  struct queue *q;
  struct my_work_t *work;
  int ret=0;


 while(!kthread_should_stop()){
 
  mutex_lock(&mutex);
  if (qlen == 0) {
    mutex_unlock(&mutex);
    msleep(500);
    continue;
  }

  q = remove_first_job(); // pull first job
  qlen--;

  printk("consumer: qlen val c:%d\n", qlen);

  work = q->work;

  mutex_unlock(&mutex);

  //perform work in the workqueue
  ret = queue_work( superio_workqueue, (struct work_struct *)work);

  wait_for_completion(&work->comp);
  printk("consumer: queue_work done\n");

  kfree( work );
  kfree(q);

 }

  return ret;
}



