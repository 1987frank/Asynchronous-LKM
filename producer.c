
#include "sys_xjob.h"
#include "externs.h"

void add2queue(struct queue *q)
{
	BUG_ON(!q);
	q->next = NULL;

	if(tail) {
		tail->next = q;
	}
	else {
		head = q;
	}

	tail = q;

	return;
}


struct shared_queue *remove_first_shared_job(void)
{
        struct shared_queue *q = NULL, *temp = NULL;
        BUG_ON(!shared_head);

        if(!shared_head->next){
                q = shared_head;
                shared_head = NULL;
		shared_tail = NULL;
                goto out;
        }

        q = shared_head;
        temp = shared_head->next;
        shared_head = temp;

out:
        return q;
}


int produce(struct my_work_t *work)
{
  struct queue *q;
  int err = 0;
  work_func_t work_func = NULL;
  
  mutex_lock(&mutex);
  if (qlen >= qmax) {
    err = -EBUSY;
    goto out;
  }

  q = kmalloc(sizeof(struct queue), GFP_KERNEL);
  if (q == NULL) {
   err = -ENOMEM;
   goto out;
  }

  q->work = work; // insert job into queue cell

  work_func = get_work_func(work->job->info->action);

  BUG_ON(!work_func);

  //add to workqueue
  INIT_WORK( (struct work_struct *) work, work_func);

  init_completion(&work->comp);

  add2queue(q); // add new job to end of queue
  qlen++;

  printk("producer: qlen val:%d\n",qlen);

out:
  mutex_unlock(&mutex);

  return err;
}


int add_to_produce(void *arg)
{
	int err = 0;
	struct shared_queue *q = NULL;
	my_work_t *work = NULL;
	JOB* job = NULL;


	while(!kthread_should_stop()){
		mutex_lock(&shared_mutex);

		if (shared_qlen == 0) {
			mutex_unlock(&shared_mutex);
			msleep(100);
			continue;
		}

		q = remove_first_shared_job();
		shared_qlen--;

		job = q->j_arg;

		mutex_unlock(&shared_mutex);

                kfree(q);

		//Create work structure and add it to the queue
                work = (my_work_t *)kmalloc(sizeof(my_work_t), GFP_KERNEL);
                if (work) {
		     work->job = job;
		     err = produce(work);

		     while(err == -EBUSY){
			msleep(100);
			err = produce(work);
		     }

                }
        }

	return err;
}
