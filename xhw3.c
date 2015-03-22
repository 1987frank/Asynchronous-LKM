#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <strings.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <signal.h>
#include <stdint.h>
#include <pthread.h>

#include "includes.h"

#define __NR_xjob	349	/* our private syscall number */

#include <sys/socket.h>
#include <linux/netlink.h>
#define NETLINK_USER 31
#define MAX_PAYLOAD 1024 /* maximum payload size*/ 


struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
int sock_fd;
struct msghdr msg;

void interpret_msg(struct return_struct *ret)
{
	switch(ret->action)
	{
		case ENCRYPT:
			if(!ret->rs.ret_ed.ret)
				printf("Encryption done, ret :%d\n",  ret->rs.ret_ed.ret);
			else 
				printf("Encryption failed, ret :%d\n",  ret->rs.ret_ed.ret);
			
			break;

		case DECRYPT:
			if(!ret->rs.ret_ed.ret)
				printf("Decryption done, ret :%d\n", ret->rs.ret_ed.ret);
			else
				printf("Decryption failed, ret :%d\n", ret->rs.ret_ed.ret);
			break;

		case COMPRESS:
			if(!ret->rs.ret_cd.ret)
	                        printf("Compress done, ret :%d\n",  ret->rs.ret_cd.ret);
			else
				printf("Compress failed, ret :%d\n",  ret->rs.ret_cd.ret);
                        break;

                case DECOMPRESS:
			if(!ret->rs.ret_cd.ret)
	                        printf("Decompress done, ret :%d\n", ret->rs.ret_cd.ret);
			else
				printf("Decompress failed, ret :%d\n", ret->rs.ret_cd.ret);
                        break;

		case CHECKSUM:
			if(!ret->rs.ret_cs.ret)
				printf("Checksum obtained: %u\n", ret->rs.ret_cs.crc);
			else 
				printf("Checksum failed: %d\n", ret->rs.ret_cs.ret);
			
			break;

		case JOB_REMOVED:
			printf("Job was removed, pid of process who killed (%d)\n", ret->rs.ret_rj.pid);
			break;

		default:
			printf("Unknown val returned: %d\n", ret->action);
	}

}

void* call_netlink(void* arg)
{

	sock_fd=socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);  
	if(sock_fd<0)  
	    return NULL;  

	memset(&src_addr, 0, sizeof(src_addr));  
	src_addr.nl_family = AF_NETLINK;  
	src_addr.nl_pid = getpid();  /* self pid */  
	/* interested in group 1<<0 */  
	bind(sock_fd, (struct sockaddr*)&src_addr,  
	  sizeof(src_addr));  

	memset(&dest_addr, 0, sizeof(dest_addr));  
	memset(&dest_addr, 0, sizeof(dest_addr));  
	dest_addr.nl_family = AF_NETLINK;  
	dest_addr.nl_pid = 0;   /* For Linux Kernel */  
	dest_addr.nl_groups = 0; /* unicast */  

	nlh = (struct nlmsghdr *)malloc(  
	                      NLMSG_SPACE(MAX_PAYLOAD));  
	memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));  
	nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);  
	nlh->nlmsg_pid = getpid();  
	nlh->nlmsg_flags = 0;  

	iov.iov_base = (void *)nlh;  
	iov.iov_len = nlh->nlmsg_len;  
	msg.msg_name = (void *)&dest_addr;  
	msg.msg_namelen = sizeof(dest_addr);  
	msg.msg_iov = &iov;  
	msg.msg_iovlen = 1;  

	/* Read message from kernel */  
	recvmsg(sock_fd, &msg, 0);  
	interpret_msg((struct return_struct *)NLMSG_DATA(nlh));

	close(sock_fd); 
	return NULL;
}

void print_usage(char *s)
{
        printf("Usage: %s [flags] infile outfile\n", s);
        printf("where flags are: \n\n");
        printf("-e: encrypt input\n");
        printf("-d: decrypt input\n");
        printf("-c: findchecksum of infile\n");
	printf("-C: compress input\n");
	printf("-D: decompress input\n");
        printf("-S: Submit job\n");
	printf("-L: List job\n");
	printf("-R pid: Remove job with given pid\n");
        printf("-X: Remove infile after operation\n");
        printf("-N: Create new outfile after operation\n");
        printf("-M: Rename infile to outfile after operation\n");
        printf("-h: print short usage string\n");
}


int set_key(char *key)
{
        int len = strlen(key);
        int i;

        if (len > 16 )
                return -1;

        if (len == 16)
                return 0;

        if ( len < 16 && len >=0 )
        {
                for ( i = len ; i < 16 ; i++)
                {
                        memcpy(key+i,"0",1);
                }
                return 0;
        }

        return -1;
}

int main(int argc, char *argv[])
{
	int rc, opt, i, job_pid, ret=0;
	char *rename = NULL;
	struct user_job_info* st_arg = NULL;
	pthread_t tid;

	if(argc < 2) {
		printf("xhw3: invalid args!!\n");
		print_usage(argv[0]);
		exit(1);
	}

	//signal(SIGINT, &signal_handler_func); 

	st_arg = (struct user_job_info*) malloc(sizeof(struct user_job_info));
	st_arg->type = SUBMIT_JOB;
	st_arg->mode = NEW;

	 while ((opt = getopt(argc, argv, "edcNXMCDSLhR:")) != -1)
        {
               switch (opt)
               {
               case 'e':
                   st_arg->action = ENCRYPT;
                   //printf("encrypt given\n");
                   break;
               case 'd':
		   st_arg->action = DECRYPT;
                   //printf("decrypt given\n");
                   break;
               case 'c':
                   st_arg->action = CHECKSUM;
                   //printf("checksum given\n");
                   break;
	       case 'C':
                   st_arg->action = COMPRESS;
                   //printf("compress given\n");
                   break;
               case 'D':
                   st_arg->action = DECOMPRESS;
                   //printf("decompress given\n");
                   break;
               case 'S':
                   st_arg->type = SUBMIT_JOB;
                   //printf("Submit job given\n");
                   break;
               case 'L':
                   st_arg->type = LIST_JOB;
                   //printf("List job given\n");
                   break;
               case 'R':
		   st_arg->type = REMOVE_JOB;
		   job_pid = atoi(optarg);
                   //printf("Remove jobs given for pid: %d\n", job_pid);
		   break;
	       case 'X':
		   st_arg->mode = DEL;
		   //printf("Remove existing file given\n");
		   break;
	       case 'N':
		   st_arg->mode = NEW;
                   //printf("Remove existing file given\n");
                   break;
	       case 'M':
		   st_arg->mode = RENAME;
                   //printf("Remove existing file given\n");
                   break;
	       case 'h':
		    print_usage(argv[0]);
                   exit(EXIT_SUCCESS);
               default:
                   printf("\n");
                   print_usage(argv[0]);
                   exit(EXIT_FAILURE);

		}
	}

	st_arg->finname = NULL;
	st_arg->foutname = NULL;
	st_arg->foutrename = NULL;
	st_arg->action_param.encrypt.key = NULL;

	if(st_arg->type == SUBMIT_JOB){

		st_arg->finname = (char *) malloc(MAX_FILENAME_SIZE);
		memset(st_arg->finname, 0, MAX_FILENAME_SIZE);
		strcpy(st_arg->finname, getenv("PWD"));
		strncat(st_arg->finname, "/", MAX_FILENAME_SIZE);
		strncat(st_arg->finname, argv[optind], MAX_FILENAME_SIZE);
	
		if(st_arg->action != CHECKSUM){// || (st_arg->action == CHECKSUM && st_arg->mode == RENAME)){
	
			if(!argv[optind + 1]){
				printf("xhw3: please enter outfile!\n");
				exit(EXIT_FAILURE);
			}
			st_arg->foutname = (char *) malloc(MAX_FILENAME_SIZE);
		        memset(st_arg->foutname, 0, MAX_FILENAME_SIZE);
		        strcpy(st_arg->foutname, getenv("PWD"));
		        strncat(st_arg->foutname, "/", MAX_FILENAME_SIZE);
		        strncat(st_arg->foutname, argv[optind + 1], MAX_FILENAME_SIZE);
		}

		if(st_arg->action == ENCRYPT || st_arg->action == DECRYPT){

			st_arg->action_param.encrypt.key = (char *)malloc(MAX_FILENAME_SIZE);
		        memset(st_arg->action_param.encrypt.key, 0, MAX_FILENAME_SIZE);
			printf("Please enter key for encryption/decryption (less than 16 bits):\n");
			scanf("%s", st_arg->action_param.encrypt.key);
			if(set_key(st_arg->action_param.encrypt.key)){
				printf("Invalid key entered! Try again.. \n");
				if(st_arg->finname)
		                        free(st_arg->finname);
	
		                if(st_arg->foutname)
		                        free(st_arg->foutname);
	
        	       		if(st_arg->action_param.encrypt.key)
		                        free(st_arg->action_param.encrypt.key);

				free(st_arg);
				exit(EXIT_FAILURE);
			}

		}

		if(st_arg->mode == RENAME){
			rename = (char *)malloc(MAX_FILENAME_SIZE);
			printf("Enter the name to rename the input file to:\n");

			st_arg->foutrename = (char *)malloc(MAX_FILENAME_SIZE);
			memset(st_arg->foutrename, 0, MAX_FILENAME_SIZE);
			scanf("%s", rename);
	
			strcpy(st_arg->foutrename, getenv("PWD"));
	                strncat(st_arg->foutrename, "/", MAX_FILENAME_SIZE);
	                strncat(st_arg->foutrename, rename, MAX_FILENAME_SIZE);
	
			free(rename);
			rename = NULL;
		}

		ret = pthread_create(&tid, NULL, call_netlink, NULL);
		if(ret){
			printf("xhw3: error in pthread create:%d\n", ret);
			exit(EXIT_FAILURE);
		}

		rc = syscall(__NR_xjob, (void*) st_arg, sizeof(struct user_job_info));

		if (rc >= 0) {
		        printf("syscall success: %d\n", rc);
			pthread_join(tid, NULL);
		}
		else {
		        printf("syscall returned %d (errno=%d), err msg: %s\n", rc, errno, strerror(errno));
			pthread_cancel(tid);
		}
	
		if(st_arg->finname)
			free(st_arg->finname);
	
	        if(st_arg->foutname)
		        free(st_arg->foutname);
	
		if(st_arg->foutrename)
			free(st_arg->foutrename);
	
	        if(st_arg->action_param.encrypt.key)
		        free(st_arg->action_param.encrypt.key);
	
	}
	else if(st_arg->type == LIST_JOB) {
		st_arg->data = malloc(10*sizeof(struct job_list));
		if(!st_arg->data)
			printf("xhw3: allocation\n");	

		st_arg->maxlen = 10;
		rc = syscall(__NR_xjob, (void*) st_arg, sizeof(struct user_job_info));

	        if (rc >= 0){
        	        printf("syscall success, items in queue: %d\n", rc);
			if(rc == 0)
				printf("List is empty!\n");

			else{
				struct job_list* jl = NULL;
				jl = (struct job_list*) st_arg->data;
				
				for(i = 0; i < rc && i < st_arg->maxlen; i++){
					printf("Job pid: %d, action: %d\n",jl[i].pid, jl[i].action);
				}
			}
				
		}
	        else
	                printf("syscall returned %d (errno=%d), err msg: %s\n", rc, errno, strerror(errno));

		
	}
	else if(st_arg->type == REMOVE_JOB){
		struct job_list *job_list = NULL;
		st_arg->data = malloc(sizeof(struct job_list));

		job_list = (struct job_list *) st_arg->data;
                if(!st_arg->data)
                        printf("xhw3: allocation\n");

                st_arg->maxlen = 1;
		job_list->pid = job_pid;
                rc = syscall(__NR_xjob, (void*) st_arg, sizeof(struct user_job_info));

                if (rc >= 0){
                        printf("syscall success: %d\n", rc);
                }
                else
                        printf("syscall returned %d (errno=%d), err msg: %s\n", rc, errno, strerror(errno));
	}

	free(st_arg);
	exit(rc);
}
