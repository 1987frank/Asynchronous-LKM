#ifndef _INCLUDES_H
#define _INCLUDES_H

#define PAGESIZE 4096

#define MAX_FILENAME_SIZE 4096        //assumption: max size of each file name


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
  char*   key;
};


struct user_job_info {
  char*    finname;
  char*    foutname;
  char*	   foutrename;
  int maxlen;
  void *data;
  JOB_OUT_MODE          mode;
  JOB_INFO_ACTION       action;
  JOB_TYPE    		type;

  union {
    struct encrypt_info encrypt;
  }action_param;

};

struct ret_checksum {
  uint32_t crc;
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



#endif	//end ifndef
