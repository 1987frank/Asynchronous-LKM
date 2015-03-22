/* 
 * Simple demo explaining usage of the Linux kernel CryptoAPI.
 * By Michal Ludvig <michal@logix.cz>
 *    http://www.logix.cz/michal/
 */

#include <linux/linkage.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fd.h>
#include <linux/spinlock.h>
#include <linux/fdtable.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/cred.h>
#include <linux/dnotify.h>
#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <crypto/hash.h>
#include <linux/key-type.h>
#include <keys/ceph-type.h>
#include <linux/ceph/decode.h>
#include <linux/crypto.h>
#include <linux/vmalloc.h>
#include <crypto/internal/hash.h>
#include <linux/string.h>
#include <linux/kernel.h>

#define DEF_OUT_MODE 0644
#define COMPRESS_BLOCK_SIZE PAGE_SIZE

static const u8 *aes_iv = (u8 *)CEPH_AES_IV;

#define DATA_SIZE 16

static struct crypto_blkcipher *ceph_crypto_alloc_cipher(void)
{
        return crypto_alloc_blkcipher("cbc(aes)", 0, CRYPTO_ALG_ASYNC);
}

static int ceph_aes_decrypt(const void *key, int key_len,
                            void *dst, size_t *dst_len,
                            const void *src, size_t src_len)
{
        struct scatterlist sg_in[1], sg_out[2];
        struct crypto_blkcipher *tfm = ceph_crypto_alloc_cipher();
        struct blkcipher_desc desc = { .tfm = tfm };
        char pad[16];
        void *iv;
        int ivsize;
        int ret;
        int last_byte;

        if (IS_ERR(tfm))
                return PTR_ERR(tfm);

        crypto_blkcipher_setkey((void *)tfm, key, key_len);
        sg_init_table(sg_in, 1);
        sg_init_table(sg_out, 2);
        sg_set_buf(sg_in, src, src_len);
        sg_set_buf(&sg_out[0], dst, *dst_len);
        sg_set_buf(&sg_out[1], pad, sizeof(pad));

        iv = crypto_blkcipher_crt(tfm)->iv;
        ivsize = crypto_blkcipher_ivsize(tfm);

        memcpy(iv, aes_iv, ivsize);

        
//        print_hex_dump(KERN_ERR, "dec key: ", DUMP_PREFIX_NONE, 16, 1,
//                       key, key_len, 1);
//        print_hex_dump(KERN_ERR, "dec  in: ", DUMP_PREFIX_NONE, 16, 1,
//                       src, src_len, 1);
        

        ret = crypto_blkcipher_decrypt(&desc, sg_out, sg_in, src_len);
        crypto_free_blkcipher(tfm);
        if (ret < 0) {
                pr_err("ceph_aes_decrypt failed %d\n", ret);
                return ret;
        }


        if (src_len <= *dst_len)
                last_byte = ((char *)dst)[src_len - 1];
        else
                last_byte = pad[src_len - *dst_len - 1];
        if (last_byte <= 16 && src_len >= last_byte) {
                *dst_len = src_len - last_byte;
        } else {
                pr_err("ceph_aes_decrypt got bad padding %d on src len %d\n",
                       last_byte, (int)src_len);
                return -EPERM;  /* bad padding */
        }
        /*
        print_hex_dump(KERN_ERR, "dec out: ", DUMP_PREFIX_NONE, 16, 1,
                       dst, *dst_len, 1);
        */
        return 0;
}

int ceph_decrypt(char* secret, void *dst, size_t *dst_len,
                 const void *src, size_t src_len)
{
                return ceph_aes_decrypt(secret, 16, dst,
                                        dst_len, src, src_len);

}

static int ceph_aes_encrypt(const void *key, int key_len,
                            void *dst, size_t *dst_len,
                            const void *src, size_t src_len)
{
        struct scatterlist sg_in[2], sg_out[1];
        struct crypto_blkcipher *tfm = ceph_crypto_alloc_cipher();
        struct blkcipher_desc desc = { .tfm = tfm, .flags = 0 };
        int ret;
        void *iv;
        int ivsize;
        size_t zero_padding = (0x10 - (src_len & 0x0f));
        char pad[16];

        if (IS_ERR(tfm))
                return PTR_ERR(tfm);
        memset(pad, zero_padding, zero_padding);
        *dst_len = src_len + zero_padding;

        crypto_blkcipher_setkey((void *)tfm, key, key_len);
        sg_init_table(sg_in, 2);
        sg_set_buf(&sg_in[0], src, src_len);
        sg_set_buf(&sg_in[1], pad, zero_padding);
        sg_init_table(sg_out, 1);
        sg_set_buf(sg_out, dst, *dst_len);
        iv = crypto_blkcipher_crt(tfm)->iv;
        ivsize = crypto_blkcipher_ivsize(tfm);

        memcpy(iv, aes_iv, ivsize);
        
//	print_hex_dump(KERN_ERR, "enc key: ", DUMP_PREFIX_NONE, 16, 1,
//		key, key_len, 1);
//	print_hex_dump(KERN_ERR, "enc src: ", DUMP_PREFIX_NONE, 16, 1,
//		src, src_len, 1);
//	print_hex_dump(KERN_ERR, "enc pad: ", DUMP_PREFIX_NONE, 16, 1,
//		pad, zero_padding, 1);
        
        ret = crypto_blkcipher_encrypt(&desc, sg_out, sg_in,
                                     src_len + zero_padding);
        crypto_free_blkcipher(tfm);
        if (ret < 0)
                pr_err("ceph_aes_crypt failed %d\n", ret);
        
//        print_hex_dump(KERN_ERR, "enc out: ", DUMP_PREFIX_NONE, 16, 1,
//                       dst, *dst_len, 1);
        
        return 0;
}

int ceph_encrypt(char *secret, void *dst, size_t *dst_len,
                 const void *src, size_t src_len)
{
                return ceph_aes_encrypt(secret, 16, dst,
                                        dst_len, src, src_len);

}

int encrypt(char *in_file, char *out_file, char *key)
{
        struct file *filp_in = NULL, *filp_out = NULL;
        int bytes1 = 0, bytes2 = 0, err=0;

        int len=0;
        char *temp_buffer = NULL, *buffer = NULL;
	mm_segment_t oldfs;

	temp_buffer = kmalloc(32, GFP_KERNEL);
	if ( temp_buffer == NULL)
	{
		err = -ENOMEM;
		goto out;
	}
	
	buffer = kmalloc(16, GFP_KERNEL);
	if ( buffer == NULL )
	{
		err = -ENOMEM;
		goto out;
	}

        memset(temp_buffer, 0 , DATA_SIZE*2);
	memset(buffer, 0 , DATA_SIZE);


        if ( strcmp(in_file,out_file) == 0 )
	{
		err = -EINVAL;
		goto out;
	}

        filp_in = filp_open(in_file, O_RDONLY, 0);

        if (filp_in == NULL || IS_ERR(filp_in))
        {
                err = (int)PTR_ERR(filp_in);
                filp_in = NULL;
                goto out;
        }

        if ( !filp_in->f_op->read )
        {
                err = -ENOSYS;
                goto out;
        }
        filp_out = filp_open(out_file, O_WRONLY | O_TRUNC | O_CREAT, DEF_OUT_MODE);

        if (filp_out == NULL || IS_ERR(filp_out))
        {
                err = (int)PTR_ERR(filp_in);
                filp_out = NULL;
                goto out;
        }

        if ( !filp_out->f_op->write )
        {
                err = -ENOSYS;
                goto out;
        }

        do
        {
                oldfs = get_fs();
                set_fs(KERNEL_DS);


                bytes1 = vfs_read(filp_in, buffer, DATA_SIZE, &filp_in->f_pos);

                set_fs(oldfs);
                if ( bytes1 > 0)
                {
                        err = ceph_encrypt(key,temp_buffer,&len,buffer,bytes1);
			if ( err < 0 )
				goto out;
                        oldfs = get_fs();
                        set_fs(KERNEL_DS);
                        bytes2 = vfs_write(filp_out, temp_buffer, len,  &filp_out->f_pos);

                        set_fs(oldfs);
			if ( bytes2 < 0)
			{
				err = bytes2;
				goto out;
			}
                }
		else if ( bytes1 < 0 )
		{
			err = bytes1;
			goto out;
		}
        }while( bytes1 > 0);

out:
        if ( filp_out)
                filp_close(filp_out, NULL);
        if (filp_in)
                filp_close(filp_in, NULL);

	if (temp_buffer)
		kfree(temp_buffer);
	if(buffer)
		kfree(buffer);

        return err;

}

int decrypt(char *in_file, char *out_file, char *key)
{
        struct file *filp_in = NULL, *filp_out = NULL;
        int bytes1 = 0, bytes2 = 0, err=0;

        size_t dec_len;
        char *dec = NULL, *buffer = NULL;
	mm_segment_t oldfs;

	dec = kmalloc(DATA_SIZE*2 + 1, GFP_KERNEL);

	if ( dec == NULL )
	{
		err = -ENOMEM;
		goto out;
	}

	buffer = kmalloc(DATA_SIZE*2 + 1, GFP_KERNEL);
	
	if ( buffer == NULL )
	{
		err = -ENOMEM;
		goto out;
	}

	memset(dec,0,33);
	memset(buffer,0,33);


        if ( strcmp(in_file, out_file) == 0 )
	{
		err = -EINVAL;
		goto out;
	}

        filp_in = filp_open(in_file, O_RDONLY, 0);

        if (filp_in == NULL || IS_ERR(filp_in))
        {
                err = (int)PTR_ERR(filp_in);
                filp_in = NULL;
                goto out;
        }

        if ( !filp_in->f_op->read )
        {
                err = -ENOSYS;
                goto out;
        }
        filp_out = filp_open(out_file, O_WRONLY | O_TRUNC | O_CREAT, DEF_OUT_MODE);

        if (filp_out == NULL || IS_ERR(filp_out))
        {
                err = (int)PTR_ERR(filp_in);
                filp_out = NULL;
                goto out;
        }

        if ( !filp_out->f_op->write )
        {
                err = -ENOSYS;
                goto out;
        }

        do
        {

                oldfs = get_fs();
                set_fs(KERNEL_DS);

                bytes1 = vfs_read(filp_in, buffer, DATA_SIZE* 2 , &filp_in->f_pos);

                set_fs(oldfs);

                if ( bytes1 > 0 )
                {

                        err = ceph_decrypt(key,dec,&dec_len,buffer,bytes1);
			if(err < 0)
				goto out;

                        oldfs = get_fs();
                        set_fs(KERNEL_DS);
                        if ( dec_len == 32 )
				bytes2 = vfs_write(filp_out, dec, DATA_SIZE,&filp_out->f_pos);
			else
				bytes2 = vfs_write(filp_out, dec, dec_len, &filp_out->f_pos);
                        set_fs(oldfs);

			if ( bytes2 < 0)
			{
				err = bytes2;
				goto out;
			}
                }
		else if ( bytes1 < 0 )
		{
			err = bytes1;
			goto out;
		}
        }while(bytes1);
out:
        if ( filp_out)
                filp_close(filp_out, NULL);
        if (filp_in)
                filp_close(filp_in, NULL);
	if (dec)
		kfree(dec);
	if (buffer)
		kfree(buffer);

        return err;
}


static int compress_lzo(char *in_buf, int in_len, char *out_buf, int *out_len)
{
        struct crypto_comp *tfm;
        int err = 0;


//      print_hex_dump(KERN_ERR, "dec key: ", DUMP_PREFIX_NONE, 16, 1,
//              in_buf, in_len, 1);

        tfm = crypto_alloc_comp("lzo", 0, 0);
        if (IS_ERR(tfm))
        {
                return PTR_ERR(tfm);
        }


        err = crypto_comp_compress(tfm, in_buf, in_len, out_buf,
                                  out_len);


//       print_hex_dump(KERN_ERR, "dec key: ", DUMP_PREFIX_NONE, 16, 1,
//                    out_buf, *out_len, 1);

        crypto_free_comp(tfm);
        return err;

}


static int decompress_lzo(char *in_buf, int in_len, char *out_buf, int *out_len)
{

//      print_hex_dump(KERN_ERR, "dec key: ", DUMP_PREFIX_NONE, 16, 1,
//                       in_buf,in_len, 1);
        struct crypto_comp *tfm;
        int err = 0;

        tfm = crypto_alloc_comp("lzo", 0, 0);
        if (IS_ERR(tfm))
        {
                return PTR_ERR(tfm);
        }


        err = crypto_comp_decompress(tfm, in_buf, in_len ,out_buf,
                                  out_len);


//      print_hex_dump(KERN_ERR, "dec key: ", DUMP_PREFIX_NONE, 16, 1,
//                       out_buf, *out_len, 1);

        crypto_free_comp(tfm);
        return err;
}


int compress(char *in_file, char *out_file)
{
        struct file *filp_in = NULL, *filp_out = NULL;
        int bytes1 = 0, bytes2 = 0, err=0;

        int len=0;
        char *temp_buffer = NULL, *buffer = NULL;
        char *orig_len = NULL, *comp_len = NULL;
        mm_segment_t oldfs;

        temp_buffer = kmalloc(COMPRESS_BLOCK_SIZE,GFP_KERNEL);
	if ( temp_buffer == NULL)
	{
		err = -ENOMEM;
		goto out;
	}
	
        buffer = kmalloc(COMPRESS_BLOCK_SIZE,GFP_KERNEL);
	if ( buffer == NULL)
	{
		err = -ENOMEM;
		goto out;
	}

        memset(temp_buffer, 0 , COMPRESS_BLOCK_SIZE);
        memset(buffer , 0, COMPRESS_BLOCK_SIZE);

        orig_len = kmalloc(5,GFP_KERNEL);
        if ( !orig_len)
        {
                err = -ENOMEM;
                goto out;
        }

        comp_len = kmalloc(5,GFP_KERNEL);
        if ( !comp_len)
        {
                err = -ENOMEM;
                goto out;
        }
        memset(orig_len,5,0);
        memset(comp_len,5,0);

        if ( strcmp(in_file,out_file) == 0 )
        {
                err = -EINVAL;
                goto out;
        }

        filp_in = filp_open(in_file, O_RDONLY, 0);

        if (filp_in == NULL || IS_ERR(filp_in))
        {
                err = (int)PTR_ERR(filp_in);
                filp_in = NULL;
                goto out;
        }

        if ( !filp_in->f_op->read )
        {
                err = -ENOSYS;
                goto out;
        }


        filp_out = filp_open(out_file, O_WRONLY | O_TRUNC | O_CREAT, DEF_OUT_MODE);

        if (filp_out == NULL || IS_ERR(filp_out))
        {
                err = (int)PTR_ERR(filp_in);
                filp_out = NULL;
                goto out;
        }

        if ( !filp_out->f_op->write )
        {
                err = -ENOSYS;
                goto out;
        }

        do
        {
                oldfs = get_fs();
                set_fs(KERNEL_DS);

                bytes1 = vfs_read(filp_in, buffer, COMPRESS_BLOCK_SIZE, &filp_in->f_pos);

                set_fs(oldfs);
                if ( bytes1 > 0)
                {
                        err = compress_lzo(buffer, bytes1, temp_buffer, &len);
                        if ( err < 0 )
                                goto out;

                        memset(orig_len,0,5);
                        sprintf(orig_len,"%d",bytes1);

                        memset(comp_len,0,5);
                        sprintf(comp_len,"%d",len);

                        oldfs = get_fs();
                        set_fs(KERNEL_DS);

                        err = vfs_write(filp_out,orig_len, 5,  &filp_out->f_pos);
                        set_fs(oldfs);

                        if ( err < 0 )
                                goto out;
			else
				err = 0;

                        oldfs = get_fs();
                        set_fs(KERNEL_DS);

                        err = vfs_write(filp_out, comp_len, 5,  &filp_out->f_pos);

                        set_fs(oldfs);

                        if ( err < 0 )
                                goto out;
			else
                                err = 0;

                        oldfs = get_fs();
                        set_fs(KERNEL_DS);

                        bytes2 = vfs_write(filp_out, temp_buffer, len,  &filp_out->f_pos);
                        set_fs(oldfs);

                        if ( bytes2 < 0 )
                        {
                                err = bytes2;
                                goto out;
                        }
                }
                else if ( bytes1 < 0)
                {
                        err = bytes1;
                        goto out;
                }
        }while( bytes1 >0 );

out:
        if ( filp_out)
                filp_close(filp_out, NULL);
        if (filp_in)
                filp_close(filp_in, NULL);
        if (temp_buffer)
                kfree (temp_buffer);
        if (buffer)
                kfree(buffer);
        if ( comp_len)
                kfree(comp_len);
        if (orig_len)
                kfree(orig_len);

        return err;
}

int decompress(char *in_file, char *out_file)
{
        struct file *filp_in = NULL, *filp_out = NULL;
        int bytes1 = 0, bytes2 = 0, err=0;

        size_t len;
        char *temp_buffer= NULL, *buffer=NULL;
        mm_segment_t oldfs;
        long orig=0,comp=0;
        char *orig_len = NULL, *comp_len= NULL;

        temp_buffer = kmalloc(COMPRESS_BLOCK_SIZE,GFP_KERNEL);
	if (temp_buffer == NULL)
	{
		err = -ENOMEM;
		goto out;
	}

        buffer = kmalloc(COMPRESS_BLOCK_SIZE,GFP_KERNEL);
	if ( buffer == NULL )
	{
		err = -ENOMEM;
		goto out;
	}

        memset(temp_buffer,0,COMPRESS_BLOCK_SIZE);
        memset(buffer,0,COMPRESS_BLOCK_SIZE);

        orig_len = kmalloc(5,GFP_KERNEL);
        if ( !orig_len)
        {
                err = -ENOMEM;
                goto out;
        }

        comp_len = kmalloc(5,GFP_KERNEL);
        if ( !comp_len)
        {
                err = -ENOMEM;
                goto out;
        }

        if ( strcmp(in_file, out_file) == 0 )
        {
                err = -EINVAL;
                goto out;
        }

        filp_in = filp_open(in_file, O_RDONLY, 0);

        if (filp_in == NULL || IS_ERR(filp_in))
        {
                err = (int)PTR_ERR(filp_in);
                filp_in = NULL;
                goto out;
        }

        if ( !filp_in->f_op->read )
        {
                err = -ENOSYS;
                goto out;
        }


        filp_out = filp_open(out_file, O_WRONLY | O_TRUNC | O_CREAT, DEF_OUT_MODE);

        if (filp_out == NULL || IS_ERR(filp_out))
        {
                err = (int)PTR_ERR(filp_in);
                filp_out = NULL;
                goto out;
        }

        if ( !filp_out->f_op->write )
        {
                err = -ENOSYS;
                goto out;
        }

        filp_in->f_pos = 0;
        filp_out->f_pos = 0;

        do
        {
                oldfs = get_fs();
                set_fs(KERNEL_DS);

                memset(orig_len,5,0);
                memset(comp_len,5,0);

                err = vfs_read(filp_in,orig_len,5,&filp_in->f_pos);

                set_fs(oldfs);

                if ( err < 0 )
                        goto out;
		else
                        err = 0;

                oldfs = get_fs();
                set_fs(KERNEL_DS);

                err = vfs_read(filp_in,comp_len,5,&filp_in->f_pos);

                set_fs(oldfs);

                if ( err < 0 )
                        goto out;
		else
                        err = 0;

                err = kstrtol(orig_len,10,&orig);
		if ( err < 0 )
			goto out;

                err = kstrtol(comp_len,10,&comp);
		if ( err < 0 )
			goto out;

                oldfs = get_fs();
                set_fs(KERNEL_DS);

                bytes1 = vfs_read(filp_in, buffer, comp, &filp_in->f_pos);

                set_fs(oldfs);
                if ( bytes1 > 0)
                {
                        len = orig;
                        err = decompress_lzo(buffer, bytes1, temp_buffer, &len);

                        if ( err < 0 )
                                goto out;

                        oldfs = get_fs();
                        set_fs(KERNEL_DS);

                        bytes2 = vfs_write(filp_out, temp_buffer, len,  &filp_out->f_pos);

                        set_fs(oldfs);
                        if ( bytes2 < 0)
                        {
                                err = bytes2;
                                goto out;
                        }
                }
                if ( bytes1 < 0 )
                {
                        err = bytes1;
                        goto out;
                }
        }while( bytes1 >0 );

out:
        if ( filp_out)
                filp_close(filp_out, NULL);
        if (filp_in)
                filp_close(filp_in, NULL);
        if ( temp_buffer)
                kfree(temp_buffer);
        if ( buffer)
                kfree(buffer);
        if ( comp_len)
                kfree(comp_len);
        if (orig_len)
                kfree(orig_len);

        return err;

}

