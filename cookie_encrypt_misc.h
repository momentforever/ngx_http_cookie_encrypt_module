/*
 * @Author: lzt
 * @Date: 2022-1-15 17:34
 * @LastEditTime: 2022-1-15 17:34
 * @LastEditors: lzt
 * @Description: save small tools func.
 * @FilePath: /nginx-cookie-encrypt-module/cookie_encrypt_misc.c
 */

#ifndef NGINX_DEV_COOKIE_ENCRYPT_MISC_H
#define NGINX_DEV_COOKIE_ENCRYPT_MISC_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

int aes_encrypt(unsigned char* str_in,unsigned char* str_out,unsigned char *key, unsigned char *iv);
int aes_decrypt(unsigned char* str_in, unsigned char* str_out,unsigned char* key,unsigned char* iv);
int base64_decode(unsigned char *in_str,unsigned char *out_str);
int base64_encode(unsigned char *in_str,unsigned char *out_str);

/*
这个是你自己写的一个十六字节的秘钥,aes加密解密都用这同一个
命令：find /usr/include/ -name *.h | xargs grep 'AES_BLOCK_SIZE'
结果：/usr/include/openssl/aes.h:# define AES_BLOCK_SIZE 16
//256下 key为秘钥32 iv为偏移16
*/
#define KEY_BLOCK_BIT 33
#define IV_BLOCK_BIT 17
#define KEY "E10ADC3949BA59ABBE56E056F20F883E"
#define IV "E10ADC3949BA59AB"
#define ENCRYPTBUFSIZE 1024
#endif //NGINX_DEV_COOKIE_ENCRYPT_MISC_H
