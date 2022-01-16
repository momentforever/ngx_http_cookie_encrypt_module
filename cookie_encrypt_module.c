/*
 * @Author: lzt
 * @Date: 2022-1-15 17:34
 * @LastEditTime: 2022-1-15 17:34
 * @LastEditors: lzt
 * @Description: As a nginx module, in order to encrypt the parameters of the cookie to improve the security of the backend server.
 * @FilePath: /nginx-cookie-encrypt-module/cookie-encrypt-module.c
 */

//  location xxx{
//      cookie_encrypt on | off;
//  }
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "cookie_encrypt_misc.h"

extern ngx_module_t ngx_http_cookie_encrypt_module;

typedef struct {
    ngx_flag_t enable;
    ngx_str_t key;
    ngx_str_t iv;
    ngx_flag_t is_strict;
} ngx_http_cookie_loc_conf_t;

/* the configuration structure */
static void *ngx_http_cookie_create_loc_conf(ngx_conf_t *cf);

static ngx_int_t ngx_http_cookie_init(ngx_conf_t *cf);

static char *ngx_http_cookie_encrypt_key(ngx_conf_t *cf,ngx_command_t *cmd,void *conf);
static char *ngx_http_cookie_encrypt_iv(ngx_conf_t *cf,ngx_command_t *cmd,void *conf);
static char *ngx_http_cookie_encrypt(ngx_conf_t *cf,ngx_command_t *cmd,void *conf);

static ngx_command_t ngx_http_cookie_commands[] = {
        {
                ngx_string("cookie_encrypt"),
                NGX_HTTP_LOC_CONF | NGX_CONF_FLAG | NGX_CONF_TAKE1,
                ngx_http_cookie_encrypt,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_http_cookie_loc_conf_t, enable),
                NULL
        },
        {
                ngx_string("cookie_encrypt_key"),
                NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
                ngx_http_cookie_encrypt_key,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_http_cookie_loc_conf_t, key),
                NULL
        },
        {
                ngx_string("cookie_encrypt_iv"),
                NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
                ngx_http_cookie_encrypt_iv,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_http_cookie_loc_conf_t, iv),
                NULL
        },
        ngx_null_command
};
static char *ngx_http_cookie_encrypt(ngx_conf_t *cf,ngx_command_t *cmd,void *conf){
    ngx_http_cookie_loc_conf_t* local_conf;
    local_conf = conf;

    ngx_str_t        *value;

    value = cf->args->elts;

    if (ngx_strcasecmp(value[1].data, (u_char *) "on") == 0) {
        local_conf->enable = 1;
        local_conf->is_strict = 0;
    } else if (ngx_strcasecmp(value[1].data, (u_char *) "off") == 0) {
        local_conf->enable = 0;
        local_conf->is_strict = 0;
    } else if (ngx_strcasecmp(value[1].data, (u_char *) "strict") == 0) {
        local_conf->enable = 1;
        local_conf->is_strict = 1;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid value \"%s\" in \"%s\" directive",
                           value[1].data, cmd->name.data);
        return NGX_CONF_ERROR;
    }
    //printf("enable => %ld\n",local_conf->enable);
    //printf("strict => %ld\n",local_conf->is_strict);
    return NGX_CONF_OK;
}

static char *ngx_http_cookie_encrypt_key(ngx_conf_t *cf,ngx_command_t *cmd,void *conf){
    ngx_http_cookie_loc_conf_t* local_conf;
    local_conf = conf;
    // reset
    ngx_str_null(&local_conf->key);

    char *rv = NULL;
    rv = ngx_conf_set_str_slot(cf,cmd,conf);
    if(local_conf->key.len != 32){
        ngx_conf_log_error(NGX_LOG_ERR,cf,0,"KEY length does not meet requirements, KEY length should be 32.");
        return NGX_CONF_ERROR;
    }
    ngx_conf_log_error(NGX_LOG_DEBUG,cf,0,"encrypt cookie key:%s",local_conf->key.data);
    return rv;
};

static char *ngx_http_cookie_encrypt_iv(ngx_conf_t *cf,ngx_command_t *cmd,void *conf){
    ngx_http_cookie_loc_conf_t* local_conf;
    local_conf = conf;
    // reset
    ngx_str_null(&local_conf->iv);

    char *rv = NULL;
    rv = ngx_conf_set_str_slot(cf,cmd,conf);
    if(local_conf->iv.len != 16){
        ngx_conf_log_error(NGX_LOG_ERR,cf,0,"IV length does not meet requirements, IV length should be 16.");
        return NGX_CONF_ERROR;
    }
    ngx_conf_log_error(NGX_LOG_DEBUG,cf,0,"encrypt cookie iv:%s",local_conf->iv.data);
    return rv;
}

// 初始化配置文件
static void *ngx_http_cookie_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_cookie_loc_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_cookie_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    // TODO 随机生成key和iv
//    ngx_str_null(&conf->key);
//    ngx_str_null(&conf->iv);
    ngx_str_set(&conf->key,KEY);
    ngx_str_set(&conf->iv,IV);

    conf->is_strict = NGX_CONF_UNSET;
    conf->enable = NGX_CONF_UNSET;
    return conf;
}


static ngx_http_module_t ngx_http_cookie_module_ctx = {
        NULL,                                  /* preconfiguration */
        ngx_http_cookie_init,                                 /* postconfiguration */

        NULL,                                 /* create main configuration */
        NULL,                                   /* init main configuration */

        NULL,                        /* create server configuration */
        NULL,                                  /* merge server configuration */

        ngx_http_cookie_create_loc_conf,
        NULL
};

ngx_module_t ngx_http_cookie_encrypt_module = {
        NGX_MODULE_V1,
        &ngx_http_cookie_module_ctx,
        ngx_http_cookie_commands,
        NGX_HTTP_MODULE,                                  /* module type */
        NULL,                                  /* init master */
        NULL,                                  /* init module */
        NULL,                                  /* init process */
        NULL,                                  /* init thread */
        NULL,                                  /* exit thread */
        NULL,                                  /* exit process */
        NULL,                                  /* exit master */
        NGX_MODULE_V1_PADDING
};


static ngx_int_t ngx_cookie_decrypt_handler(ngx_http_request_t *r) {
    ngx_http_cookie_loc_conf_t *cf;
    cf = ngx_http_get_module_loc_conf(r, ngx_http_cookie_encrypt_module);
    if (cf->enable) {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "enable decrypt!");

        ngx_table_elt_t *elt;
        ngx_list_part_t *part;
        ngx_uint_t i;
        part = &r->headers_in.headers.part;
        elt = part->elts;
        for (i = 0;; i++) {
            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }
                part = part->next;
                elt = part->elts;
                i = 0;
            }
            /* ... */
            if (ngx_strcmp(elt[i].key.data, "Cookie") == 0) {
                ngx_str_t cookie_s = ngx_string(elt[i].value.data);
                int ii;
                int begin = 0;
                int start = -1;
                int end = -1;
                int len = (int) ngx_strlen(cookie_s.data);
                u_char *encrypt_cookie;
                encrypt_cookie = ngx_pcalloc(r->pool, ENCRYPTBUFSIZE);
                if (encrypt_cookie == NULL) {
                    return NGX_ERROR;
                }
                u_char *cp = encrypt_cookie;

                ngx_str_t cookie_arg_decode;
                cookie_arg_decode.data = ngx_pcalloc(r->pool, ENCRYPTBUFSIZE);
                if (cookie_arg_decode.data == NULL) {
                    return NGX_ERROR;
                }
                ngx_str_t cookie_arg_decrypt;
                cookie_arg_decrypt.data = ngx_pcalloc(r->pool, ENCRYPTBUFSIZE);
                if (cookie_arg_decrypt.data == NULL) {
                    return NGX_ERROR;
                }
                ngx_str_t cookie_arg;
                cookie_arg.data = ngx_pcalloc(r->pool, ENCRYPTBUFSIZE);
                if (cookie_arg.data == NULL) {
                    return NGX_ERROR;
                }
                u_char *cap;

                for (ii = 0; ii < len; ++ii) {
                    if (ii == len - 1) {
                        end = len - 1;
                    }
                    if (cookie_s.data[ii] == '=' && start == -1) {
                        start = ii + 1;
                    }
                    if (cookie_s.data[ii] == ';') {
                        end = ii - 1;
                    }
                    if (start != -1 && end != -1) {
                        //printf(" start -> %d , end -> %d \n",start,end);
                        // 赋值
                        cookie_arg.len = end - start + 1;
                        cap = ngx_cpymem(cookie_arg.data, cookie_s.data + start, cookie_arg.len);
                        ngx_memcpy(cap, "\n\0", 2);
                        //printf("cookie_arg -> %s\n",cookie_arg.data);
                        // 赋值end
                        // 解码
                        base64_decode(cookie_arg.data,cookie_arg_decode.data);
                        if((cookie_arg_decode.len = ngx_strlen(cookie_arg_decode.data)) == 0){
                            ngx_log_error(NGX_LOG_ERR,r->connection->log,0,"can't decode cookie arg");
                            if(!cf->is_strict){
                                cp = ngx_copy(cp, cookie_s.data + begin, start - begin);
                                cp = ngx_copy(cp, cookie_arg.data, cookie_arg.len);
                            }
                            begin = start + 1;
                            end = -1;
                            start = -1;
                            continue;
                        }
                        //printf("cookie_arg_decode len -> %zu, data -> %s\n",cookie_arg_decode.len,cookie_arg_decode.data);
                        // 解码end
                        // 解密
                        if(aes_decrypt(cookie_arg_decode.data, cookie_arg_decrypt.data, cf->key.data, cf->iv.data) == 0){
                            ngx_log_error(NGX_LOG_ERR,r->connection->log,0,"cookie decrypt fail!");
                            if(!cf->is_strict){
                                cp = ngx_copy(cp, cookie_s.data + begin, start - begin);
                                cp = ngx_copy(cp, cookie_arg.data, cookie_arg.len);
                            }
                            begin = start + 1;
                            end = -1;
                            start = -1;
                            continue;
                        }

                        //success
                        cp = ngx_copy(cp, cookie_s.data + begin, start - begin);
                        //printf("decrypt success!\n");
                        cookie_arg_decrypt.len = ngx_strlen(cookie_arg_decrypt.data);
                        cp = ngx_copy(cp, cookie_arg_decrypt.data, cookie_arg_decrypt.len);
                        //printf( "replacing decrypt cookie -> %s\n",encrypt_cookie);
                        // 解密 end
                        begin = start + 1;
                        end = -1;
                        start = -1;
                    }
                }
                ngx_str_set(&elt[i].value, encrypt_cookie);
                elt[i].value.len = ngx_strlen(encrypt_cookie);
                //printf( "finish decrypt cookie -> %s\n",encrypt_cookie);
            }
            //ngx_log_error(NGX_LOG_ERR,r->connection->log,0,"%s -> %s",elt[i].key.data,elt[i].value.data);
        }

    }
    return NGX_DECLINED;
}

static ngx_http_output_header_filter_pt ngx_http_next_header_filter;

static ngx_int_t ngx_http_encrypt_filter(ngx_http_request_t *r) {
    ngx_http_cookie_loc_conf_t *cf;
    cf = ngx_http_get_module_loc_conf(r, ngx_http_cookie_encrypt_module);
    if (cf->enable) {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "enable encrypt!");
        ngx_table_elt_t *elt;
        ngx_list_part_t *part;
        ngx_uint_t i;
        // TODO AES加密
        part = &r->headers_out.headers.part;
        elt = part->elts;

        for (i = 0;; i++) {
            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }
                part = part->next;
                elt = part->elts;
                i = 0;
            }
            /* ... */
            if (ngx_strcmp(elt[i].key.data, "Set-Cookie") == 0) {
                ngx_str_t cookie_s = ngx_string(elt[i].value.data);
                int len = (int) ngx_strlen(cookie_s.data);
                cookie_s.len = len;
                int ii = 0;
                int start = -1;
                int end = -1;
                u_char *cp;
                u_char *encrypt_cookie = ngx_pcalloc(r->pool, ENCRYPTBUFSIZE);
                if (encrypt_cookie == NULL) {
                    return ngx_http_next_header_filter(r);
                }
                ngx_str_t cookie_arg_encode;
                cookie_arg_encode.data = ngx_pcalloc(r->pool, ENCRYPTBUFSIZE);
                if (cookie_arg_encode.data == NULL) {
                    return ngx_http_next_header_filter(r);
                }
                ngx_str_t cookie_arg_encrypt;
                cookie_arg_encrypt.data = ngx_pcalloc(r->pool, ENCRYPTBUFSIZE);
                if (cookie_arg_encrypt.data == NULL) {
                    return ngx_http_next_header_filter(r);
                }
                u_char *cap;
                ngx_str_t cookie_arg;
                cookie_arg.data = ngx_pcalloc(r->pool, ENCRYPTBUFSIZE);
                if (cookie_arg.data == NULL) {
                    return ngx_http_next_header_filter(r);
                }
                // search  = and ; to find cookie arg
                for (ii = 0; ii < len; ii++) {
                    if (ii == len - 1) {
                        end = len - 1;
                    }
                    if (cookie_s.data[ii] == '=' && start == -1) {
                        start = ii + 1;
                    }
                    if (cookie_s.data[ii] == ';') {
                        end = ii - 1;
                        break;
                    }
                }
                //printf(" start -> %d , end -> %d \n",start,end);
                if (start != -1 && end != -1) {
                    cp = ngx_copy(encrypt_cookie, cookie_s.data, start);
                    //printf("cookie_s len ->%zu ,data ->%s\n",cookie_s.len,cookie_s.data);
                    // 加密
                    cookie_arg.len = end - start + 1;
                    cap = ngx_cpymem(cookie_arg.data, cookie_s.data + start, cookie_arg.len);
                    ngx_memcpy(cap, "\0", 1);
                    //printf("cookie_arg -> %s\n",cookie_arg.data);
                    if(aes_encrypt(cookie_arg.data, cookie_arg_encrypt.data, cf->key.data, cf->iv.data) == 0){
                        ngx_log_error(NGX_LOG_ERR,r->connection->log,0,"can't encrypt cookie arg(due to encrypt)");
                        continue;
                    }
                    if((cookie_arg_encrypt.len = ngx_strlen(cookie_arg_encrypt.data))==0){
                        ngx_log_error(NGX_LOG_ERR,r->connection->log,0,"can't encrypt cookie arg(due to length)");
                        continue;
                    }
                    // 加密 end
                    // 编码
                    base64_encode(cookie_arg_encrypt.data, cookie_arg_encode.data);
                    if((cookie_arg_encode.len = ngx_strlen(cookie_arg_encode.data))==0){
                        ngx_log_error(NGX_LOG_ERR,r->connection->log,0,"can't encode cookie arg");
                        continue;
                    }
                    //printf("cookie_arg_encode -> %s",cookie_arg_encode.data);
                    // 编码 end
                    // 拷贝
                    cp = ngx_copy(cp, cookie_arg_encode.data, cookie_arg_encode.len - 1);
                    // 拷贝 end
                    cp = ngx_copy(cp, cookie_s.data + end + 1, len - end);
                    ngx_str_set(&elt[i].value, encrypt_cookie);
                    elt[i].value.len = ngx_strlen(encrypt_cookie);
                }
                //printf( "finish encrypt cookie -> %s\n",elt[i].value.data);
            }
        }
    }
    return ngx_http_next_header_filter(r);
}


static ngx_int_t ngx_http_cookie_init(ngx_conf_t *cf) {
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    *h = ngx_cookie_decrypt_handler;

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_encrypt_filter;
    return NGX_OK;
}

