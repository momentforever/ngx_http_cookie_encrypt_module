//
// Created by lzt11 on 2021/12/28.
//

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
} ngx_http_cookie_loc_conf_t;

/* the configuration structure */
static void *ngx_http_cookie_create_loc_conf(ngx_conf_t *cf);

static ngx_int_t ngx_http_cookie_init(ngx_conf_t *cf);

static ngx_command_t ngx_http_cookie_commands[] = {
        {
                ngx_string("cookie_encrypt"),
                NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
                ngx_conf_set_flag_slot,
                NGX_HTTP_LOC_CONF_OFFSET,
                offsetof(ngx_http_cookie_loc_conf_t, enable),
                NULL
        },
        ngx_null_command
};

// 初始化配置文件
static void *ngx_http_cookie_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_cookie_loc_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_cookie_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }
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
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "decrypt");
        ngx_table_elt_t *elt;
        ngx_list_part_t *part;
        ngx_uint_t i;
        // TODO AES加密
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
                encrypt_cookie = ngx_pcalloc(r->pool, 1024);
                if (encrypt_cookie == NULL) {
                    return NGX_ERROR;
                }
                u_char *cp =encrypt_cookie;

                ngx_str_t cookie_arg = ngx_string("cookie_decrypt");

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
                        printf(" start -> %d , end -> %d \n",start,end);
                        cp = ngx_copy(cp, cookie_s.data + begin, start - begin);
                        // 加密
                        // 加密 end
                        cp = ngx_copy(cp, cookie_arg.data, cookie_arg.len);
                        printf( "replacing decrypt cookie -> %s\n",encrypt_cookie);
                        begin = start + 1;
                        end = -1;
                        start = -1;
                    }
                }

                ngx_str_set(&elt[i].value, encrypt_cookie);
                elt[i].value.len = ngx_strlen(encrypt_cookie);
                printf( "finish decrypt cookie -> %s\n",encrypt_cookie);
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
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "encrypt");
        //printf("open!\n");
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

                u_char *encrypt_cookie = ngx_pcalloc(r->pool, 1024);
                if (encrypt_cookie == NULL) {
                    return NGX_ERROR;
                }
                //ngx_str_t cookie_arg = ngx_string("cookie_encrypt");
                ngx_str_t cookie_arg_encode;
                cookie_arg_encode.data = ngx_pcalloc(r->pool, 1024);
                if (cookie_arg_encode.data == NULL) {
                    return NGX_ERROR;
                }
                ngx_str_t cookie_arg_encrypt;
                cookie_arg_encrypt.data = ngx_pcalloc(r->pool, 1024);
                if (cookie_arg_encrypt.data == NULL) {
                    return NGX_ERROR;
                }
                u_char *cap;
                ngx_str_t cookie_arg;
                cookie_arg.data = ngx_pcalloc(r->pool, 1024);
                if (cookie_arg.data == NULL) {
                    return NGX_ERROR;
                }
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
                    aes_encrypt(cookie_arg.data, cookie_arg_encrypt.data, (u_char *) KEY, (u_char *) IV);
                    cookie_arg_encrypt.len = ngx_strlen(cookie_arg_encrypt.data);
                    // 加密 end
                    // 编码
                    base64_encode(cookie_arg_encrypt.data, cookie_arg_encode.data);
                    cookie_arg_encode.len = ngx_strlen(cookie_arg_encode.data);
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

