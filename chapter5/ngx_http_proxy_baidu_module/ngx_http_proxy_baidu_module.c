#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_config.h>

typedef struct {
    ngx_http_upstream_conf_t    upstream;
} ngx_http_proxy_baidu_loc_conf_t;

typedef struct {
    ngx_http_status_t   status;
} ngx_http_proxy_baidu_ctx_t;

static ngx_int_t ngx_http_proxy_baidu_handler(ngx_http_request_t *r);
static void* ngx_http_proxy_baidu_create_loc_conf(ngx_conf_t *cf);
static char* ngx_http_proxy_baidu_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char* ngx_conf_set_proxy_baidu(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t proxy_baidu_create_request(ngx_http_request_t *r);
static ngx_int_t proxy_baidu_process_line(ngx_http_request_t *r);
static ngx_int_t proxy_baidu_process_header(ngx_http_request_t *r);
static void proxy_baidu_finalize_request(ngx_http_request_t *r, ngx_int_t rc);

// ngx_http_proxy_module.c -> ngx_http_proxy_hide_headers
static ngx_str_t ngx_http_proxy_baidu_hide_headers[] = {
    ngx_string("Data"),
    ngx_string("Server"),
    ngx_string("X-Pad"),
    ngx_string("X-Accel-Expires"),
    ngx_string("X-Accel-Redirect"),
    ngx_string("X-Accel-Limit-Rate"),
    ngx_string("X-Accel-Buffering"),
    ngx_string("X-Accel-Charset"),
    ngx_null_string
};

static ngx_http_module_t ngx_http_proxy_baidu_module_ctx = {
    NULL,
    NULL,

    NULL,
    NULL,

    NULL,
    NULL,

    ngx_http_proxy_baidu_create_loc_conf,
    ngx_http_proxy_baidu_merge_loc_conf
};

static ngx_command_t ngx_http_proxy_baidu_commands[] = {

    { ngx_string("proxy_baidu"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_conf_set_proxy_baidu,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("c_timeout"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_baidu_loc_conf_t, upstream.connect_timeout),
      NULL },

    { ngx_string("s_timeout"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_baidu_loc_conf_t, upstream.send_timeout),
      NULL },

    { ngx_string("r_timeout"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_baidu_loc_conf_t, upstream.read_timeout),
      NULL },

    ngx_null_command
};

ngx_module_t ngx_http_proxy_baidu_module = {
    NGX_MODULE_V1,
    &ngx_http_proxy_baidu_module_ctx,
    ngx_http_proxy_baidu_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_http_proxy_baidu_handler(ngx_http_request_t *r)
{
    ngx_http_upstream_t *u;
    ngx_http_proxy_baidu_loc_conf_t *lcf;
    ngx_http_proxy_baidu_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_baidu_module);

    ctx = ngx_palloc(r->pool, sizeof(ngx_http_proxy_baidu_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_proxy_baidu_module);

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_ERROR;
    }

    u = r->upstream; // 不能在 create 前初始化

    lcf = (ngx_http_proxy_baidu_loc_conf_t *) ngx_http_get_module_loc_conf(r, ngx_http_proxy_baidu_module);
    u->conf = ngx_palloc(r->pool, sizeof(ngx_http_upstream_conf_t));
    ngx_memcpy(u->conf, &lcf->upstream, sizeof(ngx_http_upstream_conf_t));

    u->buffering = lcf->upstream.buffering;
    u->resolved = (ngx_http_upstream_resolved_t *) ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
    if (u->resolved == NULL) {
        return NGX_ERROR;
    }

    struct addrinfo hints, *result;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    if (getaddrinfo("www.baidu.com", "80", &hints, &result) != 0) {
        return NGX_ERROR;
    }

    u->resolved->sockaddr = result->ai_addr;
    u->resolved->socklen = result->ai_addrlen;
    u->resolved->naddrs = 1;
    u->resolved->port = htons(80);  // 不设置会报错

    u->create_request = proxy_baidu_create_request;
    u->process_header = proxy_baidu_process_line;
    u->finalize_request = proxy_baidu_finalize_request;

    r->main->count++;
    ngx_http_upstream_init(r);

    return NGX_DONE;
}

static void*
ngx_http_proxy_baidu_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_proxy_baidu_loc_conf_t *lcf;
    lcf = (ngx_http_proxy_baidu_loc_conf_t *) ngx_pcalloc(cf->pool, sizeof(ngx_http_proxy_baidu_loc_conf_t));
    if (lcf == NULL) {
        return NULL;
    }

    lcf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    lcf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    lcf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;

    // 硬编码
    lcf->upstream.store_access = 0600;
    lcf->upstream.buffering = 0;
    lcf->upstream.buffer_size = ngx_pagesize;

    // 等到 merge 再设置
    lcf->upstream.hide_headers = NGX_CONF_UNSET_PTR;
    lcf->upstream.pass_headers = NGX_CONF_UNSET_PTR;
    
    return lcf;
}

static char*
ngx_http_proxy_baidu_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_proxy_baidu_loc_conf_t *prev = (ngx_http_proxy_baidu_loc_conf_t *) parent;
    ngx_http_proxy_baidu_loc_conf_t *conf = (ngx_http_proxy_baidu_loc_conf_t *) child;

    ngx_hash_init_t hash;
    hash.max_size = 100;
    hash.bucket_size = 1024;
    hash.name = "proxy_headers_hash";

    // ngx_http_upstream.c 建立 hash 表
    if (ngx_http_upstream_hide_headers_hash(cf, &conf->upstream, &prev->upstream, 
                ngx_http_proxy_baidu_hide_headers, &hash) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;

}

static char*
ngx_conf_set_proxy_baidu(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_proxy_baidu_handler;

    return NGX_CONF_OK;
}

static ngx_int_t
proxy_baidu_create_request(ngx_http_request_t *r)
{
    static ngx_str_t req = ngx_string("GET /s?wd=%V HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n");

    ngx_int_t len = req.len + r->args.len - 2;
    ngx_buf_t *b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }
    b->last = b->pos + len;

    ngx_snprintf(b->pos, len, (char *) req.data, &r->args);
    r->upstream->request_bufs = ngx_alloc_chain_link(r->pool);
    if (r->upstream->request_bufs == NULL) {
        return NGX_ERROR;
    }

    r->upstream->request_bufs->buf = b;
    r->upstream->request_bufs->next = NULL;

    r->upstream->request_sent = 0;
    r->upstream->header_sent = 0;
    // 不懂
    r->header_hash = 1;

    return NGX_OK;
}

static ngx_int_t
proxy_baidu_process_line(ngx_http_request_t *r)
{
    size_t len;
    ngx_int_t rc;
    ngx_http_upstream_t *u = r->upstream;

    ngx_http_proxy_baidu_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_proxy_baidu_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    rc = ngx_http_parse_status_line(r, &u->buffer, &ctx->status);
    if (rc == NGX_AGAIN) { // 响应行不完整
        return NGX_AGAIN;
    }

    if (rc == NGX_ERROR) { // 响应行不合法
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "upstream sent no valid HTTP header");

        // 为什么这样返回
        r->http_version = NGX_HTTP_VERSION_9;
        u->state->status = NGX_HTTP_OK;

        return NGX_OK;
    }

    len = ctx->status.end - ctx->status.start; 

    if (u->state) {
        u->state->status = ctx->status.code;
    }
    u->headers_in.status_n = ctx->status.code;
    u->headers_in.status_line.len = len;
    u->headers_in.status_line.data = ngx_pnalloc(r->pool, len);
    if (u->headers_in.status_line.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(u->headers_in.status_line.data, ctx->status.start, len);

    // 之后收到的数据由其他函数解析
    u->process_header = proxy_baidu_process_header;

    return proxy_baidu_process_header(r); // 处理剩余数据
}

static ngx_int_t
proxy_baidu_process_header(ngx_http_request_t *r)
{
    ngx_int_t rc;
    ngx_table_elt_t *h;
    ngx_http_upstream_header_t *hh;
    ngx_http_upstream_t *u = r->upstream;
    ngx_http_upstream_main_conf_t *mcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

    // 添加头部到 headers_in.headers
    for ( ;; ) {
        // 第三个参数代表是否允许下划线
        rc = ngx_http_parse_header_line(r, &u->buffer, 1);
        if (rc == NGX_OK) {
            h = ngx_list_push(&u->headers_in.headers);
            if (h == NULL) {
                return NGX_ERROR;
            }

            h->hash = r->header_hash;
            h->key.len = r->header_name_end - r->header_name_start;
            h->value.len = r->header_end - r->header_start;

            // header 数据在 u->buffer 中，之后可能会被覆盖，所以需要额外分配一块空间
            h->key.data = ngx_pnalloc(r->pool, h->key.len + h->value.len + h->key.len);
            if (h->key.data == NULL) {
                return NGX_ERROR;
            }
            h->value.data = h->key.data + h->key.len;
            h->lowcase_key = h->value.data + h->value.len;

            ngx_memcpy(h->key.data, r->header_name_start, h->key.len);
            ngx_memcpy(h->value.data, r->header_start, h->value.len);

            /* ngx_http_parse.c -> ngx_http_parse_header_line
               粗略看了一下 key.len != lowcase_index 的情况好像有两种
               第一种情况是 key 的长度大于 32
               第二种情况是 key 中存在奇奇怪怪的字符 */
            if (h->key.len == r->lowcase_index) {
                ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);
            } else {
                ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
            }

            hh = ngx_hash_find(&mcf->headers_in_hash, h->hash, h->lowcase_key, h->key.len);

            // 不懂
            if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
                return NGX_ERROR;
            }

            continue;
        }

        // 如果没有则设置 server 和 date 头部
        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
            if (u->headers_in.server == NULL) {
                h = ngx_list_push(&u->headers_in.headers);
                if (h == NULL) {
                    return NGX_ERROR;
                }

                h->hash = ngx_hash_key((u_char *) "server", 6);

                // 这里可以不用分配空间 因为是字符串常量
                ngx_str_set(&h->key, "Server");
                ngx_str_null(&h->value);
                h->lowcase_key = (u_char *) "server";
            }

            if (u->headers_in.date == NULL) {
                h = ngx_list_push(&u->headers_in.headers);
                if (h == NULL) {
                    return NGX_ERROR;
                }

                h->hash = ngx_hash_key((u_char *) "date", 4);

                ngx_str_set(&h->key, "Date");
                ngx_str_null(&h->value);
                h->lowcase_key = (u_char *) "date";
            }

            return NGX_OK;
        }

        if (rc == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        // 其他返回值不合法
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "upstream sent invalid header");

        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }
}

static void
proxy_baidu_finalize_request(ngx_http_request_t *r, ngx_int_t rc) 
{
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "upstream finalize request with %d", rc);
}
