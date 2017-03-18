#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_config.h>

typedef struct {
    ngx_str_t   result;
} ngx_http_sub_proxy_ctx_t;

static ngx_int_t ngx_http_sub_proxy_handler(ngx_http_request_t *r);
static char* ngx_conf_set_sub_proxy(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t sub_proxy_subrequest_post_handler(ngx_http_request_t *r, void *data, ngx_int_t rc);
static void sub_proxy_post_handler(ngx_http_request_t *r);

static ngx_http_module_t ngx_http_sub_proxy_module_ctx = {
    NULL,
    NULL,

    NULL,
    NULL,

    NULL,
    NULL,

    NULL,
    NULL
};

static ngx_command_t ngx_http_sub_proxy_commands[] = {

    { ngx_string("sub_proxy"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_conf_set_sub_proxy,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};

ngx_module_t ngx_http_sub_proxy_module = {
    NGX_MODULE_V1,
    &ngx_http_sub_proxy_module_ctx,
    ngx_http_sub_proxy_commands,
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
ngx_http_sub_proxy_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;
    ngx_http_request_t *sr;
    ngx_http_post_subrequest_t *psr;
    ngx_http_sub_proxy_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_sub_proxy_module);

    ctx = ngx_palloc(r->pool, sizeof(ngx_http_sub_proxy_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_sub_proxy_module);

    psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (psr == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    psr->handler = sub_proxy_subrequest_post_handler;
    psr->data = NULL;

    ngx_str_t loc = ngx_string("/proxy");

    // 创建 subrequest
    // NGX_HTTP_SUBREQUEST_IN_MEMORY 代表将响应保存在 buffer 中
    rc = ngx_http_subrequest(r, &loc, NULL, &sr, psr, NGX_HTTP_SUBREQUEST_IN_MEMORY);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_DONE;
}

static char*
ngx_conf_set_sub_proxy(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_sub_proxy_handler;

    return NGX_CONF_OK;
}

static ngx_int_t
sub_proxy_subrequest_post_handler(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_http_request_t *pr = r->parent;
    ngx_http_sub_proxy_ctx_t *ctx = ngx_http_get_module_ctx(pr, ngx_http_sub_proxy_module);

    pr->headers_out.status = r->headers_out.status;
    if (r->headers_out.status == NGX_HTTP_OK) { // 假装解析 http body
        ngx_str_set(&ctx->result, "http body");
    }

    // 设置父请求回调方法
    pr->write_event_handler = sub_proxy_post_handler;

    return NGX_OK;
}

static void
sub_proxy_post_handler(ngx_http_request_t *r)
{
    if (r->headers_out.status != NGX_HTTP_OK) { // 结束请求
        ngx_http_finalize_request(r, r->headers_out.status);
        return;
    }

    static ngx_str_t type = ngx_string("text/plain; charset=utf-8");
    ngx_http_sub_proxy_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_sub_proxy_module);
    ngx_str_t fmt = ngx_string("result: %V");
    ngx_uint_t len = fmt.len + ctx->result.len - 2;

    r->headers_out.content_length_n = len;
    r->headers_out.content_type = type;
    r->connection->buffered |= NGX_HTTP_WRITE_BUFFERED; // 不懂

    ngx_int_t rc = ngx_http_send_header(r); 
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        ngx_http_finalize_request(r, rc);
        return;
    }

    ngx_buf_t *b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_snprintf(b->pos, len, (char *) fmt.data, &ctx->result);
    b->last = b->pos + len;
    b->last_buf = 1;

    ngx_chain_t out;
    out.buf = b;
    out.next = NULL;

    rc = ngx_http_output_filter(r, &out);

    ngx_http_finalize_request(r, rc);
}
