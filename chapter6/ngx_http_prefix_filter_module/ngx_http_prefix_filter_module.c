#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_config.h>

#define NGX_PREFIX_NULL 0
#define NGX_PREFIX_NEED 1
#define NGX_PREFIX_DONE 2

typedef struct {
    ngx_flag_t  enable;
} ngx_http_prefix_filter_loc_conf_t;

typedef struct {
    ngx_uint_t  status;
} ngx_http_prefix_filter_ctx_t;

static ngx_http_output_header_filter_pt ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

static ngx_int_t ngx_http_prefix_filter_init(ngx_conf_t *cf);
static void* ngx_http_prefix_filter_create_loc_conf(ngx_conf_t *cf);
static char* ngx_http_prefix_filter_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_prefix_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_prefix_body_filter(ngx_http_request_t *r, ngx_chain_t *in);

static ngx_str_t prefix = ngx_string("[prefix]");

static ngx_http_module_t ngx_http_prefix_filter_module_ctx = {
    NULL,
    ngx_http_prefix_filter_init,

    NULL,
    NULL,

    NULL,
    NULL,

    ngx_http_prefix_filter_create_loc_conf,
    ngx_http_prefix_filter_merge_loc_conf
};

static ngx_command_t ngx_http_prefix_filter_commands[] = {

    { ngx_string("prefix_enable"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_prefix_filter_loc_conf_t, enable),
      NULL },

    ngx_null_command
};

ngx_module_t ngx_http_prefix_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_prefix_filter_module_ctx,
    ngx_http_prefix_filter_commands,
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
ngx_http_prefix_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_prefix_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_prefix_body_filter;

    return NGX_OK;
}

static void*
ngx_http_prefix_filter_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_prefix_filter_loc_conf_t *lcf;
    lcf = (ngx_http_prefix_filter_loc_conf_t *) ngx_pcalloc(cf->pool, sizeof(ngx_http_prefix_filter_loc_conf_t));
    if (lcf == NULL) {
        return NULL;
    }

    lcf->enable = NGX_CONF_UNSET;

    return lcf;
}

static char*
ngx_http_prefix_filter_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_prefix_filter_loc_conf_t *prev = (ngx_http_prefix_filter_loc_conf_t *) parent;
    ngx_http_prefix_filter_loc_conf_t *conf = (ngx_http_prefix_filter_loc_conf_t *) child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_prefix_header_filter(ngx_http_request_t *r)
{
    static ngx_str_t type = ngx_string("text/plain");

    if (r->headers_out.status != NGX_HTTP_OK) {
        return ngx_http_next_header_filter(r);
    }

    ngx_http_prefix_filter_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_prefix_filter_module);
    if (ctx) {
        return ngx_http_next_header_filter(r);
    }

    ngx_http_prefix_filter_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_prefix_filter_module);
    if (conf->enable == 0) {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_palloc(r->pool, sizeof(ngx_http_prefix_filter_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_prefix_filter_module);

    if (r->headers_out.content_type.len >= type.len &&
            ngx_strncasecmp(r->headers_out.content_type.data, type.data, type.len) == 0) {
        ctx->status = NGX_PREFIX_NEED;
        if (r->headers_out.content_length_n > 0) {
            r->headers_out.content_length_n += prefix.len;
        }
    } else {
        ctx->status = NGX_PREFIX_NULL;
    }

    return ngx_http_next_header_filter(r);
}

static ngx_int_t
ngx_http_prefix_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_http_prefix_filter_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_prefix_filter_module);
    if (ctx == NULL || ctx->status != NGX_PREFIX_NEED) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx->status = NGX_PREFIX_DONE;

    ngx_buf_t *b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->start = b->pos = prefix.data;
    b->last = b->pos + prefix.len;
    b->temporary = 1;

    ngx_chain_t *out = ngx_alloc_chain_link(r->pool);
    out->buf = b;
    out->next = in;

    return ngx_http_next_body_filter(r, out);
}
