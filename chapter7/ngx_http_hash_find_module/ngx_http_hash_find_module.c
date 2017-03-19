#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_config.h>

typedef struct {
    ngx_array_t*    keyval_array;
} ngx_http_hash_find_srv_conf_t;

static ngx_int_t ngx_http_hash_find_handler(ngx_http_request_t *r);
static void* ngx_http_hash_find_create_srv_conf(ngx_conf_t *cf);
static char* ngx_conf_set_hash_find(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_http_module_t ngx_http_hash_find_module_ctx = {
    NULL,
    NULL,

    NULL,
    NULL,

    ngx_http_hash_find_create_srv_conf,
    NULL,

    NULL,
    NULL
};

static ngx_command_t ngx_http_hash_find_commands[] = {

    { ngx_string("hash_find"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_conf_set_hash_find,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("hash_add"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_keyval_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_hash_find_srv_conf_t, keyval_array),
      NULL },

    ngx_null_command
};

ngx_module_t ngx_http_hash_find_module = {
    NGX_MODULE_V1,
    &ngx_http_hash_find_module_ctx,
    ngx_http_hash_find_commands,
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
ngx_http_hash_find_handler(ngx_http_request_t *r)
{
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    ngx_int_t rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_str_t type = ngx_string("text/plain");
    ngx_str_t fmt = ngx_string("key=%V, value=%V");
    ngx_str_t nul = ngx_string("(null)");
    ngx_http_hash_find_srv_conf_t *scf;
    ngx_keyval_t *elts;
    ngx_hash_init_t hi;
    ngx_hash_keys_arrays_t ha;
    ngx_hash_combined_t hc;

    ngx_memzero(&ha, sizeof(ngx_hash_keys_arrays_t));

    ha.pool = r->pool;
    ha.temp_pool = ngx_create_pool(16384, r->connection->log);
    if (ha.temp_pool == NULL) {
        return NGX_ERROR;
    }

    // 初始化 hash_keys_arrays
    if (ngx_hash_keys_array_init(&ha, NGX_HASH_SMALL) != NGX_OK) {
        return NGX_ERROR;
    }

    scf = (ngx_http_hash_find_srv_conf_t *) ngx_http_get_module_srv_conf(r, ngx_http_hash_find_module);
    elts = scf->keyval_array->elts;

    for (ngx_uint_t i = 0; i < scf->keyval_array->nelts; ++i) {
        ngx_hash_add_key(&ha, &elts[i].key, &elts[i].value, NGX_HASH_WILDCARD_KEY);
    }

    // 初始化 hash_init
    hi.key = ngx_hash_key_lc;
    hi.max_size = 64;
    hi.bucket_size = 32;
    hi.name = "hash_find";
    hi.pool = r->pool;

    if (ha.keys.nelts) {
        hi.hash = &hc.hash; // hc.hash 不是指针 hc.wc_head hc.wc_tail 是指针
        hi.temp_pool = NULL;
        if (ngx_hash_init(&hi, ha.keys.elts, ha.keys.nelts) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (ha.dns_wc_head.nelts) {
        hi.hash = NULL;
        hi.temp_pool = ha.temp_pool;
        if (ngx_hash_wildcard_init(&hi, ha.dns_wc_head.elts, ha.dns_wc_head.nelts) != NGX_OK) {
            return NGX_ERROR;
        }
        hc.wc_head = (ngx_hash_wildcard_t *) hi.hash;
    }

    if (ha.dns_wc_tail.nelts) {
        hi.hash = NULL;
        hi.temp_pool = ha.temp_pool;
        if (ngx_hash_wildcard_init(&hi, ha.dns_wc_tail.elts, ha.dns_wc_tail.nelts) != NGX_OK) {
            return NGX_ERROR;
        }
        hc.wc_tail = (ngx_hash_wildcard_t *) hi.hash;
    }

    ngx_destroy_pool(ha.temp_pool);

    ngx_str_t args = r->args;
    ngx_str_t *rs = ngx_hash_find_combined(&hc, ngx_hash_key_lc(args.data, args.len), args.data, args.len);
    if (rs == NULL) {
        rs = &nul;
    }

    ngx_uint_t len = fmt.len + args.len + rs->len - 4;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = len;
    r->headers_out.content_type = type;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    ngx_buf_t *b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    ngx_snprintf(b->pos, len, (char *) fmt.data, &args, rs);
    b->last = b->pos + len;
    b->last_buf = 1;

    ngx_chain_t out;
    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}

static void*
ngx_http_hash_find_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_hash_find_srv_conf_t *lcf;
    lcf = (ngx_http_hash_find_srv_conf_t *) ngx_pcalloc(cf->pool, sizeof(ngx_http_hash_find_srv_conf_t));
    if (lcf == NULL) {
        return NULL;
    }

    lcf->keyval_array = NULL;

    return lcf;
}

static char*
ngx_conf_set_hash_find(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_hash_find_handler;

    return NGX_CONF_OK;
}
