#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_config.h>

typedef struct {
    ngx_str_t   pf;
    ngx_str_t   ps;
    ngx_str_t   pt;
} ngx_http_show_args_params_t;

typedef struct {
    ngx_flag_t                      args_flag;
    ngx_http_show_args_params_t     args_params; 
} ngx_http_show_args_main_conf_t;

typedef struct {
    ngx_array_t*    args_str_array;
    ngx_array_t*    args_keyval;
} ngx_http_show_args_srv_conf_t;

typedef struct {
    ngx_str_t       args_str;
    ngx_msec_t      args_msec;
    ngx_uint_t      args_enum;
} ngx_http_show_args_loc_conf_t;

static ngx_conf_enum_t ngx_http_show_args_enums[] = {
    { ngx_string("http"), 1 },
    { ngx_string("server"), 2 },
    { ngx_string("location"), 3 },
    { ngx_null_string, 0 }
};

static ngx_int_t ngx_http_show_args_handler(ngx_http_request_t *r);
static void* ngx_http_show_args_create_main_conf(ngx_conf_t *cf);
static void* ngx_http_show_args_create_srv_conf(ngx_conf_t *cf);
static void* ngx_http_show_args_create_loc_conf(ngx_conf_t *cf);
static char* ngx_http_show_args_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char* ngx_conf_set_show_args_params(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char* ngx_conf_set_show_args(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_http_module_t ngx_http_show_args_module_ctx = {
    NULL,
    NULL,

    ngx_http_show_args_create_main_conf,
    NULL,

    ngx_http_show_args_create_srv_conf,
    NULL,

    ngx_http_show_args_create_loc_conf,
    ngx_http_show_args_merge_loc_conf
};

static ngx_command_t ngx_http_show_args_commands[] = {

    { ngx_string("show_args"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_conf_set_show_args,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("args_flag"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_show_args_main_conf_t, args_flag),
      NULL },

    { ngx_string("args_str"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_show_args_loc_conf_t, args_str),
      NULL },

    { ngx_string("args_str_array"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_array_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_show_args_srv_conf_t, args_str_array),
      NULL },

    { ngx_string("args_keyval"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_keyval_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_show_args_srv_conf_t, args_keyval),
      NULL },

    { ngx_string("args_msec"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_show_args_loc_conf_t, args_msec),
      NULL },

    { ngx_string("args_enum"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_show_args_loc_conf_t, args_enum),
      ngx_http_show_args_enums },

    { ngx_string("args_params"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE123,
      ngx_conf_set_show_args_params,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};

ngx_module_t ngx_http_show_args_module = {
    NGX_MODULE_V1,
    &ngx_http_show_args_module_ctx,
    ngx_http_show_args_commands,
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
ngx_http_show_args_handler(ngx_http_request_t *r)
{
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    ngx_int_t rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    ngx_str_t type = ngx_string("text/plain");
    ngx_uint_t idx = ngx_http_show_args_module.ctx_index;
    ngx_uint_t i, len;

    ngx_http_show_args_main_conf_t *mcf = (ngx_http_show_args_main_conf_t *) r->main_conf[idx];
    u_char *mbuf = ngx_pcalloc(r->pool, 1024);

    ngx_snprintf(mbuf, 1024,
                 "http {%N\targs_flag %s;%N\targs_params_pf %V;%N\targs_params_ps %V;%N\targs_params_pt %V;%N",
                 (mcf->args_flag == 0) ? "off" : "on",
                 &mcf->args_params.pf,
                 &mcf->args_params.ps,
                 &mcf->args_params.pt);

    ngx_http_show_args_srv_conf_t *scf = (ngx_http_show_args_srv_conf_t *) r->srv_conf[idx];
    u_char *sbuf = ngx_pcalloc(r->pool, 1024);

    ngx_str_t *str_elts = scf->args_str_array->elts;

    ngx_snprintf(sbuf, 1024, "\tserver {%N");

    for (i = 0; i < scf->args_str_array->nelts; ++i) {
        len = ngx_strlen(sbuf);
        // 如果打印下标，用 %u 会导致后面那个参数出错，要用 %ui 才行
        ngx_snprintf(sbuf + len, 1024 - len, "\t\targs_str_array %V;%N", str_elts + i);
    }

    ngx_keyval_t *kv_elts = scf->args_keyval->elts;

    for (i = 0; i < scf->args_keyval->nelts; ++i) {
        len = ngx_strlen(sbuf);
        ngx_snprintf(sbuf + len, 1024 - len, "\t\targs_keyval %V %V;%N", &kv_elts[i].key, &kv_elts[i].value);
    }

    ngx_http_show_args_loc_conf_t *lcf = (ngx_http_show_args_loc_conf_t *) r->loc_conf[idx];
    u_char *lbuf = ngx_pcalloc(r->pool, 1024);

    ngx_snprintf(lbuf, 1024,
                 "\t\tlocation {%N\t\t\targs_str %V;%N\t\t\targs_msec %M;%N\t\t\targs_enum %ui;%N\t\t}%N\t}%N}",
                 &lcf->args_str, lcf->args_msec, lcf->args_enum);

    len = ngx_strlen(mbuf) + ngx_strlen(sbuf) + ngx_strlen(lbuf);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = len;
    r->headers_out.content_type = type;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    ngx_buf_t *b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_snprintf(b->pos, len, "%s%s%s", mbuf, sbuf, lbuf);
    b->last = b->pos + len;
    b->last_buf = 1;

    ngx_chain_t out;
    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}

static void*
ngx_http_show_args_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_show_args_main_conf_t *mcf;
    mcf = (ngx_http_show_args_main_conf_t *) ngx_pcalloc(cf->pool, sizeof(ngx_http_show_args_main_conf_t));
    if (mcf == NULL) {
        return NULL;
    }

    mcf->args_flag = NGX_CONF_UNSET;

    return mcf;
}

static void*
ngx_http_show_args_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_show_args_srv_conf_t *scf;
    scf = (ngx_http_show_args_srv_conf_t *) ngx_pcalloc(cf->pool, sizeof(ngx_http_show_args_srv_conf_t));
    if (scf == NULL) {
        return NULL;
    }

    scf->args_str_array = NGX_CONF_UNSET_PTR;
    scf->args_keyval = NULL;

    return scf;
}

static void*
ngx_http_show_args_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_show_args_loc_conf_t *lcf;
    lcf = (ngx_http_show_args_loc_conf_t *) ngx_pcalloc(cf->pool, sizeof(ngx_http_show_args_loc_conf_t));
    if (lcf == NULL) {
        return NULL;
    }

    lcf->args_msec = NGX_CONF_UNSET_MSEC;
    lcf->args_enum = NGX_CONF_UNSET;    // 书上没写要设置，但是不设置会出错

    return lcf;
}

static char*
ngx_http_show_args_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_show_args_loc_conf_t *prev = (ngx_http_show_args_loc_conf_t *) parent;
    ngx_http_show_args_loc_conf_t *conf = (ngx_http_show_args_loc_conf_t *) child;

    ngx_conf_merge_str_value(conf->args_str, prev->args_str, "default");

    return NGX_CONF_OK;
}

static char*
ngx_conf_set_show_args_params(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_show_args_main_conf_t *mcf = conf;
    ngx_str_t *val = cf->args->elts;

    if (cf->args->nelts > 1) {
        mcf->args_params.pf = val[1];
        if (cf->args->nelts > 2) {
            mcf->args_params.ps = val[2];
            if (cf->args->nelts > 3) {
                mcf->args_params.pt = val[3];
            }
        }
    }

    return NGX_CONF_OK;
}

static char*
ngx_conf_set_show_args(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_show_args_handler;

    return NGX_CONF_OK;
}
