#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_config.h>

typedef struct {
    u_char          rbtree_node_data;
    ngx_queue_t     queue;
    ngx_msec_t      last;
    u_short         len;
    u_char          data[1];
} ngx_http_limit_access_node_t;

typedef struct {
    ssize_t             shmsize;
    ngx_int_t           interval;
    ngx_slab_pool_t     *pool;
    ngx_rbtree_t        rbtree;
    ngx_rbtree_node_t   sentinel;
    ngx_queue_t         queue;
} ngx_http_limit_access_conf_t;

static ngx_int_t ngx_http_limit_access_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_limit_access_init(ngx_conf_t *cf);
static void* ngx_http_limit_access_create_conf(ngx_conf_t *cf);
static char* ngx_conf_set_limit_access(ngx_conf_t *cf, ngx_command_t *cmd,
        void *conf);
static ngx_int_t ngx_http_limit_access_shm_zone_init(ngx_shm_zone_t *zone, void *data);
static void ngx_http_limit_access_rbtree_insert_value(ngx_rbtree_node_t *temp,
        ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static ngx_int_t ngx_http_limit_access_lookup(ngx_http_limit_access_conf_t *conf,
        ngx_uint_t hash, u_char *data, size_t len);
static void ngx_http_limit_access_expire(ngx_http_limit_access_conf_t *conf);

static ngx_http_module_t ngx_http_limit_access_module_ctx = {
    NULL,
    ngx_http_limit_access_init,

    ngx_http_limit_access_create_conf,
    NULL,

    NULL,
    NULL,

    NULL,
    NULL
};

static ngx_command_t ngx_http_limit_access_commands[] = {

    { ngx_string("limit_access"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_limit_access,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    ngx_null_command
};

ngx_module_t ngx_http_limit_access_module = {
    NGX_MODULE_V1,
    &ngx_http_limit_access_module_ctx,
    ngx_http_limit_access_commands,
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
ngx_http_limit_access_handler(ngx_http_request_t *r)
{
    size_t                          len;
    uint32_t                        hash;
    ngx_int_t                       rc;
    ngx_http_limit_access_conf_t    *conf;

    conf = ngx_http_get_module_main_conf(r, ngx_http_limit_access_module);
    rc = NGX_DECLINED;

    if (conf->interval == -1) {
        return rc;
    }

    len = r->connection->addr_text.len + r->uri.len;
    u_char *data = ngx_palloc(r->pool, len);
    ngx_memcpy(data, r->uri.data, r->uri.len);
    ngx_memcpy(data + r->uri.len, r->connection->addr_text.data, r->connection->addr_text.len);

    hash = ngx_crc32_short(data, len);

    ngx_shmtx_lock(&conf->pool->mutex);

    rc = ngx_http_limit_access_lookup(conf, hash, data, len);

    ngx_shmtx_unlock(&conf->pool->mutex);

    return rc;
}

static ngx_int_t
ngx_http_limit_access_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt         *h;
    ngx_http_core_main_conf_t   *cmcf;
    
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_limit_access_handler;

    return NGX_OK;
}

static void*
ngx_http_limit_access_create_conf(ngx_conf_t *cf)
{
    ngx_http_limit_access_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_limit_access_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->interval = -1;
    conf->shmsize = -1;

    return conf;
}

static char*
ngx_conf_set_limit_access(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                       *value;
    ngx_shm_zone_t                  *zone;
    ngx_http_limit_access_conf_t    *mcf;

    ngx_str_t name = ngx_string("limit_access_slab_shm");

    value = cf->args->elts;
    mcf = (ngx_http_limit_access_conf_t *) conf;
    mcf->interval = 1000 * ngx_atoi(value[1].data, value[1].len);

    if (mcf->interval == NGX_ERROR || mcf->interval == 0) {
        mcf->interval = -1;
        return "invalid value";
    }

    mcf->shmsize = ngx_parse_size(&value[2]);
    if (mcf->shmsize == NGX_ERROR || mcf->shmsize == 0) {
        mcf->interval = -1;
        return "invalid value";
    }

    zone = ngx_shared_memory_add(cf, &name, mcf->shmsize, &ngx_http_limit_access_module);
    if (zone == NULL) {
        mcf->interval = -1;
        return NGX_CONF_ERROR;
    }

    zone->init = ngx_http_limit_access_shm_zone_init;
    zone->data = mcf;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_limit_access_shm_zone_init(ngx_shm_zone_t *zone, void *data)
{
    ngx_http_limit_access_conf_t *conf, *oconf;
    size_t len;

    conf = zone->data;
    oconf = data;

    if (oconf) {
        conf->rbtree = oconf->rbtree;
        conf->sentinel = oconf->sentinel;
        conf->queue = oconf->queue;
        conf->pool = oconf->pool;
        return NGX_OK;
    }

    conf->pool = (ngx_slab_pool_t *) zone->shm.addr;

    conf->pool->data = &conf->rbtree;

    ngx_rbtree_init(&conf->rbtree, &conf->sentinel, ngx_http_limit_access_rbtree_insert_value);
    ngx_queue_init(&conf->queue);

    len = sizeof(" in slab \"\"") + zone->shm.name.len;

    conf->pool->log_ctx = ngx_slab_alloc(conf->pool, len);
    if (conf->pool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(conf->pool->log_ctx, " in slab \"%V\"%Z", &zone->shm.name);

    return NGX_OK;
}

static void
ngx_http_limit_access_rbtree_insert_value(ngx_rbtree_node_t *temp,
        ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t               **p;
    ngx_http_limit_access_node_t    *lrn, *lrnt;

    lrn = (ngx_http_limit_access_node_t *) &node->data;

    for ( ;; ) {
        if (node->key < temp->key) {
            p = &temp->left;
        } else if (node->key > temp->key) {
            p = &temp->right;
        } else {
            lrnt = (ngx_http_limit_access_node_t *) &temp->data;
            p = (ngx_memn2cmp(lrn->data, lrnt->data, lrn->len, lrnt->len) < 0) ?
                &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}

static ngx_int_t
ngx_http_limit_access_lookup(ngx_http_limit_access_conf_t *conf, ngx_uint_t hash,
        u_char *data, size_t len)
{
    size_t                          size;
    ngx_int_t                       rc;
    ngx_time_t                      *tp;
    ngx_msec_t                      now;
    ngx_rbtree_node_t               *node, *sentinel;
    ngx_http_limit_access_node_t    *lr;

    tp = ngx_timeofday();
    now = (ngx_msec_t) (tp->sec * 1000 + tp->msec);

    node = conf->rbtree.root;
    sentinel = conf->rbtree.sentinel;

    while (node != sentinel) {
        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        lr = (ngx_http_limit_access_node_t *) &node->data;
        rc = ngx_memn2cmp(data, lr->data, len, (size_t) lr->len);

        if (rc == 0) {
            if (now > lr->last + conf->interval) {
                lr->last = now;

                ngx_queue_remove(&lr->queue);
                ngx_queue_insert_head(&conf->queue, &lr->queue);

                return NGX_DECLINED;
            } else {
                return NGX_HTTP_FORBIDDEN;
            }
        }

        node = (rc < 0) ? node->left : node->right;
    }

    // 没找到则为初次访问 添加新节点

    ngx_http_limit_access_expire(conf);

    size = offsetof(ngx_rbtree_node_t, data) +
        offsetof(ngx_http_limit_access_node_t, data) + len;
    node = ngx_slab_alloc_locked(conf->pool, size);

    if (node == NULL) {
        return NGX_ERROR;
    }

    node->key = hash;

    lr = (ngx_http_limit_access_node_t *) &node->data;
    lr->last = now;
    lr->len = (u_char) len;
    ngx_memcpy(lr->data, data, len);

    ngx_rbtree_insert(&conf->rbtree, node);

    ngx_queue_insert_head(&conf->queue, &lr->queue);

    return NGX_DECLINED;
}

static void
ngx_http_limit_access_expire(ngx_http_limit_access_conf_t *conf)
{
    ngx_time_t                      *tp;
    ngx_msec_t                      now;
    ngx_queue_t                     *q;
    ngx_rbtree_node_t               *node;
    ngx_http_limit_access_node_t    *lr;

    tp = ngx_timeofday();
    now = (ngx_msec_t) (tp->sec * 1000 + tp->msec);

    for ( ;; ) {
        if (ngx_queue_empty(&conf->queue)) {
            return;
        }

        q = ngx_queue_last(&conf->queue);
        lr = ngx_queue_data(q, ngx_http_limit_access_node_t, queue);
        node = (ngx_rbtree_node_t *) 
            ((u_char *) lr - offsetof(ngx_rbtree_node_t, data));
        
        if (now < lr->last + conf->interval) {
            return;
        }

        ngx_queue_remove(q);
        ngx_rbtree_delete(&conf->rbtree, node);
        ngx_slab_free_locked(conf->pool, node);
    }
}
