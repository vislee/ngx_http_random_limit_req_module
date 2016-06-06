
/*
 * Copyright (C) SAE wenqiang3@staff.sina.com.cn
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#ifndef NGX_RANDOM_LIMIT_IGNORE_BITMASK
#define NGX_RANDOM_LIMIT_IGNORE_BITMASK  1
#endif


#if (NGX_RANDOM_LIMIT_IGNORE_BITMASK)
#define NGX_LIMIT_IGNORE_CSS    0x0002
#define NGX_LIMIT_IGNORE_JS     0x0004
// #define NGX_LIMIT_IGNORE_HTML   0x0008
// #define NGX_LIMIT_IGNORE_HTM    0x0010
// #define NGX_LIMIT_IGNORE_XML    0x0020
// #define NGX_LIMIT_IGNORE_TXT    0x0040
#endif

#define ngx_strrchr(s1, c)   strrchr((const char *) s1, (int) c)

typedef struct {
    ngx_str_node_t     sn;             /* {node, str:domain} */
    ngx_queue_t        queue;
    time_t             expire;
    ngx_uint_t         ratio;
    ngx_uint_t         limit_count;
    ngx_uint_t         total_count;
    u_char             domain;
} ngx_http_random_limit_node_t;

typedef struct {
    ngx_rbtree_t       rbtree;
    ngx_rbtree_node_t  sentinel;
    ngx_queue_t        queue;
} ngx_http_random_limit_shctx_t;

typedef struct {
    ngx_http_random_limit_shctx_t  *sh;
    ngx_slab_pool_t                *shpool;
} ngx_http_random_limit_ctx_t;

typedef struct {
    time_t                    limit_continue_sec;
    ngx_shm_zone_t           *shm_zone;
#if !(NGX_RANDOM_LIMIT_IGNORE_BITMASK)
    ngx_array_t              *ignore_types;
#else
    ngx_uint_t                ignore_types2;
#endif
    size_t                    size;
} ngx_http_random_limit_srv_conf_t;


typedef struct {
    ngx_str_t   domain;
    ngx_uint_t  ratio;
    time_t      expire;
} ngx_http_random_limit_args_t;


typedef struct {
    ngx_str_t   domain;
    ngx_str_t   ip;
} ngx_http_random_limit_remote_t;


static ngx_str_t ngx_http_random_limit_allow     = ngx_string("allow");
static ngx_str_t ngx_http_random_limit_deny      = ngx_string("deny");

static ngx_str_t ngx_http_random_limit_res_ok    = ngx_string("ok");
static ngx_str_t ngx_http_random_limit_res_err   = ngx_string("error");
static ngx_str_t ngx_http_random_limit_res_null  = ngx_string("null");


static ngx_int_t ngx_http_random_limit_add_variables(ngx_conf_t *cf);
static void *ngx_http_random_limit_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_random_limit_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_random_limit_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_random_limit_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_random_limit_ctx_init_zone(ngx_shm_zone_t *shm_zone, void *data);
static ngx_int_t ngx_http_random_limit_get(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_random_limit_args_parse(ngx_str_t *arg, ngx_http_random_limit_args_t *args);
static ngx_int_t ngx_http_random_limit_update_rule(ngx_http_random_limit_ctx_t *ctx, ngx_http_random_limit_args_t *args);
static ngx_int_t ngx_http_random_limit_rule_dump(ngx_buf_t *b, ngx_uint_t *rl, ngx_http_random_limit_ctx_t *ctx, 
    ngx_http_random_limit_args_t *args);
static ngx_int_t ngx_http_random_limit_handler(ngx_http_request_t *r);



static ngx_http_variable_t ngx_http_random_limit_variable[] = {

  { ngx_string("sae_limit_act"), NULL, ngx_http_random_limit_get, 0, 0, 0 },

  { ngx_null_string, NULL, NULL, 0, 0, 0 }

};

#if (NGX_RANDOM_LIMIT_IGNORE_BITMASK)
static ngx_conf_bitmask_t  ngx_http_random_limit_ignore_types[] = {
    { ngx_string(".css"), NGX_LIMIT_IGNORE_CSS },
    { ngx_string(".js"), NGX_LIMIT_IGNORE_JS },
    // { ngx_string(".html"), NGX_LIMIT_IGNORE_HTML },
    // { ngx_string(".htm"), NGX_LIMIT_IGNORE_HTM },
    // { ngx_string(".xml"), NGX_LIMIT_IGNORE_XML },
    // { ngx_string(".txt"), NGX_LIMIT_IGNORE_TXT },
    { ngx_null_string, 0 }
};
#endif

static ngx_command_t ngx_http_random_limit_commands[] = {

    { ngx_string("sae_random_limit"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_random_limit_command,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("sae_limit_continue"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_random_limit_srv_conf_t, limit_continue_sec),
      NULL },

    { ngx_string("sae_limit_cache_zone_size"),
      NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_random_limit_zone,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

#if !(NGX_RANDOM_LIMIT_IGNORE_BITMASK)
    { ngx_string("sae_limit_ignore_types"),
      NGX_HTTP_SRV_CONF|NGX_CONF_ANY,
      ngx_http_types_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_random_limit_srv_conf_t, ignore_types),
      NULL },
#else
    { ngx_string("sae_limit_ignore_types"),
      NGX_HTTP_SRV_CONF|NGX_CONF_ANY,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_random_limit_srv_conf_t, ignore_types2),
      ngx_http_random_limit_ignore_types },
#endif

    ngx_null_command
};


static ngx_http_module_t  ngx_http_random_limit_module_ctx = {
    ngx_http_random_limit_add_variables,        /* preconfiguration */
    NULL,                                   /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    ngx_http_random_limit_create_srv_conf,      /* create server configuration */
    ngx_http_random_limit_merge_srv_conf,       /* merge server configuration */

    NULL,                                   /* create location configuration */
    NULL                                    /* merge location configuration */
};


ngx_module_t  ngx_http_random_limit_req_module = {
    NGX_MODULE_V1,
    &ngx_http_random_limit_module_ctx,          /* module context */
    ngx_http_random_limit_commands,             /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t 
ngx_http_random_limit_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t         *ite;
    ngx_http_variable_t         *v;

    for (ite = ngx_http_random_limit_variable; ite->name.len; ite++) {
        v = ngx_http_add_variable(cf, &ite->name, ite->flags);
        if (v == NULL) {
            return NGX_ERROR;
        }
        v->set_handler = ite->set_handler;
        v->get_handler = ite->get_handler;
        v->data = ite->data;
    }

    return NGX_OK;
}


static void *
ngx_http_random_limit_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_random_limit_srv_conf_t  *lscf;

    lscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_random_limit_srv_conf_t));
    if (NULL == lscf) {
        return NULL;
    }

#if (NGX_RANDOM_LIMIT_IGNORE_BITMASK)
    lscf->ignore_types2 = 0;
#endif
    lscf->limit_continue_sec = NGX_CONF_UNSET;
    lscf->shm_zone = NULL;
    lscf->size     = NGX_CONF_UNSET_SIZE;

    return lscf;
}


static char *
ngx_http_random_limit_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_random_limit_srv_conf_t *prev = parent;
    ngx_http_random_limit_srv_conf_t *conf = child;

    ngx_conf_merge_sec_value(conf->limit_continue_sec,
                              prev->limit_continue_sec, 300);

    if (NULL == conf->shm_zone) {
        if (NULL == prev->shm_zone) {
            ngx_log_error(NGX_LOG_ERR, cf->log, 
                0, "sae_random_limit_cache_shm_zone null, please check nginx.conf \"sae_limit_cache_zone_size\" ");
            return NGX_CONF_ERROR;
        }
        conf->shm_zone = prev->shm_zone;
        conf->size     = prev->size;
    }

#if !(NGX_RANDOM_LIMIT_IGNORE_BITMASK)
    if (NULL == conf->ignore_types) {
        conf->ignore_types = prev->ignore_types;
    }
#else
    if (0 == conf->ignore_types2) {
        conf->ignore_types2 = prev->ignore_types2;
    }
#endif

    return NGX_CONF_OK;
}


static char *
ngx_http_random_limit_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) 
{
    ngx_str_t                            zone_name;
    ngx_shm_zone_t                      *shm_zone;
    ngx_http_random_limit_ctx_t             *ctx;
    ngx_http_random_limit_srv_conf_t        *lscf;
    ngx_str_t                           *value;
    size_t                               size;

    lscf = conf;
    value = cf->args->elts;
    size = ngx_parse_size(&value[1]);

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_random_limit_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_str_set(&zone_name, "sae_random_limit_cache_shm_zone");

    shm_zone = ngx_shared_memory_add(cf, &zone_name, size, &ngx_http_random_limit_req_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    shm_zone->init = ngx_http_random_limit_ctx_init_zone;
    shm_zone->data = ctx;

    lscf->shm_zone = shm_zone;
    lscf->size     = size;
    return NGX_CONF_OK;
}



static ngx_int_t
ngx_http_random_limit_ctx_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_random_limit_ctx_t   *octx = data;

    size_t                         len;
    ngx_http_random_limit_ctx_t   *ctx;

    ctx = shm_zone->data;

    if (NULL != octx) {
        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;

        return NGX_OK;
    }

    ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->sh = ctx->shpool->data;
        return NGX_OK;
    }

    ctx->sh = ngx_slab_alloc(ctx->shpool, sizeof(ngx_http_random_limit_ctx_t));
    if (NULL == ctx->sh) {
        return NGX_ERROR;
    }

    ctx->shpool->data = ctx->sh;

    // ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
    //                 ngx_http_random_limit_rbtree_insert_value);
    ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    ngx_str_rbtree_insert_value);

    ngx_queue_init(&ctx->sh->queue);

    len = sizeof(" in_random limit zone \"\"") + shm_zone->shm.name.len;

    ctx->shpool->log_ctx = ngx_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(ctx->shpool->log_ctx, " in_random limit zone \"%V\"%Z",
                &shm_zone->shm.name);


    return NGX_OK;
}

#if !(NGX_RANDOM_LIMIT_IGNORE_BITMASK)
static ngx_int_t
ngx_limit_check_type(ngx_http_request_t *r) {
    ngx_http_random_limit_srv_conf_t    *lscf;
    ngx_array_t                         *types;
    ngx_hash_key_t                      *type;
    ngx_uint_t                           i;

    lscf = ngx_http_get_module_srv_conf(r, ngx_http_random_limit_req_module);
    if (NULL == lscf) {
        return NGX_ERROR;
    }

    types = lscf->ignore_types;
    if (types == NULL || types->nelts == 0) {
        return NGX_OK;
    }

    type = types->elts;
    for (i = 0; i < types->nelts; i++) {
        if (ngx_memcmp(type[i].key.data, r->uri.data + r->uri.len - type[i].key.len, type[i].key.len) == 0){
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

#else

static ngx_int_t
ngx_limit_check_type(ngx_http_request_t *r) {
    ngx_http_random_limit_srv_conf_t    *lscf;
    ngx_uint_t                ignore_types2;

    lscf = ngx_http_get_module_srv_conf(r, ngx_http_random_limit_req_module);
    if (NULL == lscf) {
        return NGX_ERROR;
    }

    ignore_types2 = lscf->ignore_types2;
    if (ignore_types2 == 0) {
        return NGX_OK;
    }

    if (ignore_types2 & NGX_LIMIT_IGNORE_CSS) {
        if (ngx_memcmp(".css", r->uri.data+r->uri.len-4, 4) == 0) {
            return NGX_ERROR;
        }
    }

    if (ignore_types2 & NGX_LIMIT_IGNORE_JS) {
        if (ngx_memcmp(".js", r->uri.data+r->uri.len-3, 3) == 0) {
            return NGX_ERROR;
        }
    }

    // if (ignore_types2 & NGX_LIMIT_IGNORE_HTML) {
    //     if (ngx_memcmp(".html", r->uri.data+r->uri.len-5, 5) == 0) {
    //         return NGX_ERROR;
    //     }
    // }

    return NGX_OK;
}
#endif

static void 
ngx_limit_act_parse(ngx_http_request_t *r, ngx_http_random_limit_node_t *lint, ngx_time_t *nt, ngx_http_variable_value_t *v)
{
    ngx_int_t   chk_type_res;

    v->len = ngx_http_random_limit_allow.len;
    v->data = ngx_http_random_limit_allow.data;

    if (NULL != lint && lint->expire > nt->sec) {
        lint->total_count += 1;
        chk_type_res = ngx_limit_check_type(r);
        if (chk_type_res == NGX_OK && (lint->limit_count * 10 < lint->total_count * lint->ratio)) {
                lint->limit_count += 1;
                v->len = ngx_http_random_limit_deny.len;
                v->data = ngx_http_random_limit_deny.data;
        }
        if (lint->total_count > 10) {
            lint->total_count = 0;
            lint->limit_count = 0;
        }
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return;
}

static void 
ngx_remote_ip_init(ngx_http_random_limit_remote_t *lirt) {

    lirt->ip.len    = 0;
    lirt->ip.data   = NULL;
    lirt->domain.len    = 0;
    lirt->domain.data   = NULL;

    return;
}

static void 
ngx_remote_ip_format(ngx_http_random_limit_remote_t *lirt) {
    if (lirt->domain.len > 4 && ngx_memcmp(lirt->domain.data, "www.", 4)==0) {
        lirt->domain.data += 4;
        lirt->domain.len -= 4;
    }
    return;
}

static ngx_int_t 
ngx_http_random_limit_get(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_random_limit_srv_conf_t    *lscf;
    ngx_http_random_limit_node_t        *lint;
    ngx_http_random_limit_ctx_t         *ctx;
    ngx_http_random_limit_remote_t       lirt;
    uint32_t                         hash;
    ngx_time_t                      *nt;

    lscf = ngx_http_get_module_srv_conf(r, ngx_http_random_limit_req_module);
    if (NULL == lscf) {
        return NGX_ERROR;
    }

    ctx = (ngx_http_random_limit_ctx_t*)lscf->shm_zone->data;
    if (NULL == ctx) {
        return NGX_ERROR;
    }

    ngx_remote_ip_init(&lirt);
    lirt.ip.data = r->connection->addr_text.data;
    lirt.ip.len  = r->connection->addr_text.len;
    lirt.domain.data = r->headers_in.server.data;
    lirt.domain.len =  r->headers_in.server.len;
    ngx_remote_ip_format(&lirt);

    hash = ngx_crc32_long(lirt.domain.data, lirt.domain.len);
    nt   = ngx_timeofday();

    // search ip
    ngx_shmtx_lock(&ctx->shpool->mutex);
    lint = (ngx_http_random_limit_node_t *)
           ngx_str_rbtree_lookup(&ctx->sh->rbtree, &lirt.domain, hash);
    ngx_limit_act_parse(r, lint, nt, v);
    ngx_shmtx_unlock(&ctx->shpool->mutex);


    return NGX_OK;
}


static ngx_http_random_limit_node_t *
ngx_http_random_limit_alloc_node_lru(ngx_http_random_limit_ctx_t *ctx, size_t len)
{
    ngx_uint_t                 i;
    ngx_http_random_limit_node_t  *lint;
    ngx_queue_t               *q;

    lint = ngx_slab_alloc_locked(ctx->shpool, len);
    if (NULL == lint) {
        for (i = 0; i < 10 && lint == NULL; i++) {
            if (ngx_queue_empty(&ctx->sh->queue)) {
                break;
            }

            q = ngx_queue_last(&ctx->sh->queue);
            // lint = (ngx_http_random_limit_node_t *)
            //        (q - offsetof(ngx_http_random_limit_node_t, queue));
            lint = ngx_queue_data(q, ngx_http_random_limit_node_t, queue);

            ngx_queue_remove(q);
            ngx_rbtree_delete(&ctx->sh->rbtree, &lint->sn.node);
            ngx_slab_free_locked(ctx->shpool, lint);

            lint = ngx_slab_alloc_locked(ctx->shpool, len);
        }
    }
    return lint;
}


static ngx_int_t
ngx_http_random_limit_update_rule(ngx_http_random_limit_ctx_t *ctx, ngx_http_random_limit_args_t *args)
{
    uint32_t                         hash;
    ngx_time_t                      *nt;
    ngx_http_random_limit_node_t    *lint;

    hash = ngx_crc32_long(args->domain.data, args->domain.len);
    nt   = ngx_timeofday();

    ngx_shmtx_lock(&ctx->shpool->mutex);
    lint = (ngx_http_random_limit_node_t *)
           ngx_str_rbtree_lookup(&ctx->sh->rbtree, &args->domain, hash);

    if (NULL == lint) {
        lint = ngx_http_random_limit_alloc_node_lru(ctx, sizeof(ngx_http_random_limit_node_t)+args->domain.len);
        if (NULL == lint) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            return NGX_ERROR;
        }

        lint->sn.node.key = hash;
        ngx_memcpy(&lint->domain, args->domain.data, args->domain.len);
        lint->sn.str.len  = args->domain.len;
        lint->sn.str.data = &lint->domain;
        lint->expire = nt->sec + args->expire;
        lint->ratio  = args->ratio;
        if (lint->ratio < 1 || lint->ratio > 9) {
            lint->ratio = 5;
        }
        lint->limit_count = 0;
        lint->total_count = 0;

        ngx_rbtree_insert(&ctx->sh->rbtree, &lint->sn.node);
        ngx_queue_insert_head(&ctx->sh->queue, &lint->queue);
    } else {
        if (args->ratio >= 1 && args->ratio <= 9) {
            lint->ratio = args->ratio;
        }
        lint->expire = nt->sec + args->expire;

        ngx_queue_remove(&lint->queue);
        ngx_queue_insert_head(&ctx->sh->queue, &lint->queue);
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return NGX_OK;
}

static ngx_int_t
ngx_http_random_limit_del_rule(ngx_http_random_limit_ctx_t *ctx, ngx_http_random_limit_args_t *args) {
    uint32_t                         hash;
    ngx_http_random_limit_node_t        *lint;

    hash = ngx_crc32_long(args->domain.data, args->domain.len);

    ngx_shmtx_lock(&ctx->shpool->mutex);
    lint = (ngx_http_random_limit_node_t *)
           ngx_str_rbtree_lookup(&ctx->sh->rbtree, &args->domain, hash);

    if (NULL != lint) {
        ngx_queue_remove(&lint->queue);
        ngx_rbtree_delete(&ctx->sh->rbtree, &lint->sn.node);
        ngx_slab_free_locked(ctx->shpool, lint);
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return NGX_OK;
}


static ngx_int_t
ngx_rbnode_2_buf(ngx_buf_t *b, ngx_uint_t *l, ngx_http_random_limit_node_t *lint) {
    size_t         len;
    size_t         len2;
    size_t         ml;

    len2 =  b->end - b->last;
    if (len2 == 0) return NGX_ERROR;

    len  =  ngx_strlen("domain=") + lint->sn.str.len;
    len  += ngx_strlen(" expire=") + 10;
    len  += ngx_strlen(" ratio=;") + 1;

    ml = len2 > len? len: len2;

    ngx_snprintf(b->pos + *l, ml, "domain=%V expire=%T ratio=%d;", 
                &lint->sn.str, lint->expire, lint->ratio);
    *l += ml;
    b->last = b->pos + *l;
    return NGX_OK;
}


static ngx_int_t
ngx_http_random_limit_rule_dump(ngx_buf_t *b, ngx_uint_t *rl, ngx_http_random_limit_ctx_t *ctx, ngx_http_random_limit_args_t *args)
{
    ngx_http_random_limit_node_t    *lint;
    uint32_t                     hash;
    ngx_time_t                  *nt;
    ngx_queue_t                 *q;
    ngx_queue_t                 *cache;
    ngx_int_t                    ret;

    nt  = ngx_timeofday();
    *rl = 0;

    if (0 < args->domain.len) {
        hash = ngx_crc32_long(args->domain.data, args->domain.len);
        ngx_shmtx_lock(&ctx->shpool->mutex);
        lint = (ngx_http_random_limit_node_t *)
               ngx_str_rbtree_lookup(&ctx->sh->rbtree, &args->domain, hash);
        if (NULL != lint) {
            if (0 != args->expire && lint->expire > nt->sec) {
                ret = ngx_rbnode_2_buf(b, rl, lint);
                ngx_shmtx_unlock(&ctx->shpool->mutex);
                return ret;
            }

            if (0 == args->expire) {
                ret = ngx_rbnode_2_buf(b, rl, lint);
                ngx_shmtx_unlock(&ctx->shpool->mutex);
                return ret;
            }
        }

        ngx_shmtx_unlock(&ctx->shpool->mutex);
        return NGX_ERROR;
    }

    ngx_shmtx_lock(&ctx->shpool->mutex);
    cache = &ctx->sh->queue;
    for(q = ngx_queue_head(cache); 
        q != ngx_queue_sentinel(cache);
        q = ngx_queue_next(q)) 
    {
        lint = ngx_queue_data(q, ngx_http_random_limit_node_t, queue);

        if (0 == args->expire || lint->expire > nt->sec) {
            if (NGX_OK != ngx_rbnode_2_buf(b, rl, lint)) {
                break;
            }
        }
    }
    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return *rl==0? NGX_ERROR: NGX_OK;
}

static void 
ngx_limit_args_init(ngx_http_random_limit_args_t *lias)
{
    lias->domain.len     = 0;
    lias->domain.data    = NULL;
    lias->expire         = 0;
    lias->ratio          = 0;
    return;
}

static ngx_int_t
ngx_http_random_limit_args_parse(ngx_str_t *arg, ngx_http_random_limit_args_t *args)
{
    u_char    *p1, *p2, *p3;

    p1 = arg->data;

    //domain=liwq.com&ratio=3[&expire=30]
    //domain=liwq.com&ratio=3
    while (NULL != p1 && *p1 != 0) {
        p2 = (u_char*)ngx_strchr(p1, '=');
        if (NULL == p2)  break;
        p3 = (u_char*)ngx_strchr(p2, '&');

        if (ngx_memcmp(p1, "domain=", 7) == 0) {
            if (ngx_memcmp(p2+1, "www.", 4) == 0) {
                args->domain.data = p2 + 1 + 4;
                args->domain.len = (p3==NULL? arg->data+arg->len-p2-2-4: p3-p2-1-4);
            } else {
                args->domain.data = p2 + 1;
                args->domain.len = (p3==NULL? arg->data+arg->len-p2-2: p3-p2-1);
            }
        }

        if (ngx_memcmp(p1, "expire=", 7) == 0) {
            args->expire = (time_t)strtoull((const char*)p2+1, NULL, 10);
        }

        if (ngx_memcmp(p1, "ratio=", 6) == 0) {
            args->ratio = (ngx_uint_t)strtoull((const char*)p2+1, NULL, 10);
        }

        if (NULL == p3) break;
        p1 = p3 + 1;
    }

    return NGX_OK;
}

/*
 *\ /xxxx/get[?domain=liwq.com]/
 *\ /xxxx/set?domain=liwq.com&ratio=3[&expire=30]/
 */
static ngx_int_t
ngx_http_random_limit_handler(ngx_http_request_t *r)
{
    ngx_http_random_limit_srv_conf_t  *lscf;
    ngx_http_random_limit_args_t       lias;
    ngx_int_t                      rc;
    ngx_int_t                      i;
    u_char                        *u;
    ngx_str_t                      type;
    ngx_uint_t                     rl;
    ngx_str_t                      limit_args;
    ngx_buf_t                     *b;
    ngx_chain_t                    out;
    ngx_log_t                     *log;


    if (!(r->method & NGX_HTTP_GET)) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    log = r->connection->log;
    lscf = ngx_http_get_module_srv_conf(r, ngx_http_random_limit_req_module);

    ngx_log_error(NGX_LOG_NOTICE, log, 0, "SAE url: \"%V?%V\"", &r->uri, &r->args);


    rc = ngx_http_discard_request_body(r);
    if (NGX_OK != rc) {
        return rc;
    }

    if (r->uri.len == 0 || r->uri.data[0] != '/') {
        return NGX_DECLINED;
    }

    u = NULL;
    for(i=r->uri.len-2; i>=0; --i) {
        u = r->uri.data + i;
        if (*u == '/') {
            break;
        }
    }


    ngx_limit_args_init(&lias);
    lias.expire     = lscf->limit_continue_sec;

    limit_args.len  = r->args.len;
    limit_args.data = NULL;

    if (limit_args.len > 0) {
        if (r->args.data[r->args.len-1] != '/') {
            limit_args.len += 1;
        }

        limit_args.data = ngx_pcalloc(r->pool, limit_args.len);
        if (NULL == limit_args.data) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_memset(limit_args.data, 0x00, limit_args.len);
        ngx_memcpy(limit_args.data, r->args.data, limit_args.len-1);

        ngx_http_random_limit_args_parse(&limit_args, &lias);
    }

    rl = 0;
    if (ngx_memcmp(u, "/set", 4) == 0) {

        if (lias.domain.len == 0) {
            return NGX_HTTP_BAD_REQUEST;
        }

        b = ngx_create_temp_buf(r->pool, 16);
        if (NULL == b) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        rc = ngx_http_random_limit_update_rule(lscf->shm_zone->data, &lias);
        ngx_memcpy(b->pos, ngx_http_random_limit_res_ok.data, ngx_http_random_limit_res_ok.len);
        rl = ngx_http_random_limit_res_ok.len;
        b->last = b->pos + rl;

        if (NGX_ERROR == rc) {
            ngx_memcpy(b->pos, ngx_http_random_limit_res_err.data, ngx_http_random_limit_res_err.len);
            rl = ngx_http_random_limit_res_err.len;
            b->last = b->pos + rl;
        }

    } else if(ngx_memcmp(u, "/get", 4) == 0) {

        b = ngx_create_temp_buf(r->pool, lscf->size);
        if (NULL == b) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        rc = ngx_http_random_limit_rule_dump(b, &rl, lscf->shm_zone->data, &lias);
        if (NGX_ERROR == rc) {
            ngx_memcpy(b->pos, ngx_http_random_limit_res_null.data, ngx_http_random_limit_res_null.len);
            rl = ngx_http_random_limit_res_null.len;
            b->last = b->pos + rl;
        }

    } else if (ngx_memcmp(u, "/del", 4) == 0){

        if (lias.domain.len == 0) {
            return NGX_HTTP_BAD_REQUEST;
        }

        b = ngx_create_temp_buf(r->pool, 16);
        if (NULL == b) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        rc = ngx_http_random_limit_del_rule(lscf->shm_zone->data, &lias);

        ngx_memcpy(b->pos, ngx_http_random_limit_res_ok.data, ngx_http_random_limit_res_ok.len);
        rl = ngx_http_random_limit_res_ok.len;
        b->last = b->pos + rl;

        if (NGX_ERROR == rc) {
            ngx_memcpy(b->pos, ngx_http_random_limit_res_err.data, ngx_http_random_limit_res_err.len);
            rl = ngx_http_random_limit_res_err.len;
            b->last = b->pos + rl;
        }

    } else {
        return NGX_HTTP_BAD_REQUEST;
    }

    ngx_str_set(&type, "text/html");

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = rl;
    r->headers_out.content_type = type;

    rc = ngx_http_send_header(r);
    if (NGX_ERROR == rc || NGX_OK < rc || r->header_only) {
        return rc;
    }

    b->memory = 1;
    b->last_buf = 1;
    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


static char *
ngx_http_random_limit_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_random_limit_handler;

    return NGX_CONF_OK;
}
