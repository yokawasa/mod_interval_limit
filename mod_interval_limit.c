/*
 * Copyright (C) 2009 Yoichi Kawasaki All rights reserved.
 * yk55.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "ap_config.h"
#include "apr_strings.h"
#include "apr_lib.h"
#include "apr_md5.h"
#include "apr_base64.h"
#include "commons.h"
#include "memcached_funcs.h"

#define MEMC_KEY_PREFIX_COUNTING "count"
#define MEMC_KEY_PREFIX_BLOCKING "block"
#define MEMC_VAl_BLOCKED_PERIOD  "1"
#define INIT_MEMC_ADDR  (2)
#define MAX_MEMC_ADDR  (10)
#define INIT_RULE      (2)
#define MAX_RULE       (5)

/* apache module name */
module AP_MODULE_DECLARE_DATA interval_limit_module;

typedef struct {
    int enabled;
    apr_array_header_t *memc_addrs;
    apr_array_header_t *rules;
    char *cookie_name;
} interval_limit_config;

typedef enum {
    THRESHOLD_IP= 0,
    THRESHOLD_COOKIE
} threshold_type;

typedef struct {
    char  *name;                /* the rule name                               */
    threshold_type type;        /* the threshold type                          */
    long max_count;             /* maximum hit count per interval              */
    long interval;              /* interval period (sec)                       */
    long blocking_period;       /* blocking period for limit reached ip/cookie */
    int block;                  /* block(1) or not block (0)                   */
} rule_entry;

typedef struct {
    char *name;
    int block;
} threshold_exceeded_entry;

static const char* parse_memc_addr(apr_pool_t *p, const char *val, memc_addr_ilimit_entry *memc_addr)
{
    char *next, *last;
    if ( !val||!memc_addr ) {
        return "parse_memc_addr: null arg";
    }
    next =  (char*)apr_strtok( (char*)val, ":", &last);
    if (!next||!last) {
        return "parse_memc_addr: invalid param";
    }
    memc_addr->hostname = next;
    memc_addr->port = atoi(last);
    return NULL;
}

static void dump_rules(request_rec *r, apr_array_header_t *rules)
{
    int i;
    rule_entry *rule, *rs;
    if (rules) {
        rs = (rule_entry *)rules->elts;
        for ( i =0; i <rules->nelts; i++) {
            rule =  &rs[i];
            ILLOG_DEBUG(r, MODTAG "dump rule %s type %d maxcount %d interval %d blockperiod %d block %d",
                        rule->name,
                        rule->type,
                        rule->max_count,
                        rule->interval,
                        rule->blocking_period,
                        rule->block );
        }
    }
}

static int check_rule_name_duplication(const char* name, apr_array_header_t *rules )
{
    int i,j;
    rule_entry *rule, *rs;
    if (rules) {
        rs = (rule_entry *)rules->elts;
        for ( i =0, j=0; i <rules->nelts; i++) {
            rule =  &rs[i];
            if (!strcmp(name, rule->name)) {
                if (j > 0) return 1;
                j++;
            }
        }
    }
    return 0;
}

static int nextarg(apr_pool_t *p, const char *val, char **arg)
{
    char quote;
    int pos=0;
    char *tmp= (char*)apr_pstrdup(p, val);
    while (apr_isspace(*tmp)) {
        ++tmp;
        ++pos;
    }
    quote = (*tmp == '"' || *tmp == '\'') ? *tmp++ : '\0';
    *arg = tmp;
    for (; *tmp; ++tmp && ++pos ) {
        if ((apr_isspace(*tmp) && !quote) || (*tmp == quote)) {
            break;
        }
        if (*tmp == '\\' && apr_isspace(tmp[1])) {
            ++tmp;
            ++pos;
            continue;
        }
    }
    if (!*tmp) {
        return 0;
    }
    *tmp++ = '\0';
    pos++;
    return pos;
}

static const char* parse_rule_line(apr_pool_t *p, const char *val, rule_entry *rule)
{
    char *arg1, *arg2, *arg3, *arg4, *arg5, *arg6;
    int pos;
    if (!val||!rule) {
        return "parse_rule_line: null arg";
    }
    if ((pos = nextarg(p, val, &arg1))==0) {
        return "parse_rule_line: invalid rule (arg1)";
    }
    val = val+pos;
    rule->name = (char*)apr_pstrdup(p, arg1);
    if ((pos = nextarg(p, val, &arg2))==0) {
        return "parse_rule_line: invalid rule (arg2)";
    }
    val = val+pos;
    rule->type = ( strcmp(arg2, "ip")==0 ) ? THRESHOLD_IP : THRESHOLD_COOKIE;
    if ((pos = nextarg(p, val, &arg3))==0) {
        return "parse_rule_line: invalid rule (arg3)";
    }
    val = val+pos;
    rule->max_count = atoi(arg3);
    if ((pos = nextarg(p, val, &arg4))==0) {
        return "parse_rule_line: invalid rule (arg4)";
    }
    val = val+pos;
    rule->interval = atoi(arg4);
    if ((pos = nextarg(p, val, &arg5))==0) {
        return "parse_rule_line: invalid rule (arg5)";
    }
    val = val+pos;
    rule->blocking_period = atoi(arg5);
    if ((pos = nextarg(p, val, &arg6)) < 0) {
        return "parse_rule_line: invalid rule (arg6)";
    }
    rule->block = atoi(arg6);

    return NULL;
}

static const char *set_engine(cmd_parms *parms, void *mconfig, int arg)
{
    interval_limit_config *conf = mconfig;
    if (!conf){
        return "IntervalLimitModule: Failed to retrieve configuration for mod_interval_limit";
    }
    conf->enabled = arg;
    return NULL;
}

static const char *set_cookie_name(cmd_parms *parms, void *mconfig, const char *arg)
{
    interval_limit_config *conf = mconfig;
    if (!conf){
        return "IntervalLimitModule: Failed to retrieve configuration for mod_interval_limit";
    }
    conf->cookie_name = (char*)arg;
    return NULL;
}

static const char *set_memc_addr(cmd_parms *parms, void *mconfig, const char *arg)
{
    const char *err;
    char *next, *last, *memc_addr_str;
    memc_addr_ilimit_entry *memc_addr;
    interval_limit_config *conf = mconfig;
    if (!conf){
        return "IntervalLimitModule: Failed to retrieve configuration for mod_interval_limit";
    }

    /*
    * split memc_addr string into each server addr
    */
    memc_addr_str = (char*)apr_pstrdup(parms->pool, (char*)arg);
    next =  (char*)apr_strtok( memc_addr_str, ",", &last);
    while (next) {
        apr_collapse_spaces (next, next);
        memc_addr = (memc_addr_ilimit_entry *)apr_array_push(conf->memc_addrs);
        if( (err = parse_memc_addr(parms->pool, next, memc_addr))!=NULL ) {
            return apr_psprintf(parms->pool, "IntervalLimitModule: %s", err);
        }
        next = (char*)apr_strtok(NULL, ",", &last);
    }
    return NULL;
}

static const char *set_rule(cmd_parms *parms, void *mconfig, const char *arg)
{
    char *val;
    const char *err;
    rule_entry *rule;
    interval_limit_config *conf = mconfig;
    if (!conf){
        return "IntervalLimitModule: Failed to retrieve configuration for mod_interval_limit";
    }
    /* check if the number of rules exceeds MAX_RULE */
    if (conf->rules->nelts > MAX_RULE) {
        return apr_psprintf(parms->pool, "IntervalLimitModule: Cannot define more %d rules!", MAX_RULE);
    }

    rule = (rule_entry *)apr_array_push(conf->rules);
    val = (char*)apr_pstrdup(parms->pool, (char*)arg);

    /*  parse the rule argument line */
    if ( (err = parse_rule_line(parms->pool, val, rule) )!=NULL){
        return apr_psprintf(parms->pool, "IntervalLimitModule: %s", err);
    }
    /* check if there is no duplication among the names of rules */
    if (check_rule_name_duplication(rule->name, conf->rules)) {
        return apr_psprintf(parms->pool, "parse_rule_line: rule name duplication error: %s",rule->name);
    }
    return NULL;
}

static void* interval_limit_create_dir_config(apr_pool_t *p, char *d)
{
    interval_limit_config* conf = apr_pcalloc(p, sizeof(interval_limit_config));
    conf->enabled = 0;
    conf->memc_addrs =apr_array_make(p, INIT_MEMC_ADDR, sizeof(memc_addr_ilimit_entry));
    conf->rules = apr_array_make(p, INIT_RULE, sizeof(rule_entry));
    conf->cookie_name = NULL;
    return conf;
}

static char* find_cookie(request_rec *r, const char* cookie_name)
{

    const char* cookies;
    char *cookie = NULL;

    /* todo: protect against xxxCookieNamexxx, regex? */
    /* todo: make case insensitive? */
    /* Get the cookie (code from mod_log_config). */
    if ((cookies = apr_table_get(r->headers_in, "Cookie"))) {
        char *start_cookie, *end_cookie;
        if ((start_cookie = ap_strstr_c(cookies, cookie_name))) {
            start_cookie += strlen(cookie_name) + 1;
            cookie = apr_pstrdup(r->pool, start_cookie);
            /* kill everything in cookie after ';' */
            end_cookie = strchr(cookie, ';');
            if (end_cookie) {
                *end_cookie = '\0';
            }
        }
    }
    if (!cookie) {
        return NULL;
    }
    return apr_pstrdup(r->pool,cookie);
}

char* conv2hex(request_rec *r, const unsigned char *in, const size_t inlen) {
    size_t i, j;
    char *out;
    static char hextab[] = "0123456789abcdef";
    out = apr_palloc(r->pool, (inlen * 2) + 1);
    for (i = j = 0; i < inlen; i++) {
        out[j++] = hextab[in[i] >> 4];
        out[j++] = hextab[in[i] & 15];
    }
    out[j] = '\0';
    return out;
}

static char* get_encoded_string(request_rec *r, const char* str)
{
    char* buf;
    int len;
    if (!str) {
        return NULL;
    }
#ifdef MEMC_KEY_ENCODING_BASE64
    len = apr_base64_encode_len( strlen(str) );
    buf = (char *) apr_palloc( r->pool, len + 1 );
    if(!buf){
       ILLOG_ERROR(r, MODTAG "memory alloc failed!");
       return NULL;
    }
    apr_base64_encode(buf,str,strlen(str));
    return buf;
#else
    len = APR_MD5_DIGESTSIZE;
    buf = (unsigned char*) apr_palloc( r->pool, len + 1);
    apr_md5(buf, str, strlen(str));
    return conv2hex(r,(const unsigned char *)buf,APR_MD5_DIGESTSIZE);
#endif
}

static int get_block_and_count_value(request_rec *r, const char *blockkey, const char *countkey,
                char **blockval, char **countval )
{
    int i;
    const char **keys;
    apr_table_t *results;
    const apr_array_header_t *arr;
    const apr_table_entry_t *te;
    if (!blockkey||!countkey) {
        return -1;
    }
    keys = apr_pcalloc(r->pool, (sizeof(char*))* 2);
    *(keys) = blockkey;
    *(keys+1) = countkey;
    results = apr_table_make(r->pool, 2);
    if( memcached_mget_ilimit_func(r, keys, 2, results) < 0 ) {
        return -1;
    }
    arr = apr_table_elts(results);
    te = (const apr_table_entry_t*)arr->elts;
    for (i = 0; i < arr->nelts; i++) {
        if ( !strcmp(blockkey, te[i].key) ) {
            *blockval = te[i].val;
        }
        if ( !strcmp(blockkey, te[i].key) ) {
            *countval = te[i].val;
        }
    }
    return 0;
}

static int apply_rules(request_rec *r, apr_array_header_t *rules, apr_array_header_t *threshold_exceededs ) {
    int i, ret, go_to_blockedperiod;
    uint32_t incred_count;
    rule_entry *rule, *rs;
    char *id, *cookie;
    char *blockkey, *countkey, *blockval, *countval;
    char *mgetkeys;
    threshold_exceeded_entry *threshold_exceeded;
    interval_limit_config *conf = ap_get_module_config(r->per_dir_config, &interval_limit_module);

    if (rules) {
        /* init local vars */
        blockkey = NULL; countkey = NULL;
        blockval = NULL; countval = NULL;
        /* init memcached */
        ret = memcached_init_ilimit_func(r, conf->memc_addrs);
        if (ret < 0) {
            return -1;
        }
        /* apply rules */
        rs = (rule_entry *)rules->elts;
        for ( i =0; i <rules->nelts; i++) {
            rule =  &rs[i];
            id = NULL;
            ILLOG_DEBUG(r, MODTAG "apply_rule %s type %d maxcount %d interval %d blockperiod %d block %d",
                        rule->name,
                        rule->type,
                        rule->max_count,
                        rule->interval,
                        rule->blocking_period,
                        rule->block );
            if ( rule->type == THRESHOLD_IP) {
                id = r->connection->remote_ip;
            } else if (rule->type == THRESHOLD_COOKIE) {
                if (!conf->cookie_name) {
                    ILLOG_ERROR(r, MODTAG "no cookie name specified even if you choose cookie as user identifier! "
                                  "you must specify cookie name with IntervalLimitCookieName directive");
                    continue;
                }
                cookie = find_cookie(r, conf->cookie_name);
                if (!cookie) {
                    continue;
                }
                id = cookie;

            } else {
                continue;
            }
            if (!id) {
                continue;
            }
            blockkey = (char*)apr_psprintf(r->pool, "%s-%s-%s",
                            MEMC_KEY_PREFIX_BLOCKING, rule->name, id);
            countkey = (char*)apr_psprintf(r->pool, "%s-%s-%s",
                            MEMC_KEY_PREFIX_COUNTING, rule->name, id);
            blockval = NULL; countval = NULL;
            /* key encode */
            blockkey = get_encoded_string(r, blockkey);
            countkey = get_encoded_string(r, countkey);
            ILLOG_DEBUG(r, MODTAG "apply_rule request: id(raw)=%s blockkey=%s countkey=%s", id, blockkey, countkey);
            /* get block + count value */
            ret = get_block_and_count_value(r, blockkey, countkey, &blockval, &countval);
            if ( ret < 0 ) {
                 continue;
            }
            go_to_blockedperiod = 0;
            /* check if requestin user is not in the blocking period */
            if ( blockval && !strcmp(blockval, MEMC_VAl_BLOCKED_PERIOD) ) {
                /* append to threshold_exceeded */
                threshold_exceeded = (threshold_exceeded_entry *)apr_array_push(threshold_exceededs);
                threshold_exceeded->name = rule->name;
                threshold_exceeded->block = rule->block;
                ILLOG_DEBUG(r, MODTAG "apply_rule result rule=%s state=OverLimited block=%d",
                            rule->name, rule->block );
                continue;
            }
            /* check if the count has already exceeded threshold */
            if ( countval && atoi(countval) >= rule->max_count) {
                go_to_blockedperiod = 1;
            /* check if the count hits threshold after incremented */
            } else {
                ret = memcached_incr_ilimit_func(r, countkey, rule->interval, &incred_count);
                if (ret < 0) {
                    ILLOG_ERROR(r, MODTAG "apply_rule increment count failure: rule=%s", rule->name );
                    continue;
                }
                if ( incred_count >= rule->max_count ) {
                    go_to_blockedperiod = 1;
                }
            }
            if (go_to_blockedperiod){
                /* append to threshold_exceeded */
                threshold_exceeded = (threshold_exceeded_entry *)apr_array_push(threshold_exceededs);
                threshold_exceeded->name = rule->name;
                threshold_exceeded->block = rule->block;

                /* set blockperiod flag */
                ret = memcached_set_ilimit_func(r, blockkey, (const char*)MEMC_VAl_BLOCKED_PERIOD, rule->blocking_period);
                if (ret < 0) {
                    ILLOG_ERROR(r, MODTAG "apply_rule set blockperiod flag failure: rule=%s", rule->name );
                    continue;
                }
                /* reset count slot */
                ret = memcached_del_ilimit_func(r, countkey);
                if (ret < 0) {
                    ILLOG_ERROR(r, MODTAG "apply_rule reset counter slot failure: rule=%s", rule->name );
                    continue;
                }

            }
            ILLOG_DEBUG(r, MODTAG "apply_rule result rule=%s state=NotYetOverLimit block=%d count=%d",
                        rule->name, rule->block,  incred_count );
        } // end of for
    }
    return 0;
}

static int interval_limit_access_checker(request_rec *r)
{
    interval_limit_config *conf = ap_get_module_config(r->per_dir_config, &interval_limit_module);
    int i, block_access;
    char *threshold_exceeded_rules=NULL;
    threshold_exceeded_entry *threshold_exceeded, *ol;

    if (!conf || !conf->enabled) {
        return DECLINED;
    }
    if (!conf->rules || conf->rules->nelts < 1) {
        return DECLINED;
    }
    block_access =0;
    apr_array_header_t *threshold_exceededs =apr_array_make(r->pool, 2, sizeof(threshold_exceeded_entry));
    if(  apply_rules(r, conf->rules, threshold_exceededs) !=0 ) {
        ILLOG_ERROR(r, MODTAG "apply_rules failure!");
        return DECLINED;
    }
    if (threshold_exceededs->nelts > 0) {
        ol = (threshold_exceeded_entry *)threshold_exceededs->elts;
        for ( i =0; i <threshold_exceededs->nelts; i++) {
            threshold_exceeded =  &ol[i];
            ILLOG_DEBUG(r, MODTAG "dump threshold_exceeded: name=%s block=%d",
                                        threshold_exceeded->name, threshold_exceeded->block);

            if (threshold_exceeded_rules == NULL) {
                threshold_exceeded_rules = (char*)apr_pstrdup(r->pool, threshold_exceeded->name);
            } else {
                threshold_exceeded_rules = (char*)apr_psprintf(r->pool, "%s,%s", threshold_exceeded_rules, threshold_exceeded->name);
            }
            if (threshold_exceeded->block){
                block_access = 1;
            }
        }
        if (threshold_exceeded_rules) {
            apr_table_setn(r->subprocess_env, "threshold_exceeded_rules", threshold_exceeded_rules);
            apr_table_set(r->headers_in, "threshold_exceeded_rules", threshold_exceeded_rules);
        }
    }
    if (block_access) {
        return (HTTP_SERVICE_UNAVAILABLE);
    }

    return OK;
}

static void interval_limit_register_hooks(apr_pool_t *p)
{
    ap_hook_access_checker(interval_limit_access_checker, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec interval_limit_cmds[] =
{
    AP_INIT_FLAG("IntervalLimitEngine", set_engine, NULL,
        OR_FILEINFO, "set \"On\" to enable interval_limit, \"Off\" to disable"),
    AP_INIT_TAKE1("IntervalLimitCookieName",set_cookie_name, NULL,
        OR_FILEINFO, "Name of cookie to lookup"),
    AP_INIT_TAKE1("IntervalLimitMemcachedAddrPort", set_memc_addr, NULL,
        OR_FILEINFO, "Liste of the memcached address( ip or host adresse(s) and port ':' separated). The addresses are ',' comma separated"),
    AP_INIT_RAW_ARGS("IntervalLimitRule", set_rule, NULL,
        OR_FILEINFO, "set an interval limit rule line. multiple rules can be defined."),
    {NULL}
};

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA interval_limit_module = {
    STANDARD20_MODULE_STUFF,
    interval_limit_create_dir_config,        /* create per-dir    config structures */
    NULL,                                    /* merge  per-dir    config structures */
    NULL,                                    /* create per-server config structures */
    NULL,                                    /* merge  per-server config structures */
    interval_limit_cmds,                     /* table of config file commands       */
    interval_limit_register_hooks            /* register hooks                      */
};

/*
 * vim:ts=4 et
 */
