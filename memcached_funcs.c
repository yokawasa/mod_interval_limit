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
#include "http_log.h"
#include <libmemcached/memcached.h>
#include "commons.h"
#include "memcached_funcs.h"

static memcached_st *memc = NULL;
static memcached_server_st *servers = NULL;

static apr_status_t
_cleanup_register_func(void *dummy)
{
    if(servers){
        memcached_server_list_free(servers);
        servers = NULL;
    }
    if(memc){
        memcached_free(memc);
        memc = NULL;
    }
    return APR_SUCCESS;
}

int _init_func(request_rec *r, apr_array_header_t *memc_addrs)
{
    int i;
    memc_addr_entry *memc_addr, *ma;
    memcached_return rc;
    memc = memcached_create(NULL);
    int binary_available = 0;
    if (!memc) {
        ILLOG_ERROR( r, MODTAG "memcached_create failure!");
        return -1;
    }
    if(memc_addrs) {
        ma = (memc_addr_entry *)memc_addrs->elts;
        if (memc_addrs->nelts < 1) {
            ILLOG_ERROR( r, MODTAG "no memcached server to push!");
            return -1;
        }
        binary_available = 1;
        for ( i =0; i <memc_addrs->nelts; i++) {
            memc_addr =  &ma[i];
            if (i==0) {
                servers = memcached_server_list_append_with_weight(NULL, memc_addr->hostname, memc_addr->port, 0, &rc);
            } else {
                servers = memcached_server_list_append_with_weight(servers, memc_addr->hostname, memc_addr->port, 0, &rc);
            }
            if (rc != MEMCACHED_SUCCESS) {
                ILLOG_ERROR(r, MODTAG "memcached_server_list_append_with_weight failure: server=%s:%d rc=%d",
                        memc_addr->hostname, memc_addr->port, rc);
                return -1;
            }
        }
        rc = memcached_server_push(memc, servers);
        if (rc != MEMCACHED_SUCCESS) {
            ILLOG_ERROR(r, MODTAG "memcached_server_push failure: rc=%d", rc);
            return -1;
        }

       // check memcached version for binary protocol
        memcached_version(memc);
        for ( i =0; i <memc->number_of_hosts; i++) {
            if (memc->hosts[i].major_version >= 1 && memc->hosts[i].minor_version > 2) {
                ILLOG_DEBUG(r, MODTAG "memcached version OK: server=%s:%d major=%d minor=%d",
                    memc->hosts[i].hostname,memc->hosts[i].port,
                    memc->hosts[i].major_version, memc->hosts[i].minor_version);
            } else {
                if (memc->hosts[i].major_version != 0 && memc->hosts[i].minor_version != 0) {
                    ILLOG_DEBUG(r,
                        MODTAG "memcached version need to be higher than 1.2 " "(binary protocol NOT available): server=%s:%d major=%d minor=%d",
                        memc->hosts[i].hostname,memc->hosts[i].port,
                        memc->hosts[i].major_version, memc->hosts[i].minor_version);
                    binary_available=0;
                }
            }
        }
        if(binary_available) {
            memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_NO_BLOCK, 0);
            rc = memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_BINARY_PROTOCOL, 1);
            if (rc != MEMCACHED_SUCCESS) {
                ILLOG_ERROR(r, MODTAG "memcached_behavior_set failed to enable binary protocol: rc=%d", rc);
                return -1;
            }
        }
    }
    apr_pool_cleanup_register(r->pool, NULL, _cleanup_register_func, _cleanup_register_func);
    return 0;
}

int memcached_init_func(request_rec *r, apr_array_header_t *memc_addrs)
{
    if (!memc) {
        return _init_func(r, memc_addrs);
    }
    return 0;
}

int memcached_get_func(request_rec *r, const char *key, char **val)
{
    memcached_return rc;
    char *received;
    size_t length;
    uint32_t flags;
    if (!r || !key) {
        return -1;
    }
    received = memcached_get(memc, key, strlen(key),
                             &length, &flags, &rc);
    if (rc != MEMCACHED_SUCCESS && rc != MEMCACHED_NOTFOUND ) {
        ILLOG_ERROR(r, MODTAG "memcached_get failure: key=%s rc=%d msg=%s",
                                    key, rc, memcached_strerror(memc, rc) );
        return -1;
    }
    if (received != NULL) {
        *val = (char*)apr_pstrdup(r->pool, received);
    }
    return 0;
}

char* _carrtostr(request_rec *r, const char **carr, size_t num ) {
    int i;
    char* str=NULL;
    for(i=0; i<num; i++) {
        if (str == NULL) {
            str = (char*)apr_pstrdup(r->pool, *(carr + i));
        } else {
            //str = (char*)apr_pstrcat(r->pool, str, *(carr + i),NULL);
            str = (char*)apr_psprintf(r->pool, "%s,%s", str, *(carr + i));
        }
    }
    return str;
}

int memcached_mget_func(request_rec *r, const char **keys, size_t keynum, apr_table_t *results)
{
    memcached_return rc;
    int i;
    size_t *key_len;
    char *ret_key;
    size_t ret_key_len, ret_val_len;
    char *ret_val;
    uint32_t flags;

    if ( !r || !keys || keynum<1 ){
        return -1;
    }
    // alloc for key_len
   key_len = apr_pcalloc(r->pool, (sizeof(size_t))* keynum);
    for (i=0; i< keynum; i++) {
        *(key_len + i ) = strlen( *(keys + i) );
    }

    rc = memcached_mget(memc, keys, key_len, keynum);
    if (rc != MEMCACHED_SUCCESS) {
        ILLOG_ERROR(r, MODTAG "memcached_mget failure: keys=%s rc=%d msg=%s",
                                    _carrtostr(r,keys, keynum), rc, memcached_strerror(memc, rc) );
        return -1;
    }
    if (!results) {
         results = apr_table_make(r->pool, keynum);
    }
    // alloc for ret_key
    ret_key = apr_palloc(r->pool, MEMCACHED_MAX_KEY);
    while( (ret_val = memcached_fetch(memc, ret_key, &ret_key_len, &ret_val_len, &flags, &rc) )) {
        if (rc != MEMCACHED_SUCCESS) {
            ILLOG_ERROR(r, MODTAG "memcached_fetch failure: keys=%s rc=%d msg=%s",
                                         _carrtostr(r,keys, keynum), rc, memcached_strerror(memc, rc) );
            return -1;
        }
        apr_table_set(results, ret_key, ret_val);
    }
    return 0;
}

int memcached_set_func(request_rec *r, const char *key, const char *val, time_t expire)
{
    memcached_return rc;
    if (!r || !key || !val) {
        return -1;
    }
    rc = memcached_set(memc,
                       key, strlen(key),
                       val, strlen(val),
                       expire, (uint32_t)0);

    if (rc != MEMCACHED_SUCCESS && rc != MEMCACHED_BUFFERED){
        ILLOG_ERROR(r, MODTAG "memcached_set failure: key=%s rc=%d msg=%s",
                                    key, rc, memcached_strerror(memc, rc) );
        return -1;
    }
    return 0;
}

int memcached_del_func(request_rec *r, char *key)
{
    memcached_return rc;
    if (!r || !key) {
        return -1;
    }
    rc = memcached_delete(memc, key, strlen(key), (time_t)60);
    if (rc != MEMCACHED_SUCCESS && rc != MEMCACHED_BUFFERED) {
        ILLOG_ERROR(r, MODTAG "memcached_delete failure: key=%s rc=%d msg=%s",
                                    key, rc, memcached_strerror(memc, rc) );
        return -1;
    }
    return 0;
}

int memcached_incr_func(request_rec *r, char *key, time_t expire, uint32_t *new_num )
{
// this increment interface is available only with binary protocol
// as far as i've checked, unitl the version 0.34 it is the case.
    memcached_return rc;
    uint64_t _new_num;
    if (!r || !key) {
        return -1;
    }
    if ( memcached_behavior_get(memc, MEMCACHED_BEHAVIOR_BINARY_PROTOCOL) !=1 ) {
        ILLOG_ERROR(r,
            MODTAG "binary protocol disabled, thus cannot exec memcached_increment_with_initial: key=%s", key);
        return -1;
    }
    rc= memcached_increment_with_initial(memc, key, strlen(key),
                                         1, 1, expire, &_new_num);
    if (rc != MEMCACHED_SUCCESS) {
        ILLOG_ERROR(r, MODTAG "memcached_increment_with_initial failure: key=%s rc=%d msg=%s",
                                key, rc, memcached_strerror(memc, rc) );
        return -1;
    }
    *new_num = (uint32_t)_new_num;
    return 0;
}

int memcached_decr_func(request_rec *r, char *key, time_t expire, uint32_t* new_num)
{
// this decrement interface is available only with binary protocol
// as far as i've checked, unitl the version 0.34 it is the case.
    memcached_return rc;
    uint64_t _new_num;
    if (!r || !key) {
        return -1;
    }
    if ( memcached_behavior_get(memc, MEMCACHED_BEHAVIOR_BINARY_PROTOCOL) !=1 ) {
        ILLOG_ERROR(r,
            MODTAG "binary protocol disabled, thus cannot exec memcached_decrement_with_initial: key=%s", key);
        return -1;
    }
    rc= memcached_decrement_with_initial(memc, key, strlen(key),
                                         1, 1, expire, &_new_num);
    if (rc != MEMCACHED_SUCCESS) {
        ILLOG_ERROR(r, MODTAG "memcached_increment_with_initial failure: key=%s rc=%d msg=%s",
                                    key, rc, memcached_strerror(memc, rc) );
        return -1;
    }
    *new_num = (uint32_t)_new_num;
    return 0;
}
