#pragma once

///////////////////////////////////////////////////////////////////////
//for fix_hashmap_t
///////////////////////////////////////////////////////////////////////

typedef int (*hash_func_t)(void *key);
typedef int (*equal_func_t)(void *keyvalue, void *key);

typedef struct hmap_node {
    void *kv;
    struct hmap_node *next;
} hmap_node_t;

typedef struct fix_hash_map {
    hmap_node_t **buckets;
    hash_func_t hash;
    equal_func_t equal;
    int size;
} fix_hashmap_t;

void init_fix_hashmap(
        fix_hashmap_t **ppfh, int size, 
        hash_func_t hf, equal_func_t ef);

void destroy_fix_hashmap(fix_hashmap_t **ppfh);

// return node->kv
void* lookup_fix_hashmap(fix_hashmap_t *pfh, void* key);

void insert_fix_hashmap(fix_hashmap_t *pfh, void* key, void* keyvalue);

// return node->kv
void* delnode_fix_hashmap(fix_hashmap_t *pfh, void* key);

///////////////////////////////////////////////////////////////////////
//for sorted_list_t
///////////////////////////////////////////////////////////////////////

typedef int (*slist_cmp)(void *payload1, void *payload2);

typedef struct slist_node {
    void *payload;
    struct slist_node *next;
} slist_node_t;

typedef struct sorted_list {
    slist_node_t *head;
    slist_cmp cmp;
} sorted_list_t;

void init_slist(sorted_list_t **ppsl, slist_cmp cmp);
void destroy_slist(sorted_list_t **ppsl, int free_payload);

//return slist_node_t* {payload}
void* slist_insert(sorted_list_t *sl, void *payload);

void* slist_pop_first(sorted_list_t *sl); 
