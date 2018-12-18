#pragma once

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

