#include "tcpdup_container.h"
#include <malloc.h>
#include <stdlib.h>

void init_fix_hashmap(
		fix_hashmap_t **ppfh, int size, 
		hash_func_t hf, equal_func_t ef)
{
	*ppfh = malloc(sizeof(fix_hashmap_t));
	(*ppfh)->buckets = malloc(size * sizeof(hmap_node_t *));
	(*ppfh)->hash = hf;
	(*ppfh)->equal = ef;
	(*ppfh)->size = size;
}	

void destroy_fix_hashmap(fix_hashmap_t **ppfh)
{
	free((*ppfh)->buckets);
	free(*ppfh);
}

void* lookup_fix_hashmap(fix_hashmap_t *pfh, void* key)
{
	int hash = abs(pfh->hash(key));
	int bucket_index = hash % pfh->size;
	hmap_node_t *node = pfh->buckets[bucket_index];
	while (node != NULL) {
		if (pfh->equal(node->kv, key)) {
			return node->kv;
		}
		node = node->next;
	}
	return NULL;
}

void insert_fix_hashmap(fix_hashmap_t *pfh, void* key, void* keyvalue)
{
	int hash = abs(pfh->hash(key));
	int bucket_index = hash % pfh->size;

	hmap_node_t *new_node = malloc(sizeof(hmap_node_t));
	new_node->kv = keyvalue;
	new_node->next = NULL;

	hmap_node_t *node = pfh->buckets[bucket_index];
	if (node == NULL) {
		pfh->buckets[bucket_index] = new_node;
		return;
	}

	while (node->next != NULL) {
		node = node->next;
	}
	node->next = new_node;
	return;
}

void* delnode_fix_hashmap(fix_hashmap_t *pfh, void* key)
{
	int hash = abs(pfh->hash(key));
	int bucket_index = hash % pfh->size;
	hmap_node_t *node = pfh->buckets[bucket_index];

	if (node == NULL) {
		return NULL;
	}
	if (pfh->equal(node->kv, key)) {
		pfh->buckets[bucket_index] = node->next;
		return node->kv;
	}

	while (node->next != NULL) {
		if (pfh->equal(node->next->kv, key)) {
			hmap_node_t *res = node->next;
			node->next = node->next->next;
			return res->kv;
		}
		node = node->next;
	}
	return NULL;
}

