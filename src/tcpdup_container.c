#include "tcpdup_container.h"
#include <malloc.h>
#include <stdlib.h>
#include <string.h>

void init_fix_hashmap(
		fix_hashmap_t **ppfh, int size, 
		hash_func_t hf, equal_func_t ef)
{
	*ppfh = malloc(sizeof(fix_hashmap_t));
	(*ppfh)->buckets = malloc(size * sizeof(hmap_node_t *));
	memset((*ppfh)->buckets, 0, size * sizeof(hmap_node_t *));
	(*ppfh)->hash = hf;
	(*ppfh)->equal = ef;
	(*ppfh)->size = size;
}	

void destroy_fix_hashmap(fix_hashmap_t **ppfh, int free_payload)
{
	int size = (*ppfh)->size;
	int i = 0;
	for (; i < size; ++i) {
		hmap_node_t *node = (*ppfh)->buckets[i];
		while (node != NULL) {
			hmap_node_t *to_free = node;
			if (free_payload) {
				free(to_free->kv);
			}
			free(to_free);
			node = node->next;
		}
	}
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

void init_slist(sorted_list_t **ppsl, slist_cmp cmp)
{
	*ppsl = malloc(sizeof(sorted_list_t));
	(*ppsl)->head = NULL;
	(*ppsl)->cmp = cmp;
}

void destroy_slist(sorted_list_t **ppsl, int free_payload)
{
	slist_node_t *node = (*ppsl)->head;
	while (node != NULL) {
		slist_node_t *to_del = node;
		node = node->next;
		if (free_payload) {
			free(to_del->payload);
		}
		free(to_del);
	}
	free(*ppsl);
}

void* slist_insert(sorted_list_t *sl, void *payload) 
{
	slist_node_t *node = malloc(sizeof(slist_node_t));
	node->payload = payload;
	node->next = NULL;
	if (sl->head == NULL || sl->cmp(sl->head->payload, payload) > 0) {
		node->next = sl->head;
		sl->head = node;
	} else {
		slist_node_t *prev = sl->head;
		slist_node_t *now = prev->next;
		while (now != NULL && sl->cmp(now->payload, payload) < 0) {
			prev = prev->next;
			now = now->next;
		}
		node->next = prev->next;
		prev->next = node;
	}
	return node;
}

void* slist_pop_first(sorted_list_t *sl) 
{
	if (sl->head == NULL) {
		return NULL;
	}
	slist_node_t *node = sl->head;
	sl->head = sl->head->next;
	void* payload = node->payload;
	free(node);
	return payload;
}

void slist_oneshot_iter(sorted_list_t *sl, slist_iter_func si_func, void *arg)
{
	slist_node_t *node = sl->head;
	while (node != NULL) {
		if (si_func(node->payload, arg)) {
			slist_node_t *to_free = node;
			node = node->next;
			free(to_free);
		} else {
			break;
		}
	}
	sl->head = node;
}

