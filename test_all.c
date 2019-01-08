#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "tcpdup_container.h"
#include "tcpdup_ringbuffer.h"
#include "tcpdup_net_util.h"
#include "tcpdup_util.h"

/////////////////////////////////////////////////////////////////////
//TEST CASES FOR SLIST
/////////////////////////////////////////////////////////////////////

int slist_int_cmp(void *payload1, void *payload2)
{
	int *p1 = (int *)payload1;
	int *p2 = (int *)payload2;
	return *p1 - *p2;
}

int slist_one_func(void *payload, void *arg)
{
	int *p = (int *)payload;
	if (*p <= 4) {
		return 1;
	} else {
		return 0;
	}
}

int test_slist()
{
	int elems[8] = {7, 3, 5, 8, 6, 4, 2, 1};
	sorted_list_t *sl;
	init_slist(&sl, slist_int_cmp);
	int i = 0;
	for (i = 0; i < 8; ++i) {
		slist_insert(sl, &elems[i]);
	}
	assert(!is_slist_empty(sl));
	for (i = 0; i < 8; ++i) {
		int *pi = slist_pop_first(sl);
		assert(*pi == i + 1);
	}
	assert(is_slist_empty(sl));

	for (i = 0; i < 8; ++i) {
		slist_insert(sl, &elems[i]);
	}
	slist_readonly_iter(sl, slist_one_func, NULL);
	slist_oneshot_iter(sl, slist_one_func, NULL);
	for (i = 0; i < 4; ++i) {
		int *pi = slist_pop_first(sl);
		assert(*pi == i + 5);
	}

	destroy_slist(&sl, 0);
	return 0;
}

/////////////////////////////////////////////////////////////////////
//TEST CASES FOR fix_hashmap_t 
/////////////////////////////////////////////////////////////////////

typedef struct test_kv {
	int key;
	int value;
} test_kv_t;

int int_hash_func(void *key)
{
	int *pi = (int *)key;
	return *pi;
}

int test_equal_func(void *keyvalue, void *key)
{
	test_kv_t *pkv = (test_kv_t *)keyvalue;
	int *pi = (int *)key;
	return *pi == pkv->key;
}

int test_fix_hashmap()
{
	int elems[8] = {7, 3, 5, 8, 6, 4, 2, 1};
	fix_hashmap_t *pfm;
	init_fix_hashmap(&pfm, 128, int_hash_func, test_equal_func);

	int i = 0;
	for (i = 0; i < 8; ++i) {
		test_kv_t *pkv = malloc(sizeof(test_kv_t));
		pkv->key = elems[i];
		pkv->value = elems[i] * 11;
		insert_fix_hashmap(pfm, &elems[i], pkv);
	}

	for (i = 0; i < 8; ++i) {
		void *raw_kv = lookup_fix_hashmap(pfm, &elems[i]);
		assert(raw_kv != NULL);
		test_kv_t *pkv = (test_kv_t *)raw_kv; 
		assert(pkv->key == elems[i]);
		assert(pkv->value == elems[i] * 11);
	}

	for (i = 0; i < 5; ++i) {
		test_kv_t *pkv = (test_kv_t *)delnode_fix_hashmap(pfm, &elems[i]);
		assert(pkv != NULL);
		assert(pkv->key == elems[i]);
		assert(pkv->value == elems[i] * 11);
		free(pkv);

		pkv = (test_kv_t *)delnode_fix_hashmap(pfm, &elems[i]);
		assert(pkv == NULL);
	}
	
	destroy_fix_hashmap(&pfm, 1);
	return 0;
}

/////////////////////////////////////////////////////////////////////
//TEST CASES FOR fix_hashmap_t 
/////////////////////////////////////////////////////////////////////
int test_ringbuffer()
{
	int elems[8] = {7, 3, 5, 8, 6, 4, 2, 1};
	short se = 10;
	char ce = 12;
	int ie = 0;

	ring_buffer_t *prb = NULL;
	init_ringbuffer(&prb, 16);

	assert(is_ringbuffer_empty(prb));
	assert(!can_read_ringbuffer(prb));

	assert(0 == ringbuffer_write(prb, elems, sizeof(int) * 2));
	assert(0 == ringbuffer_write2(prb, &se, sizeof(short), &ce, sizeof(char)));
	assert(5 == get_ringbuffer_avail_write_size(prb));
	assert(11 == get_ringbuffer_avail_read_size(prb));
	assert(0 == ringbuffer_read(prb, &ie, sizeof(int)));
	assert(ie == elems[0]);
	assert(0 == ringbuffer_read(prb, &ie, sizeof(int)));
	assert(ie == elems[1]);
	assert(3 == get_ringbuffer_avail_read_size(prb));
	assert(0 == ringbuffer_write(prb, elems + 2, sizeof(int) * 3));
	assert(0 == ringbuffer_read(prb, &se, sizeof(short)));
	assert(se == 10);
	assert(0 == ringbuffer_read(prb, &ce, sizeof(char)));
	assert(ce == 12);
	assert(0 == ringbuffer_read(prb, &ie, sizeof(int)));
	assert(ie == elems[2]);
	assert(0 == ringbuffer_read(prb, &ie, sizeof(int)));
	assert(ie == elems[3]);
	assert(0 == ringbuffer_read(prb, &ie, sizeof(int)));
	assert(ie == elems[4]);
	assert(16 == get_ringbuffer_avail_write_size(prb));

	destroy_ringbuffer(&prb);
	return 0;
}

/////////////////////////////////////////////////////////////////////
//TEST CASES FOR linked_list_t 
/////////////////////////////////////////////////////////////////////

typedef struct list_elem_wrap {
	int value;
	linked_list_t list;
} list_elem_wrap_t;

int test_linked_list()
{
	linked_list_t lh;
	init_linked_list(&lh);
	list_elem_wrap_t ews[8] = {
		{1, {NULL, NULL}}, 
		{2, {NULL, NULL}}, 
		{3, {NULL, NULL}}, 
		{4, {NULL, NULL}}, 
		{5, {NULL, NULL}}, 
		{6, {NULL, NULL}}, 
		{7, {NULL, NULL}}, 
		{8, {NULL, NULL}} 
	};
	int i = 0;
	for (i = 0; i < 8; ++i) {
		init_linked_list(&ews[i].list);
	}

	for (i = 0; i < 4; ++i) {
		linked_list_add(&lh, &ews[i].list);
	}
	//now, head,4,3,2,1

	int value = 4;
	linked_list_t *pos;
	linked_list_t *iter_pos;
	list_elem_wrap_t *entry;
	linked_list_for_each(pos, &lh) {
		entry = linked_list_entry(pos, list_elem_wrap_t, list);
		assert(value == entry->value);
		value--;
	}

	for (i = 4; i < 8; ++i) {
		linked_list_add_tail(&lh, &ews[i].list);
	}
	//now, head,4,3,2,1,5,6,7,8
	linked_list_move(&ews[2].list, &lh);
	linked_list_move(&ews[1].list, &lh);
	linked_list_move(&ews[0].list, &lh);
	//now, head,1,2,3,4,5,6,7,8
	value = 1;
	linked_list_for_each(pos, &lh) {
		entry = linked_list_entry(pos, list_elem_wrap_t, list);
		assert(value == entry->value);
		value++;
	}
	for (i = 0; i < 4; ++i) {
		linked_list_del(&ews[2 * i].list);
	}
	//now, head,2,4,6,8
	value = 2;
	linked_list_for_each_safe(pos, iter_pos, &lh) {
		entry = linked_list_entry(pos, list_elem_wrap_t, list);
		assert(value == entry->value);
		value += 2;
	}
	for (i = 0; i < 4; ++i) {
		linked_list_add_tail(&lh, &ews[2 * i].list);
	}
	//now, head,2,4,6,8,1,3,5,7
	linked_list_for_each_safe(pos, iter_pos, &lh) {
		entry = linked_list_entry(pos, list_elem_wrap_t, list);
		if (entry->value % 2 == 0) {
			linked_list_del(pos);
		}
	}
	//now, head1,3,5,7
	value = 1;
	linked_list_for_each_safe(pos, iter_pos, &lh) {
		entry = linked_list_entry(pos, list_elem_wrap_t, list);
		assert(value == entry->value);
		value += 2;
	}

	return 0;
}

/////////////////////////////////////////////////////////////////////
//TEST CASES FOR fd_info_t 
/////////////////////////////////////////////////////////////////////

int test_fd_info()
{
	int elems[8] = {7, 3, 5, 8, 6, 4, 2, 1};
	int i = 0;
	for (i = 0; i < 8; ++i) {
		elems[i] += 'a';
	}
	int fd = open("/dev/null", O_RDWR);
	char ipport[6] = {'\0'};
	int connected = 1;
	unsigned int tcp_seq = 10000;

	fd_info_t *pfi = NULL;
	init_fd_info(&pfi, fd, ipport, connected, tcp_seq);
	assert(0 == fd_info_is_consecutive(pfi));

	fd_info_emplace_data(pfi, elems + 1, sizeof(int), 10005, 0);
	fd_info_write_data(pfi);
	assert(1 == pfi->stat_num_packet);
	assert(0 == pfi->stat_total_write);
	assert(!is_fd_info_has_writable_data(pfi));
	assert(0 == fd_info_is_consecutive(pfi));

	fd_info_emplace_data(pfi, elems, sizeof(int), 10001, 0);
	assert(2 == pfi->stat_num_packet);
	assert(is_fd_info_has_writable_data(pfi));
	assert(1 == fd_info_is_consecutive(pfi));
	fd_info_write_data(pfi);
	assert(0 == pfi->stat_num_packet);
	assert(8 == pfi->stat_total_write);

	fd_info_emplace_data(pfi, elems + 4, 4 * sizeof(int), 10017, 0);
	fd_info_write_data(pfi);
	assert(1 == pfi->stat_num_packet);

	fd_info_emplace_data(pfi, elems + 2, 2 * sizeof(int), 10009, 0);
	fd_info_emplace_data(pfi, elems + 8, 0, 10033, 1);
	assert(1 == fd_info_is_consecutive(pfi));
	fd_info_write_data(pfi);
	//last fin is not writed
	assert(1 == pfi->stat_num_packet);
	assert(32 == pfi->stat_total_write);

	destroy_fd_info(&pfi);
	close(fd);
	return 0;
}

/////////////////////////////////////////////////////////////////////
//TEST CASES FOR util 
/////////////////////////////////////////////////////////////////////

int test_util()
{
	long current_milli = get_current_milliseconds();
	assert(current_milli > 0);
	return 0;
}

/////////////////////////////////////////////////////////////////////
//BASE 
/////////////////////////////////////////////////////////////////////

typedef int (*unit_test)();

int all = 0;
int pass = 0;
void test_one(unit_test ut, const char *name) 
{
	++all;
	if (0 == ut()) {
		++pass;
		printf("TEST NAME:%s PASSED\n", name);
	} else {
		printf("TEST NAME:%s FAILED\n", name);
	}
}

int main(int argc, char **argv)
{
	test_one(test_slist, "sorted_list");
	test_one(test_fix_hashmap, "fix_hashmap");
	test_one(test_ringbuffer, "ring buffer");
	test_one(test_linked_list, "linked list");
	test_one(test_fd_info, "fd info");
	test_one(test_util, "util");
	printf("*****************************************\n");
	printf("TEST CASES TOTAL:%d, PASSED:%d, FAILED:%d\n", 
			all, pass, (all - pass));
	return 0;
}
