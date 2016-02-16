/**	\file ds_olist.c */

/** \cond 0 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
/** \endcond */

#include "ds_olist.h"

#define OLIST_P (1.0F-0.618F)

static int random_level(void) {
	int level = 1;

	while ((random() & 0xFFFF) < (OLIST_P * 0xFFFF)) {
		level += 1;
	}

	return (level < OLIST_MAXLEVEL) ? level : OLIST_MAXLEVEL;
}

static olist_node_t *olist_add_entry_unlocked(olist_t *ol, void *data)
{
	olist_node_t *update[OLIST_MAXLEVEL], *pos, *new_node;
	int i, level;

	pos = &ol->dumb;
	for (i=ol->level-1; i>=0; i--) {
		/* new data insert to front of equal elements */
		while (	(pos->level[i].next != &ol->dumb) &&
				(ol->cmp(pos->level[i].next->data, data)<0)) {
			pos = pos->level[i].next;
		}
		update[i] = pos;
	}

	level = random_level();
	if (level > ol->level) {
		for (i = ol->level; i < level; i++) {
			update[i] = &ol->dumb;
		}
		ol->level = level;
	}

	new_node = malloc(sizeof(*new_node));
	new_node->maxlevel = level;
	new_node->data = data;
	for (i = 0; i < OLIST_MAXLEVEL; i++) {
		//fprintf(stderr, "init level %d\n", i);
		if (i<level) {
			new_node->level[i].next = update[i]->level[i].next;
			new_node->level[i].prev = update[i];
			update[i]->level[i].next->level[i].prev = new_node;
			update[i]->level[i].next = new_node;
		} else {
			new_node->level[i].next = NULL;
			new_node->level[i].prev = NULL;
		}
	}

	ol->length++;

	return new_node;
}

static void olist_remove_node_unlocked(olist_t *ol, olist_node_t *x)
{
	int i;

	for (i = 0; i < x->maxlevel; i++) {
		x->level[i].next->level[i].prev = x->level[i].prev;
		x->level[i].prev->level[i].next = x->level[i].next;
	}
	free(x);
	ol->length--;
}

olist_t *olist_new(int max, olist_data_cmp_t *cmp)
{
	pthread_mutexattr_t ma;
	int j;
	olist_t *ol;

	ol = malloc(sizeof(*ol));
	if (ol == NULL) {
		return NULL;
	}

	ol->level = 1;
	ol->length = 0;
	ol->volume = max;
	ol->cmp = cmp;
	ol->dumb.data=NULL;
	ol->dumb.maxlevel = OLIST_MAXLEVEL;
	for (j=0; j<OLIST_MAXLEVEL; ++j) {
		ol->dumb.level[j].prev = &ol->dumb;
		ol->dumb.level[j].next = &ol->dumb;
	}

	pthread_mutexattr_init(&ma);
	pthread_mutexattr_settype(&ma, PTHREAD_MUTEX_RECURSIVE_NP);
	if (pthread_mutex_init(&ol->lock, &ma) != 0) {
		free(ol);
		return NULL;
	}
	pthread_mutexattr_destroy(&ma);
	return ol;
}

/*
 * Destroy an olist
 */
int olist_destroy(olist_t *ol)
{
	olist_node_t *curr, *next;

	curr = ol->dumb.level[0].next;
	while(curr!=&ol->dumb) {
		next = curr->level[0].next;
		free(curr);
		curr = next;
	}
	pthread_mutex_destroy(&ol->lock);
	free(ol);
	return 0;
}

int olist_remove_entry_by_datap(olist_t *ol, void *data)
{
	olist_node_t *pos, *ptr;
	int i, d;

	olist_lock(ol);
	pos = &ol->dumb;
	for (i = ol->level - 1; i >= 0; i--) {
		while (pos->level[i].next != &ol->dumb) {
			d = ol->cmp(pos->level[i].next->data, data);
			if (d==0) {
				pos = pos->level[i].next;
				goto search;
			}
			if (ol->cmp(pos->level[i].next->data, data)<0) {
				pos = pos->level[i].next;
			} else {
				break;
			}
		}
	}
	olist_unlock(ol);
	return -ENOENT;
search:
	ptr = pos;
	if (ptr->data == data) {
		goto do_remove;
	}

	ptr = pos->level[0].prev;
	while(ptr != &ol->dumb && ol->cmp(ptr->data, data)==0) {
		if (ptr->data == data) {
			goto do_remove;
		}
		ptr = ptr->level[0].prev;
	}

	ptr = pos->level[0].next;
	while(ptr != &ol->dumb && ol->cmp(ptr->data, data)==0) {
		if (ptr->data == data) {
			goto do_remove;
		}
		ptr = ptr->level[0].next;
	}
	olist_unlock(ol);
	return -ENOENT;
do_remove:
	olist_remove_node_unlocked(ol, ptr);
	olist_unlock(ol);
	return 0;
}

int olist_if_exists(olist_t *ol, void *data)
{
	olist_node_t *pos, *ptr;
	int i, d;

	pos = &ol->dumb;
	olist_lock(ol);
	for (i = ol->level - 1; i >= 0; i--) {
		while (pos->level[i].next != &ol->dumb) {
			d = ol->cmp(pos->level[i].next->data, data);
			if (d==0) {
				pos = pos->level[i].next;
				goto search;
			}
			if (ol->cmp(pos->level[i].next->data, data)<0) {
				pos = pos->level[i].next;
			} else {
				break;
			}
		}
	}
	olist_unlock(ol);
	return -ENOENT;
search:
	ptr = pos;
	if (ptr->data == data) {
		goto found;
	}

	ptr = pos->level[0].prev;
	while(ol->cmp(ptr->data, data)==0) {
		if (ptr->data == data) {
			goto found;
		}
		ptr = ptr->level[0].prev;
	}

	ptr = pos->level[0].next;
	while(ol->cmp(ptr->data, data)==0) {
		if (ptr->data == data) {
			goto found;
		}
		ptr = ptr->level[0].next;
	}
	olist_unlock(ol);
	return -ENOENT;
found:
	olist_unlock(ol);
	return 0;
}

int olist_add_entry(olist_t *ol, void *data)
{
	int ret;

	olist_lock(ol);

	if (ol->length >= ol->volume) {
	fprintf(stderr, "%d >= %d, OL is full.\n", (int)ol->length, (int)ol->volume);
		ret = -ENOSPC;
	} else {
		if (olist_add_entry_unlocked(ol, data)==0) {
			fprintf(stderr, "olist_add_entry_unlocked() failed.\n");
			ret = -EINVAL;
		} else {
			ret = 0;
		}
	}

	olist_unlock(ol);
	return ret;
}

void olist_lock(olist_t *ol)
{
	pthread_mutex_lock(&ol->lock);
}

void olist_unlock(olist_t *ol)
{
	pthread_mutex_unlock(&ol->lock);
}

void *olist_fetch_head(olist_t *ol)
{
	void *data;

	olist_lock(ol);
	if (ol->length<=0) {
		data=NULL;
	} else {
		data = ol->dumb.level[0].next->data;
		olist_remove_node_unlocked(ol, ol->dumb.level[0].next);
	}
	olist_unlock(ol);
	return data;
}

void *olist_peek_head(olist_t *ol)
{
	void *data;

	olist_lock(ol);
	if (ol->length<=0) {
		data=NULL;
	} else {
		data = ol->dumb.level[0].next->data;
	}
	olist_unlock(ol);
	return data;
}

#ifdef OL_TEST
#include <unistd.h>
#include <assert.h>

static olist_t *ol;
static int *dataset;
static int *dataset_o;
static int dataset_size;

static void olist_node_show(olist_node_t *node, olist_node_t *term)
{
	int i;

	if (node->data!=NULL) {
		printf("%p ", (unsigned long long)(node->data));
	} else {
		printf("*dumb ");
	}
	for (i=0; i<OLIST_MAXLEVEL-1; ++i) {
		if (node->level[i].next==term && node->level[i].prev==term) {
			putchar('O');
		} else if (node->level[i].next==term && node->level[i].prev!=term) {
			putchar('T');
		} else if (node->level[i].next!=term && node->level[i].prev==term) {
			putchar('H');
		} else if (node->maxlevel >= i) {
			putchar('|');
		} else {
			putchar('.');
		}
	}
	putchar('\n');
}

static void olist_show(olist_t *ol)
{
	olist_node_t *node;
	//int i, j;

	printf("volume=%d levels=%d nr_nodes=%d\n", ol->volume, ol->level, (int)ol->length);

	/*	Statics  */
	/*
	int count[OLIST_MAXLEVEL];
	memset(count, 0, sizeof(count));
	node = ol->dumb.level[0].next;
	while (node!=&ol->dumb) {
		//printf("Node has level=%d\n", node->maxlevel);
		count[node->maxlevel-1]++;
		node = node->level[0].next;
	};
	putchar('+');
	for (i=0; i<38; ++i) {
		putchar('-');
	}
	putchar('+');
	putchar('\n');
	for (i=0;i<OLIST_MAXLEVEL;++i) {
		//printf("%d ", count[i]);
		if (count[i]==0) {
			printf(".\n");
		} else {
			for (j=0;j<(count[i]*40.0)/(ol->length);++j) {
				putchar('*');
			}
			putchar('\n');
		}
	}
	putchar('\n');
	*/

	node = &ol->dumb;
	do {
		olist_node_show(node, &ol->dumb);
		node = node->level[0].next;
	} while (node!=&ol->dumb);

	/*
	printf("Reverse:\n");
	node = &ol->dumb;
	do {
		olist_node_show(node, &ol->dumb);
		node = node->level[0].prev;
	} while (node!=&ol->dumb);*/
}

int compare_data(void *a, void *b)
{
	int x = *(int*)a;
	int y = *(int*)b;
	return x-y;
}

static void *thr_loop(void *p) {
	int i, r, n=(int)p;

	for (i=0;i<10000;++i) {
		r = (rand()&0xff)*2+11;
		sched_yield();
//		printf("[%d]: %d, Add...", n, r);
		if (olist_add_entry(ol, &r)!=0) {
			printf("FAILED\n");
			abort();
		}
		sched_yield();
//		printf("find...");
		if (olist_if_exists(ol, &r)) {
			printf("FAILED");
			abort();
		}
		sched_yield();
//		printf("remove...");
		if (olist_remove_entry_by_datap(ol, &r)<0) {
			printf("FAILED", n, r);
			abort();
		}
		sched_yield();
//		printf("ok\n");
	}
	pthread_exit(NULL);
}

static int_cmp(const void *p1, const void *p2)
{
	return *(int*)p1 - *(int*)p2;
}

static dataset_init(int n)
{
	int i, r;

	dataset_size = n;
	dataset = malloc(sizeof(int)*dataset_size);
	dataset_o = malloc(sizeof(int)*dataset_size);
	for (i=0; i<dataset_size; i++) {
		r = (rand()&0xff)*2+2;
		dataset[i] = r;
		dataset_o[i] = r;
	}
	qsort(dataset_o, dataset_size, sizeof(int), int_cmp);
	printf("dataset inited.\n");
}

static fill_ol()
{
	int i;

	for (i = 0; i < dataset_size; i++) {
		assert(olist_add_entry(ol, dataset+i)==0);
	}
}

int main(int argc, char *argv[]) {
	int r;
	int max=1000000,count=50000, i;

//	max = atoi(argv[1]);
//	count = atoi(argv[2]);

	srand(getpid());
	printf("### Function test ###\n");
	printf("Args max:%d length:%d\n", max, count);

	dataset_init(count);

	printf("=== Init olist_ ===\n");
	ol = olist_new(max, compare_data);
	//olist_show(ol);

	printf("=== Insert olist_ ===\n");
	fill_ol();
	//olist_show(ol);

	printf("=== olist remove entry ===\n");
	for (i = 0; i < dataset_size; i++) {
		printf("remove %d\n", i);
		if (olist_remove_entry_by_datap(ol, dataset+i)) {
			olist_show(ol);
			abort();
		}
	}
	assert(ol->length==0);

	int *datap;

	printf("=== Fetch head olist ===\n");
	fill_ol();
	for (i=0;i<dataset_size;++i) {
		datap = olist_fetch_head(ol);
		if (*datap != dataset_o[i]) {
			printf("fetch %d error: Got %d while expecting %d\n", i, *datap, dataset_o[i]);
		}
	}
	assert(ol->length == 0);

	printf("=== Peek head olist ===\n");
	fill_ol();
	datap = olist_peek_head(ol);
	assert(*datap==dataset_o[0]);
	assert(ol->length == dataset_size);
	olist_add_entry(ol, datap);

	printf("=== olist find entry ===\n");
	for (i=0;i<dataset_size;++i) {
		assert(olist_if_exists(ol, olist_peek_head(ol))==0);
	}

#define	NR_THR	24
	printf("=== Loop test in %d threads ===\n", NR_THR);
	pthread_t tid[NR_THR];
	for (i=0;i<NR_THR;++i) {
		pthread_create(tid+i, NULL, thr_loop, (void*)i);
	}
	printf("%d threads created.\n", i);
	for (i=0;i<NR_THR;++i) {
		pthread_join(tid[i], NULL);
	}
	printf("%d threads joined.\n", i);

	printf("=== Remove node test 2 ===\n");
	int same[10000];
	memset(same, 0, sizeof(same));
	olist_destroy(ol);

	ol = olist_new(1000000, compare_data);
	fill_ol();
	for (i=0;i<10000;++i) {
		assert(olist_add_entry(ol, same+i)==0);
	}
	for (i=0;i<10000;++i) {
		assert(olist_remove_entry_by_datap(ol, same+i)==0);
	}

	printf("=== Delete olist ===\n");
	olist_destroy(ol);
	ol = NULL;

	return 0;
}
#endif

