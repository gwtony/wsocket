#ifndef DS_OLIST_H
#define DS_OLIST_H

#include <stdint.h>
#include <pthread.h>

typedef int olist_data_cmp_t(void *, void *);

#define OLIST_MAXLEVEL 8L

typedef struct olist_node_st {
	void *data;
	int maxlevel;
	struct {
		struct olist_node_st *prev,*next;
	} level[OLIST_MAXLEVEL];
} olist_node_t;

typedef struct olist_st {
	struct olist_node_st dumb;
	unsigned long length;
	int level;
	int volume;

	olist_data_cmp_t *cmp;
	pthread_mutex_t lock;
} olist_t;

olist_t *olist_new(int volume, olist_data_cmp_t *cmp);
int olist_destroy(olist_t *ol);

int olist_add_entry(olist_t *ol, void *data);
int olist_remove_entry_by_datap(olist_t *ol, void *data);
int olist_if_exists(olist_t *ol, void *data);

void olist_lock(olist_t *ol);
void olist_unlock(olist_t *ol);

void *olist_fetch_head(olist_t *ol);
void *olist_peek_head(olist_t *ol);

#define	olist_foreach(ol, datap, statement) do {	\
	olist_node_t *_olist_iter_;						\
	olist_lock(ol);									\
	_olist_iter_ = &ol->dumb;						\
	while (_olist_iter_->level[0].next!=&ol->dumb) {\
		datap = _olist_iter_->level[0].next->data;	\
		do { statement; }while(0);					\
		_olist_iter_ = _olist_iter_->level[0].next;	\
	}												\
	olist_unlock(ol);								\
} while(0)

#endif

