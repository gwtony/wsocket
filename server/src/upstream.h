#ifndef UPSTREAM_H
#define UPSTREAM_H

#include "frame.h"
#include "cJSON.h"


struct upstream_entry_st {
	struct sockaddr_storage addr;	// Must be the first element !!
	int index;
	int weight;
	int current_weight;
	int effective_weight;
	int connection_count;
	int estm_connect_delay;
	int port;
	int connect_timeout;
	int max_recv_timeout;
	int send_timeout;

	time_t retry_time;
	int retry_delay;
	int state;

	char *addr_str;
};

struct upstream_st {
	struct upstream_entry_st *entries;
	struct addrinfo *hint;
	size_t nr_entries;
	size_t nalloc;
	int max_connect_delay;
};

struct upstream_st *upstream_new(struct addrinfo *hint);
int upstream_delete(struct upstream_st *);

int upstream_entry_append(struct upstream_st*, cJSON *conf);

int upstream_entry_report_connect_delay(struct upstream_st*, struct upstream_entry_st*, int ms);
int upstream_entry_report_service_delay(struct upstream_st*, struct upstream_entry_st*, int ms);
int upstream_entry_report_availability(struct upstream_st*, struct upstream_entry_st*, int avail);

int upstream_entry_inc_connection(struct upstream_st*, struct upstream_entry_st*);
int upstream_entry_dec_connection(struct upstream_st*, struct upstream_entry_st*);

int upstream_entry_punish(struct upstream_st *us, struct upstream_entry_st*);

struct upstream_entry_st *upstream_get_entry(struct upstream_st*, int socket, struct internal_ctl_pipeline_open_st*);
void upstream_entries_normalize(struct upstream_st *us);

cJSON *upstream_serialize(struct upstream_st*);

#endif

