/** \cond 0 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>

#include "cJSON.h"
#include "util_atomic.h"
/** \endcond */

#include "ds_olist.h"
#include "upstream.h"
#include "util_log.h"
#include "util_time.h"

#define DEFAULT_RETRY_DELAY 5000
#define UPSTREAM_DEFAULT_TIMEOUT 5000
#define UPSTREAM_DEFAULT_MAX_TIMEOUT 30000

enum {
	UPSTREAM_OK = 0,
	UPSTREAM_DOWN = 1,
	UPSTREAM_REBORN = 2,
};

struct upstream_internal_st {
	struct upstream_st us;	// Must be the first element !!
	pthread_mutex_t lock;
};

struct upstream_st *upstream_new(struct addrinfo *hint)
{
	struct upstream_internal_st *usol;

	usol = malloc(sizeof(struct upstream_internal_st));
	if(usol == NULL) {
		return NULL;
	}

	usol->us.nalloc = 32;
	usol->us.entries = malloc(32 * sizeof(struct upstream_entry_st));
	if(usol->us.entries == NULL) {
		free(usol);
		return NULL;
	}
	usol->us.nr_entries = 0;

	pthread_mutex_init(&usol->lock, NULL);

	usol->us.hint = (struct addrinfo *)hint;
	usol->us.max_connect_delay = 600;

	return (struct upstream_st *)usol;
}

int upstream_delete(struct upstream_st *us)
{
	struct upstream_internal_st *usol = (struct upstream_internal_st *)us;

	if(usol == NULL) {
		return 0;
	}

	if(usol->us.entries != NULL) {
		free(usol->us.entries);
	}

	pthread_mutex_destroy(&usol->lock);
	free(usol);

	return 0;
}

int upstream_entry_append(struct upstream_st *us, cJSON *conf)
{
	int ret;
	struct addrinfo *ai_list, *aip;
	struct upstream_entry_st *entries;

	cJSON *node = cJSON_GetObjectItem(conf, "Address");
	cJSON *port = cJSON_GetObjectItem(conf, "Port");
	cJSON *weight = cJSON_GetObjectItem(conf, "Weight");
	cJSON *retry_delay = cJSON_GetObjectItem(conf, "FailRetryDelay_ms");
	cJSON *connect_timeout = cJSON_GetObjectItem(conf, "ConnectTimeout_ms");
	cJSON *max_recv_timeout = cJSON_GetObjectItem(conf, "MaxRecvTimeout_ms");
	cJSON *send_timeout = cJSON_GetObjectItem(conf, "SendTimeout_ms");

	ret = getaddrinfo(node->valuestring, port->valuestring, us->hint, &ai_list);
	if(ret !=0) {
		mylog(L_ERR, "Getaddrinfo error: %s", gai_strerror(ret));
		return -EINVAL;
	}

	for(aip=ai_list; aip!=NULL; aip=aip->ai_next) {
		if(aip->ai_addr == NULL) {
			continue;
		}

		if(us->nr_entries == us->nalloc) {
			entries = realloc(us->entries, 2 * us->nalloc * sizeof(struct upstream_entry_st));
			if(entries == NULL) {
				return -ENOMEM;
			}

			us->entries = entries;
			us->nalloc *= 2;
		}

		memcpy(&us->entries[us->nr_entries].addr, aip->ai_addr, aip->ai_addrlen);
		us->entries[us->nr_entries].index = us->nr_entries;
		us->entries[us->nr_entries].weight = weight->valueint;
		us->entries[us->nr_entries].effective_weight = weight->valueint;
		us->entries[us->nr_entries].current_weight = 0;
		us->entries[us->nr_entries].connection_count = 0;
		us->entries[us->nr_entries].estm_connect_delay = 0;
		us->entries[us->nr_entries].retry_time = 0;
		us->entries[us->nr_entries].retry_delay = (retry_delay && retry_delay->valueint > 0) ? retry_delay->valueint : DEFAULT_RETRY_DELAY;
		us->entries[us->nr_entries].connect_timeout = (connect_timeout && connect_timeout->valueint > 0) ? connect_timeout->valueint : UPSTREAM_DEFAULT_TIMEOUT;
		us->entries[us->nr_entries].max_recv_timeout = (max_recv_timeout && max_recv_timeout->valueint > 0) ? max_recv_timeout->valueint : UPSTREAM_DEFAULT_MAX_TIMEOUT;
		us->entries[us->nr_entries].send_timeout = (send_timeout && send_timeout->valueint > 0) ? send_timeout->valueint : UPSTREAM_DEFAULT_TIMEOUT;

		us->entries[us->nr_entries].port = atoi(port->valuestring);
		us->entries[us->nr_entries].addr_str = node->valuestring;
		us->entries[us->nr_entries].state = UPSTREAM_OK;


		mylog(L_DEBUG, "Init upstream port %s, entry %p", port->valuestring, us->entries[us->nr_entries]);

		us->nr_entries++;
	}

	freeaddrinfo(ai_list);
	return 0;
}

int upstream_entry_report_connect_delay(struct upstream_st *us, struct upstream_entry_st *entry, int ms)
{
	entry->estm_connect_delay = (entry->estm_connect_delay + ms)/2;
	return 0;
}

int upstream_entry_report_service_delay(struct upstream_st *us, struct upstream_entry_st *entry, int ms)
{
	// TODO
	return 0;
}

int upstream_entry_report_availability(struct upstream_st *us, struct upstream_entry_st *entry, int up)
{
	struct upstream_internal_st *usol = (struct upstream_internal_st *)us;

	pthread_mutex_lock(&usol->lock);

	if (!up) {
		entry->retry_time = entry->retry_delay + systimestamp_ms();
		entry->state = UPSTREAM_DOWN;
	} else {
		entry->retry_time = 0;
		entry->state = UPSTREAM_OK;
	}

	if (entry->effective_weight < 0) {
		entry->effective_weight = 0;
	} 

	pthread_mutex_unlock(&usol->lock);

	return 0;
}

int upstream_entry_inc_connection(struct upstream_st *us, struct upstream_entry_st *entry)
{
	atomic_increase(&entry->connection_count);

	return 0;
}

int upstream_entry_dec_connection(struct upstream_st *us, struct upstream_entry_st *entry)
{
	atomic_decrease(&entry->connection_count);

	return 0;
}

struct upstream_entry_st *upstream_get_entry(struct upstream_st *us, int socket, struct internal_ctl_pipeline_open_st *p)
{
	time_t now;
	int i, total = 0;
	struct upstream_entry_st *peer, *best = NULL;
	struct upstream_internal_st *usol = (void *)us;

	now = systimestamp_ms();

	pthread_mutex_lock(&usol->lock);

	for (i = 0; i < us->nr_entries; i++) {
		peer = &us->entries[i];
		if (peer->retry_time > now || peer->state == UPSTREAM_REBORN) {
			mylog(L_INFO, "Continue happend state is %d, retry_time is %lu", peer->state, peer->retry_time);
			continue;
		}
		peer->retry_time = 0;

		peer->current_weight += peer->effective_weight;
		total += peer->effective_weight;

		if (peer->effective_weight < peer->weight) {
			peer->effective_weight++;
		}   

		if (best == NULL || peer->current_weight > best->current_weight) {
			best = peer;
		}   
	}   

	if (best == NULL) {
		best = &us->entries[0];
		mylog(L_INFO, "No best upstream, choose the first");
		pthread_mutex_unlock(&usol->lock);
			
		return best;
	}

	if (best->state == UPSTREAM_DOWN) {
		best->state = UPSTREAM_REBORN;
		mylog(L_INFO, "Set upstream %s state to reborn", best->addr_str);
	}

	best->current_weight -= total;
	pthread_mutex_unlock(&usol->lock);

	mylog(L_DEBUG, "Get entry upstream %s, port is %d", best->addr_str, best->port);

	return best;
}

static cJSON *upstream_entry_serialize(struct upstream_entry_st *this)
{
	cJSON *result;
	char ip_str[16];

	inet_ntop(AF_INET, &((struct sockaddr_in*)(&this->addr))->sin_addr, ip_str, 16);

	result = cJSON_CreateObject();
	cJSON_AddNumberToObject(result, "index", this->index);
	cJSON_AddNumberToObject(result, "weight", this->weight);
	cJSON_AddStringToObject(result, "address", ip_str);
	cJSON_AddNumberToObject(result, "port", this->port);
	cJSON_AddNumberToObject(result, "retry_delay", this->retry_delay);
	cJSON_AddNumberToObject(result, "connection_count", this->connection_count);
	cJSON_AddNumberToObject(result, "estm_connect_delay", this->estm_connect_delay);

	return result;
}

cJSON *upstream_serialize(struct upstream_st *us)
{
	int i;
	cJSON *result, *arr;
	struct upstream_entry_st *curr;
	struct upstream_internal_st *this = (void*)us;

	result = cJSON_CreateObject();

	pthread_mutex_lock(&this->lock);

	cJSON_AddNumberToObject(result, "max_connect_delay", this->us.max_connect_delay);
	cJSON_AddNumberToObject(result, "nr_entries", this->us.nr_entries);

	arr = cJSON_CreateArray();
	for (i = 0; i < us->nr_entries; i++) {
		curr = &us->entries[i];
		cJSON_AddItemToArray(arr, upstream_entry_serialize(curr));
	}
	
	cJSON_AddItemToObject(result, "entries", arr);

	pthread_mutex_unlock(&this->lock);
	
	return result;
}


#if 0
int main(int argc, char *argv[]) {
	printf("=== Init Upstream ===\n");
	struct addrinfo hint;
	hint.ai_flags = AI_CANONNAME;
	hint.ai_family = AF_INET;
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_protocol = IPPROTO_TCP;
	hint.ai_addrlen = 0;
	hint.ai_canonname = NULL;
	hint.ai_addr = NULL;
	hint.ai_next = NULL;
	struct upstream_st *us = upstream_new(&hint);
	printf("Init upstream %s\n", (us==NULL ? "FAILURE" : "SUCCESS"));

	int ret;
	cJSON *conf,*node,*port,*weight;
	printf("=== Append Upstream Entry ===\n");
	conf = cJSON_CreateObject();
	cJSON_AddStringToObject(conf, "Address", "10.75.3.13");
	cJSON_AddStringToObject(conf, "Port", "6051");
	cJSON_AddNumberToObject(conf, "Weight", 3);

	ret = upstream_entry_append(us, conf);
	printf("%s\n", (ret!=0 ? "FAILURE" : "SUCCESS"));
	cJSON_Delete(conf);

	conf = cJSON_CreateObject();
	cJSON_AddStringToObject(conf, "Address", "www.weibo.com");
	cJSON_AddStringToObject(conf, "Port", "6052");
	cJSON_AddNumberToObject(conf, "Weight", 4);

	ret = upstream_entry_append(us, conf);
	printf("%s\n", (ret!=0 ? "FAILURE" : "SUCCESS"));
	cJSON_Delete(conf);

	conf = cJSON_CreateObject();
	cJSON_AddStringToObject(conf, "Address", "photo.weibo.com");
	cJSON_AddStringToObject(conf, "Port", "6053");
	cJSON_AddNumberToObject(conf, "Weight", 5);

	ret = upstream_entry_append(us, conf);
	printf("%s\n", (ret!=0 ? "FAILURE" : "SUCCESS"));
	cJSON_Delete(conf);

	printf("=== Get Upstream Entry ===\n");
	struct sockaddr *addr = upstream_get_entry(us, 0, NULL);
	if(addr == NULL) {
		printf("FAILURE\n");
	} else {
		struct sockaddr_in *sin = (struct sockaddr_in *)addr;
		printf("host:%s port:%d\n", inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));

		printf("=== Report Upstream delay ===\n");
		ret = upstream_entry_report_connect_delay(us, addr, 500);
		printf("%s\n", (ret!=0 ? "FAILURE" : "SUCCESS"));

		printf("=== Set Upstream availability ===\n");
		ret = upstream_entry_set_availability(us, addr, 1);
		printf("%s\n", (ret!=0 ? "FAILURE" : "SUCCESS"));

		printf("=== Increment Upstream connections ===\n");
		ret = upstream_entry_inc_connection(us, addr);
		printf("%s\n", (ret!=0 ? "FAILURE" : "SUCCESS"));

		printf("=== Decrement Upstream connections ===\n");
		ret = upstream_entry_dec_connection(us, addr);
		printf("%s\n", (ret!=0 ? "FAILURE" : "SUCCESS"));
	}

	printf("=== Get Upstream Entry ===\n");
	addr = upstream_get_entry(us, 0, NULL);
	if(addr == NULL) {
		printf("FAILURE\n");
	} else {
		struct sockaddr_in *sin = (struct sockaddr_in *)addr;
		printf("host:%s port:%d\n", inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));
	}

	printf("=== Delete Upstream ===\n");
	ret = upstream_delete(us);
	printf("%s\n", (ret!=0 ? "FAILURE" : "SUCCESS"));
	us = NULL;
}
#endif
