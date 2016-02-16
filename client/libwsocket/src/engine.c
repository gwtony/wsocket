/** \cond 0 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <poll.h>
#include <pthread.h>
#include <errno.h>
/** \endcond */

#include "util_time.h"
#include "ds_hasht.h"
#include "socket_end.h"

#define	POLLMAX	2048
#define	BUFSIZE	4096

extern void wsocket_init(void)__attribute__((constructor));
extern void wsocket_delete(void)__attribute__((destructor));

static int socket_end_1 = -1;
static int socket_end_count = 0;
static int socket_end_nextid = -1;
static struct socket_end_st *socket_end_list[POLLMAX];

static hasht_t *socket_end_url_index = NULL;
static hasht_t *socket_end_fd_index = NULL;
static pthread_mutex_t socket_end_index_mut = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t socket_end_count_cond = PTHREAD_COND_INITIALIZER;

static pthread_t tid_poller;
static flist_node_t *atexit_list=NULL;

static void do_nothing(int s) {}

int my_atexit(void (*func)(void)) 
{
	flist_node_t *node;
	node = (flist_node_t *) malloc(sizeof(flist_node_t));
	if(node == NULL) {
		return -1;
	}
	node->func = func;
	node->next = atexit_list;
	atexit_list = node;
	return 0;
}

static int wsocket_append_socket_end(struct socket_end_st **sep, struct wsocket_context_st *c)
{
	int end;
	hashkey_t hashkey;
	struct socket_end_st *se;

	end = socket_end_nextid;
	do {
		socket_end_nextid++;
		if(socket_end_nextid >= POLLMAX) {
			socket_end_nextid = 0;
		}
		if(socket_end_nextid == end) {
			mylog(L_ERR, "Too many socket_end,limit: %d.\n", POLLMAX);
			return -EINVAL;
		}
	} while(socket_end_list[socket_end_nextid] != NULL);

	se = socket_end_new();
	if(se == NULL) {
		mylog(L_ERR, "socket_end_new() error:%s.\n", strerror(errno));
		return -EINVAL;
	}

	se->id = socket_end_nextid;
	se->prev_id = -1;
	se->next_id = socket_end_1;
	memcpy(se->hashkey, c->hashkey, HASHKEYSIZE);
	if(socket_end_1 != -1) {
		socket_end_list[socket_end_1]->prev_id = se->id;
	}

	hashkey.offset = 0;
	hashkey.len = sizeof(int);
	hasht_add_item(socket_end_fd_index, &hashkey, se);

	hashkey.offset = sizeof(int);
	hashkey.len = HASHKEYSIZE;
	hasht_add_item(socket_end_url_index, &hashkey, se);

	socket_end_1 = se->id;
	socket_end_list[se->id] = se;
	socket_end_count++;
	pthread_cond_broadcast(&socket_end_count_cond);
	*sep = se;

	mylog(L_DEBUG, "socket_end_list[%d] append success.\n", se->id);
	return 0;
}


static int wsocket_remove_socket_end(struct socket_end_st *se)
{
	hashkey_t hashkey;

	if(socket_end_list[se->id] == NULL) {
		return -EINVAL;
	}

	hashkey.offset = 0;
	hashkey.len = sizeof(int);
	hasht_delete_item(socket_end_fd_index, &hashkey, se);

	hashkey.offset = sizeof(int);
	hashkey.len = HASHKEYSIZE;
	hasht_delete_item(socket_end_url_index, &hashkey, se);

	if(se->prev_id == -1 && se->next_id == -1) {
		socket_end_1 = -1;
	} else if(se->prev_id == -1) {
		socket_end_list[se->next_id]->prev_id = -1;
		socket_end_1 = se->next_id;
	} else if(se->next_id == -1) {
		socket_end_list[se->prev_id]->next_id = -1;
	} else {
		socket_end_list[se->prev_id]->next_id = se->next_id;
		socket_end_list[se->next_id]->prev_id = se->prev_id;
	}

	socket_end_list[se->id] = NULL;
	socket_end_count--;
	mylog(L_DEBUG, "socket_end_list[%d] remove success.\n", se->id);

	socket_end_delete(se);
	return 0;
}


void *thr_poll(void *p)
{
	int i,ret,next,nfds,timeout=10;
	hashkey_t hashkey;
	struct pollfd fds[POLLMAX];
	struct socket_end_st sed, *sep;
#ifndef DEBUG
 	struct sigaction sa;
	sa.sa_handler = do_nothing;	/* But not ignored. */
 	sigemptyset(&sa.sa_mask);
 	sa.sa_flags = 0;
 	sigaction(SIGUSR1, &sa, NULL);
	timeout = 500;
#endif
	hashkey.offset = 0;
	hashkey.len = sizeof(int);

	while(1) {
wait_socket:
		/* Make sure there is socket end to wait. */
		pthread_mutex_lock(&socket_end_index_mut);
		while(socket_end_count <= 0) {
			pthread_cond_wait(&socket_end_count_cond, &socket_end_index_mut);
		}
		pthread_mutex_unlock(&socket_end_index_mut);

start_poll:
		/* Construct pollset and set pollset_size */
		nfds = 0;
		pthread_mutex_lock(&socket_end_index_mut);
		for(i=socket_end_1; i!=-1; i=next) {
			sep = socket_end_list[i];
			next = sep->next_id;
			if(sep->connclosed) {
				wsocket_remove_socket_end(sep);
			} else {
				fds[nfds].fd = sep->fd;
				fds[nfds].events = streambuf_nr_bytes(sep->send_buffer) > 0 ? POLLIN|POLLHUP|POLLOUT : POLLIN|POLLHUP;
				nfds++;
			}
		}
		pthread_mutex_unlock(&socket_end_index_mut);

		if(nfds > 0 && (ret = poll(fds, nfds, timeout)) <= 0) {
			if(ret == 0 || errno == EINTR) {
				goto start_poll;
			} else {
				mylog(L_ERR, "poll() error:%s.\n", strerror(errno));
				usleep(500000);
				goto wait_socket;
			}
		}

		for(i=0; i<nfds; ++i) {
			if(fds[i].revents == 0) {
				continue;
			}

			sed.fd = fds[i].fd;
			pthread_mutex_lock(&socket_end_index_mut);
			sep = hasht_find_item(socket_end_fd_index, &hashkey, &sed); /* find context according fds[i].fd */;
			pthread_mutex_unlock(&socket_end_index_mut);
			if(sep == NULL) {
				mylog(L_ERR, "Hash table integrity failed: Can't find socket end of fd %d.\n", fds[i].fd);
				continue;
			}

			if(fds[i].revents & POLLHUP) {
				mylog(L_DEBUG, "socket_end_list[%d] of fd %d closed:%s.\n", sep->id, sep->fd, strerror(errno));
				socket_end_hup_cb(sep);
				continue;
			}
			if(fds[i].revents & POLLOUT) {
				socket_end_send_cb(sep);
			}
			if(fds[i].revents & POLLIN) {
				socket_end_recv_cb(sep);
			}
		}
	}

	pthread_exit(NULL);
}


void wsocket_init(void)
{
	int i,ret;

	socket_end_fd_index = hasht_new(NULL, POLLMAX);
	if (socket_end_fd_index == NULL) {
		mylog(L_ERR, "hasht_new() error:%s.\n", strerror(errno));
		raise(SIGABRT);
	}

	socket_end_url_index = hasht_new(NULL, POLLMAX);
	if (socket_end_url_index == NULL) {
		hasht_delete(socket_end_fd_index);
		mylog(L_ERR, "hasht_new() error:%s.\n", strerror(errno));
		raise(SIGABRT);
	}

	for(i=0; i<POLLMAX; i++) {
		socket_end_list[i] = NULL;
	}

	ret = pthread_create(&tid_poller, NULL, thr_poll, NULL);
	if(ret != 0) {
		hasht_delete(socket_end_fd_index);
		hasht_delete(socket_end_url_index);
		mylog(L_ERR, "pthread_create() error:%s.\n", strerror(errno));
		raise(SIGABRT);
	}

	signal(SIGPIPE, SIG_IGN);
}


void wsocket_delete(void)
{
	int i;
	flist_node_t *node;
	pthread_cancel(tid_poller);
	pthread_join(tid_poller, NULL);

	if(socket_end_fd_index != NULL) {
		hasht_delete(socket_end_fd_index);
		socket_end_fd_index = NULL;
	}

	if(socket_end_url_index != NULL) {
		hasht_delete(socket_end_url_index);
		socket_end_url_index = NULL;
	}

	for(i=0; i<POLLMAX; i++) {
		socket_end_delete(socket_end_list[i]);
		socket_end_list[i] = NULL;
	}

	while(atexit_list) {
		node = atexit_list;
		node->func();
		atexit_list = node->next;
		free(node);
	}

	socket_end_1 = -1;
	socket_end_count = 0;
	socket_end_nextid = -1;

	ERR_free_strings();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
}


int wsocket_run(wsocket_context_t *p)
{
	int ret=0;
	hashkey_t hashkey;
	struct wsocket_context_st *c=p;
	struct socket_end_st sed,*sep;

	hashkey.offset = sizeof(int);
	hashkey.len = HASHKEYSIZE;
	memcpy(sed.hashkey, c->hashkey, HASHKEYSIZE);

	pthread_mutex_lock(&socket_end_index_mut);
	sep = hasht_find_item(socket_end_url_index, &hashkey, &sed);
	if(sep == NULL && wsocket_append_socket_end(&sep, c) < 0) {
		pthread_mutex_unlock(&socket_end_index_mut);
		return -EINVAL;
	}

	pthread_mutex_lock(&sep->mut);
	pthread_mutex_unlock(&socket_end_index_mut);
	if(sep->connclosed) {
		pthread_mutex_unlock(&sep->mut);
		mylog(L_ERR, "socket_end_list[%d] of fd %d closed.\n", sep->id, sep->fd);
		return -EINVAL;
	}

	if(FLAG_CRYPT(c->peer_flag)==FRAME_FLAG_CRYPT_BLOWFISH || FLAG_CRYPT(c->local_flag)==FRAME_FLAG_CRYPT_BLOWFISH) {
		while((ret = socket_end_load_and_sync_key(sep)) < 0) {
			if(ret == -EAGAIN) {
#ifndef DEBUG
				pthread_kill(tid_poller, SIGUSR1);
#endif
				pthread_cond_wait(&sep->cond_key_state, &sep->mut);
			} else {
				sep->sharedkey_state = SHAREDKEY_STATE_CERT_EMPTY;
				pthread_mutex_unlock(&sep->mut);
				return -EINVAL;
			}
		}
	}

	ret = socket_end_open_pipeline(sep, c);
	pthread_mutex_unlock(&sep->mut);
#ifndef DEBUG
	pthread_kill(tid_poller, SIGUSR1);
#endif
	return ret;
}


int wsocket_send(wsocket_context_t *p, const void *data, size_t size)
{
	int ret=-EINVAL;
	hashkey_t hashkey;
	struct socket_end_st sed,*sep;
	struct wsocket_context_st *c=p;

	if(c == NULL || data == NULL || !size || c->pipeline_id < 0) {
		return ret;
	}

	hashkey.offset = sizeof(int);
	hashkey.len = HASHKEYSIZE;
	memcpy(sed.hashkey, c->hashkey, HASHKEYSIZE);

	pthread_mutex_lock(&socket_end_index_mut);
	sep = hasht_find_item(socket_end_url_index, &hashkey, &sed);
	if(sep == NULL) {
		pthread_mutex_unlock(&socket_end_index_mut);
		mylog(L_ERR, "Hash table integrity failed: Can't find socket end of hashkey %s.\n", c->hashkey);
		return ret;
	}

	pthread_mutex_lock(&sep->mut);
	pthread_mutex_unlock(&socket_end_index_mut);
	if(sep->connclosed) {
		mylog(L_ERR, "pipeline[%d] send data failed: socket_end_list[%d] of fd %d closed.\n", c->pipeline_id, sep->id, sep->fd);
	} else if(sep->pipeline_end[c->pipeline_id] == NULL) {
		mylog(L_ERR, "pipeline[%d] does not exist.\n", c->pipeline_id);
	} else if(c->stat.state != STATE_INPROGRESS) {
		mylog(L_ERR, "pipeline[%d] not open.\n", c->pipeline_id);
	} else {
		ret = socket_end_send_data(sep, c, data, size);
	}
	pthread_mutex_unlock(&sep->mut);
#ifndef DEBUG
	pthread_kill(tid_poller, SIGUSR1);
#endif
	return ret;
}


int wsocket_cancel(wsocket_context_t *p)
{
	int state;
	hashkey_t hashkey;
	struct socket_end_st sed,*sep;
	struct wsocket_context_st *c=p;

	if(c == NULL || c->pipeline_id < 0 || c->stat.state != STATE_INPROGRESS) {
		return -EINVAL;
	}

	hashkey.offset = sizeof(int);
	hashkey.len = HASHKEYSIZE;
	memcpy(sed.hashkey, c->hashkey, HASHKEYSIZE);

	pthread_mutex_lock(&socket_end_index_mut);
	sep = hasht_find_item(socket_end_url_index, &hashkey, &sed);
	if(sep == NULL) {
		pthread_mutex_unlock(&socket_end_index_mut);
		return -EINVAL;
	}

	pthread_mutex_lock(&sep->mut);
	pthread_mutex_unlock(&socket_end_index_mut);
	state = c->stat.state;
	if(c->stat.state == STATE_INPROGRESS && socket_end_close_pipeline(sep, c) == 0) {
		c->stat.state = STATE_CANCELED;
	}
	pthread_mutex_unlock(&sep->mut);

	return state;
}

struct wsocket_stat_st *wsocket_stat(wsocket_context_t *p, struct wsocket_stat_st *stat) {
	struct wsocket_context_st *c=p;
	struct wsocket_stat_st *statp;
	statp = malloc(sizeof(*statp));
	memcpy(statp, &c->stat, sizeof(*statp));

	if(stat != NULL) {
		memcpy(&c->stat, stat, sizeof(*stat));
	}
	return statp;
}
