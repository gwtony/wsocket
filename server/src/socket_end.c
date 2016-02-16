/** \cond 0 */
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <assert.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/tcp.h>
#include "cJSON.h"
/** \endcond */

#include <my_crypt.h>

#include "protocol.h"
#include "frame.h"
#include "ds_llist.h"
#include "ds_olist.h"
#include "util_streambuf.h"
#include "upstream.h"
#include "util_log.h"
#include "util_atomic.h"
#include "util_misc.h"
#include "util_time.h"
#include "pipeline_end.h"
#include "l7server.h"
#include "util_atomic.h"
#include "json_conf.h"

#include "socket_end.h"
#include "http_xff.h"

#define SE_BUF_HARD (1024*1024*10)
#define DEFAULT_SE_SEND_TIMEOUT 30000
#define ONE_DAY 86400000

#define	U32_SOCKET_CONNECT	1

#define SOCKET_END_BUFFER_SIZE MSG_FRAME_MAX
#define PIPELINE_END_MAX 32768
#define SOCKET_END_SEND_MAX (1024*1024)

extern int nr_threads;

static int SOCKET_END_MAX=0;
static int socket_end_total_nr=0;
static time_t now;

static __thread struct socket_end_st **socket_end_arr=NULL;
static __thread int socket_end_arr_tail=0;
static __thread int socket_end_arr_max=0;
static __thread int socket_end_arr_nr=0;

static __thread int epollfd=-1;
static __thread olist_t *timeout_index = NULL;

static void socket_end_destroy(struct socket_end_st *se);
static int socket_end_cert_request(struct socket_end_st *se);
static int socket_end_generate_cert(uint8_t **bin, struct l7_param_st *lp);
static int socket_end_key_sync(struct socket_end_st *se, struct internal_ctl_socket_key_sync_st *cks);
static int socket_end_send_key_reject(struct socket_end_st *se);
static int socket_end_send_key_ok(struct socket_end_st *se);
static int socket_end_driver(struct socket_end_st *se);
static void socket_end_process_timeout(struct socket_end_st *se, time_t now);
static int socket_end_driver_flush_ioev(struct socket_end_st *se);
static void socket_end_delete_pipeline(struct socket_end_st *se, int id);

static int se_timeout_cmp(void *p1, void *p2)
{
	struct socket_end_st *e1=p1, *e2=p2;
	return e1->min_timeout_abs_ms - e2->min_timeout_abs_ms;
}

static void socket_end_cleanup(void *args)
{
	int i, j;
	struct socket_end_st *se;
	struct pipeline_end_st *pe;

	mylog(L_ERR, "In socket_end_cleanup");

	for (i = 0; i < socket_end_arr_max; i++) {
		se = socket_end_arr[i];
		if (se) {
			for (j = 0; j < se->pipeline_arr_size; ++j) {
				pe = se->pipeline_end[j];
				if (pe) {
					socket_end_delete_pipeline(se, pe->id);
				}
			}

			streambuf_delete(se->send_buffer);
			mylog(L_INFO, "Cleanup close se[%d]", i);
			close(se->socket);
			free(se->pipeline_end);
			free(se);
		}
		socket_end_arr[i] = NULL;
	}

	if (socket_end_arr) {
		free(socket_end_arr);
		socket_end_arr = NULL;
	}

	if (timeout_index) {
		olist_destroy(timeout_index);
		timeout_index = NULL;
	}

	if (likely(epollfd > 0)) {
		close(epollfd);
		epollfd = -1;
	}
}

static int socket_end_create_pipeline(struct socket_end_st *socket_end, struct internal_ctl_pipeline_open_st *arg)
{
	struct upstream_entry_st *upstream;
	struct pipeline_end_st *pe;

	upstream = upstream_get_entry(l7_upstream, socket_end->socket, arg);
	if (unlikely(upstream == NULL)) {
		mylog(L_ERR, "Upstream get entry failed");
		return -1;
	}

	pe = pipeline_end_create(socket_end, upstream, arg->flow_id);
	if (unlikely(pe == NULL)) {
		mylog(L_ERR, "Pipeline end create failed, se[%d]", socket_end->id);
		return -1;
	}

	pe->zip_flag = FLAG_ZIP(arg->reply_frame_flags);
	pe->crypt_flag = FLAG_CRYPT(arg->reply_frame_flags);

	if (arg->upstream_recvtimeo_ms == TIMEOUT_NOLIMIT) {
		pe->recv_timeout = ONE_DAY;
		mylog(L_DEBUG, "Set pipeline[%d] recv timeout to one day", arg->flow_id);
	} else {
		pe->recv_timeout = arg->upstream_recvtimeo_ms;
		mylog(L_DEBUG, "Set pipeline[%d] recv timeout to %d", arg->flow_id, pe->recv_timeout);
	}

	pe->next_id = socket_end->pipeline_1;
	if (socket_end->pipeline_1!=-1) {
		socket_end->pipeline_end[socket_end->pipeline_1] -> prev_id = arg->flow_id;
	}
	pe->prev_id = -1;
	socket_end->pipeline_end[arg->flow_id] = pe;
	socket_end->pipeline_1 = arg->flow_id;

	return 0;
}

static void socket_end_delete_pipeline(struct socket_end_st *se, int id)
{
	struct pipeline_end_st *pe;

	pe = se->pipeline_end[id];

	if (pe->prev_id == -1 && pe->next_id == -1) {
		se->pipeline_1 = -1;
	} else if (pe->prev_id == -1) {
		se->pipeline_end[pe->next_id] -> prev_id = -1;
		se->pipeline_1 = pe->next_id;
	} else if (pe->next_id == -1) {
		se->pipeline_end[pe->prev_id] -> next_id = -1;
	} else {
		se->pipeline_end[pe->prev_id] -> next_id = pe->next_id;
		se->pipeline_end[pe->next_id] -> prev_id = pe->prev_id;
	}

	if (pe->service_start != 0) {
		pe->service_delay = now - pe->service_start;
		upstream_entry_report_service_delay(l7_upstream, pe->upstream, pe->service_delay);
	}
	if (pe->connect_delay != -1) {
		upstream_entry_report_connect_delay(l7_upstream, pe->upstream, pe->connect_delay);
	}
	upstream_entry_report_availability(l7_upstream, pe->upstream, pe->upstream_alive);
	pipeline_end_destroy(pe);
	se->pipeline_end[id] = NULL;
	se->pipeline_nr--;
	streambuf_setvolume(se->send_buffer, se->pipeline_nr * BUFVOL_MIN);
}

static void socket_end_process_timeout(struct socket_end_st *se, time_t now)
{
	struct pipeline_end_st *pe;
	int i, next;
	int timeout_happened = 0;
	time_t timeout;

	mylog(L_DEBUG, "Process timeout se timeout ms is %lu", se->timeout_abs_ms);

	if (se->timeout_abs_ms != 0 && se->timeout_abs_ms < now) {
		mylog(L_ERR, "Socket end timeout happend, client %s, se[%d]", se->client_str, se->id);
		socket_end_arr[se->id]=NULL;
		socket_end_destroy(se);
		atomic_decrease(&socket_end_total_nr);
		socket_end_arr_nr--;
		return;
	}

	for (i=se->pipeline_1; i!=-1; i=next) {
		pe = se->pipeline_end[i];
		next = pe->next_id;

		if (pe->closed) {
			continue;
		}
		if (pe->timeout_abs_ms > 0 && pe->timeout_abs_ms < now) {
			mylog(L_ERR, "Pipeline timeout happend, se[%d] pe[%d]", se->id, i);
			if (pe->timeout_abs_ms == se->min_timeout_abs_ms) {
				mylog(L_DEBUG, "To update se min timeout abs");
				timeout_happened = 1;
			}
			if (pe->iov_recv_pending) {
				streambuf_iov_free(pe->iov_recv_pending);
				pe->iov_recv_pending = NULL;
			}
			if (pe->connect_timeout_abs_ms == pe->timeout_abs_ms) {
				pe->upstream_alive = 0;
			}
			pe->error_code = PIPELINE_FAILURE_TIMEOUT;
			if (likely(pipeline_failure(pe) != ENOMEM)) {
				socket_end_delete_pipeline(se, i);
			}
		}
	}

	if (timeout_happened) {
		timeout = se->timeout_abs_ms;

		for (i=se->pipeline_1; i!=-1; i=se->pipeline_end[i]->next_id) {
			if (se->pipeline_end[i]->closed) {
				continue;
			}
			if (se->pipeline_end[i]->timeout_abs_ms > 0 &&
					(se->pipeline_end[i]->timeout_abs_ms < timeout || timeout == 0)) {
				timeout = se->pipeline_end[i]->timeout_abs_ms;
				mylog(L_DEBUG, "Set timeout from se[%d] pe[%d] abs to: %lu", se->id, i, timeout);
			}
		}

		mylog(L_DEBUG, "Update se min timeout abs to %lu, se[%d]", timeout, se->id);
		se->min_timeout_abs_ms = timeout;
	}

	if (olist_add_entry(timeout_index, se)) {
		mylog(L_ERR, "Add entry process timeout failed, se[%d]", se->id);
	} else {
		mylog(L_DEBUG, "Add entry process timeout %p success, se[%d]", se, se->id);
	}
	socket_end_driver_flush_ioev(se);

	return;
}

static int socket_end_protocol(struct socket_end_st *se)
{
	uint8_t *chunk;
	char *frame_buf;
	struct pipeline_end_st *pe;
	int plid, code, ret;
	internal_msg_t body; /* Broken down frame body */
	struct epoll_event ev;
	size_t size = MSG_FRAME_MAX;

	chunk = malloc(size);
	if (chunk == NULL) {
		mylog(L_ERR, "Allocate decode chunk buf failed, se[%d]", se->id);
		abort();
	}

	frame_buf = malloc(ntohs(se->buf_len)+2);
	if (unlikely(frame_buf == NULL)) {
		mylog(L_ERR, "Allocate frame buf failed, se[%d]", se->id);
		abort();
	}

	/* Copy body_len to buf */
	memcpy(frame_buf, &se->buf_len, 2);
	memcpy(frame_buf+2, se->buf_tail, ntohs(se->buf_len));

	ret = frame_decode(&body, (struct frame_st *)frame_buf, se->shared_key, chunk, size);
	if (ret < 0) {
		mylog(L_ERR, "Frame decode failed: unknown protocol");
		free(frame_buf);
		frame_buf = NULL;
		free(chunk);
		chunk = NULL;

		return -1;
	}

	free(frame_buf);
	frame_buf = NULL;

	if (body.msg_type == 0) { /* Data frame */
		plid = body.data_frame_body.flow_id;
		pe = se->pipeline_end[plid];

		if (unlikely((pe == NULL) || pe->closed)) {
			mylog(L_ERR, "Unvalid flowid %d, drop it, client %s, se[%d], port %d", plid, se->client_str, se->id, se->client_port);
			free(body.data_frame_body.data);
			
		} else {
			int size = body.data_frame_body.data_len;

			if (size > 0) {
				struct streambuf_iov_st *iov = NULL;

				iov = streambuf_iov_construct(body.data_frame_body.data, size);
				if (iov == NULL) {
					mylog(L_ERR, "Alloc iov failed, se[%d]", se->id);
					free(body.data_frame_body.data);
					return 0;
				}

				if (unlikely(pe->header_past==0)) {

					if (http_header_xff_process(iov, se->client_str)==0) {
						mylog(L_DEBUG, "HTTP header XFF process OK.");
					} else {
						mylog(L_ERR, "HTTP header XFF process FAILED.");
					}
					pe->header_past = 1;
				}

				mylog(L_DEBUG, "Write %d to upstream send buffer", size);
				if (pe->iov_send_pending) {
					mylog(L_INFO, "Merge to upstream_send_buf, se[%d] pe[%d]", se->id, pe->id);
					pe->iov_send_pending = streambuf_iov_merge(pe->iov_send_pending, iov);
					if (pe->iov_send_pending == NULL) {
						/* Should not be here */
						mylog(L_ERR, "Send pending iov merge failed");
						abort();
					}
					streambuf_iov_free(iov);
				} else {
					ret = streambuf_write_nb(pe->upstream_send_buf, iov);
					if (ret == ENOMEM) {
						mylog(L_INFO, "Write to upstream_send_buf failed, set send pending se[%d] pe[%d]", se->id, pe->id);
						pe->iov_send_pending = iov;
						se->send_pending_count++;
					}
				}
			} else {
				free(chunk);
			}
		}

	} else if (body.msg_type) { /* Control frame */
		code = body.ctl_frame_body.code;
		if (code == CTL_SOCKET_CERT_REQ) {
			/* Send CTL_SOCKET_CERT */
			socket_end_cert_request(se);
			free(chunk);
		} else if (code == CTL_SOCKET_KEY_SYNC) {
			/* Send CTL_SOCKET_KEY_OK or CTL_SOCKET_KEY_REJ */
			socket_end_key_sync(se, &body.ctl_frame_body.arg.socket_key_sync);
			free(chunk);
		} else if (code == CTL_PIPELINE_OPEN) {
			mylog(L_DEBUG, "Got cmd pipeline_open");
			plid = body.ctl_frame_body.arg.pipeline_open.flow_id;
			if (se->pipeline_end[plid]) {
				mylog(L_ERR, "Duplicated pipeline open id %d, Ignored, client %s, se[%d]", plid, se->client_str, se->id);
				free(chunk);
				return 0;
			}

			if (unlikely(socket_end_create_pipeline(se, &body.ctl_frame_body.arg.pipeline_open))) {
				mylog(L_ERR, "Create pipeline failed, client %s, se[%d]", se->client_str, se->id);
				free(chunk);
				return 0;
			}
			pe = se->pipeline_end[plid];
			se->pipeline_nr++;
			streambuf_setvolume(se->send_buffer, se->pipeline_nr * BUFVOL_MIN);
			ev.events = EPOLLIN|EPOLLRDHUP;
			ev.data.ptr = se;
			epoll_ctl(epollfd, EPOLL_CTL_ADD, pe->upstream_sd, &ev);

			int size = body.ctl_frame_body.arg.pipeline_open.data_len;

			if (size > 0) {
				struct streambuf_iov_st *iov = NULL;

				iov = streambuf_iov_construct(body.ctl_frame_body.arg.pipeline_open.data, size);
				if (unlikely(iov == NULL)) {
					mylog(L_ERR, "Fatal error: alloc iov failed");
					free(body.ctl_frame_body.arg.pipeline_open.data);
					socket_end_delete_pipeline(se, plid);
					return 0;
				}   

				if (likely(pe->header_past==0)) {

					if (http_header_xff_process(iov, se->client_str)==0) {
						mylog(L_DEBUG, "HTTP header XFF process OK.");
					} else {
						mylog(L_ERR, "HTTP header XFF process FAILED.");
					}
					pe->header_past = 1;
				}

				ret = streambuf_write_nb(pe->upstream_send_buf, iov);
				if (ret == ENOMEM) {
					mylog(L_INFO, "Write to upstream_send_buf failed, set send pending");
					pe->iov_send_pending = iov;
					se->send_pending_count++;
				}
			} else {
				free(chunk);
			}

		} else if (code == CTL_PIPELINE_CLOSE) {
			/* Close this pipeline */
			free(chunk);
			mylog(L_DEBUG, "Got cmd pipeline_close, se[%d]", se->id);
			plid = body.ctl_frame_body.arg.pipeline_close.flow_id;
			pe = se->pipeline_end[plid];
			if (unlikely(pe == NULL)) {
				/* Pipeline not exist */
				mylog(L_ERR, "Pipeline %d not exist, can not close, se[%d]", plid, se->id);
				return 0;
			}
			socket_end_delete_pipeline(se, plid);
		} else {
			free(chunk);
			mylog(L_INFO, "Invalid control code, client %s, se[%d]", se->client_str, se->id);
		}
	}
	return 0;
}

struct socket_end_st *socket_end_new(int sd) {
	struct socket_end_st *se;
	struct epoll_event ev;
	struct sockaddr_in addr;

	now=systimestamp_ms();

   	socklen_t addrlen = sizeof(struct sockaddr);

	mylog(L_DEBUG, "Socket end new for %d", sd);

	se = malloc(sizeof(*se));
	if (unlikely(se == NULL)) {
		return NULL;
	}

	se->send_buffer = streambuf_new(SE_BUF_HARD);
	if (unlikely(se->send_buffer == NULL)) {
		free(se);
		return NULL;
	}

	se->socket = sd;

	getpeername(sd, (struct sockaddr *)&addr, &addrlen);
	inet_ntop(AF_INET, &addr.sin_addr, se->client_str, (socklen_t)CLIENT_HOST_STR);
	se->client_port = ntohs(addr.sin_port);
	mylog(L_DEBUG, "New client from %s:%u", se->client_str, se->client_port);
	se->recv_state = SOCKET_RECV_STATE_LEN;
	se->buf_len_pos = 0;
	se->timeout_abs_ms = ONE_DAY + now;	// 1 day
	se->min_timeout_abs_ms = se->timeout_abs_ms;
	se->shared_key_flag = 0;

	se->pipeline_end = calloc(1, PIPELINE_END_MAX * sizeof(struct pipeline_end_st*));
	if (unlikely(se->pipeline_end == NULL)) {
		streambuf_delete(se->send_buffer);
		free(se);
		return NULL;
	}
	se->pipeline_arr_size = PIPELINE_END_MAX;
	se->pipeline_nr = 0;
	se->pipeline_1 = -1;
	se->send_pending_count = 0;

	memcpy(se->shared_key, NO_SHAREDKEY, strlen(NO_SHAREDKEY));

	if (olist_add_entry(timeout_index, se)) {
		mylog(L_DEBUG, "Add entry se new %p failed!", se);
	} else {
		mylog(L_DEBUG, "Add entry se new %p", se);
	}

	ev.events = EPOLLIN|EPOLLRDHUP;
	ev.data.ptr = se;
	epoll_ctl(epollfd, EPOLL_CTL_ADD, se->socket, &ev);

	return se;
}

static void socket_end_destroy(struct socket_end_st *se)
{
	int i;
	struct pipeline_end_st *pe;

	mylog(L_DEBUG, "Destroying socket end, client %s, se[%d]", se->client_str, se->id);

	/* destroy all pipelines */
	for (i = 0; i < se->pipeline_arr_size; ++i) {
		pe = se->pipeline_end[i];
		if (pe) {
			socket_end_delete_pipeline(se, pe->id);
		}
	}

	streambuf_delete(se->send_buffer);
	close(se->socket);

	se->min_timeout_abs_ms = -1;
	free(se->pipeline_end);
	free(se);
}

#define	EVENT_BATCH_SIZE	10240

void *thr_socket_end_accepter(void *p)
{
	int ret, sleep, on_duty = 0;
	int epfd, client_sd;
	struct epoll_event ev;
	struct sockaddr_in client_addr;
	socklen_t client_addr_len;
	
	epfd = epoll_create(1);
	if (unlikely(epfd == -1)) {
		mylog(L_ERR, "Init accepter epollfd failed");
		goto quit;
	}

	ev.events = EPOLLIN;
	ev.data.fd = l7_listen_socket;
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, l7_listen_socket, &ev);
	if (unlikely(ret < 0)) {
		mylog(L_ERR, "Watch listen socket failed");
		goto quit;
	}

	while (1) {
		ret = epoll_wait(epfd, &ev, 1, -1);
		if (ret > 0) {
			while (1) {
				client_sd = accept4(l7_listen_socket, (void*)&client_addr, &client_addr_len, SOCK_NONBLOCK);
				if (unlikely(client_sd < 0)) {
					if (errno == EAGAIN) {
						mylog(L_DEBUG, "Accept eagain");
						break;
					} else {
						mylog(L_ERR, "Accept(l7_listen_socket) error: %m");
						goto quit;
					}
				}
				mylog(L_DEBUG, "Accept done: fd is %d", client_sd);

				sleep = on_duty;
				while (1) {
					ret = write(accept_pipe[on_duty], &client_sd, sizeof(int));
					if (ret > 0) {
						break;
					}
					if (ret < 0 && errno == EAGAIN) {
						on_duty++;
						if (on_duty == nr_threads) {
							on_duty = 0;
						}
						if (on_duty == sleep) {
							usleep(50000);
						}
					} else {
						mylog(L_ERR, "Write client sd %d to pipe %d failed: %m", client_sd, accept_pipe[on_duty]);
						goto quit;
					}
				}

				mylog(L_DEBUG, "Write new sd %d to worker[%d] pipefd is %d", client_sd, on_duty, accept_pipe[on_duty]);
				on_duty++;
				if (on_duty == nr_threads) {
					on_duty = 0;
				}
				
				atomic_increase(socket_in_pipe);
			}
		}
	}

quit:
	mylog(L_DEBUG, "Quit accepter thr");

	if (likely(epollfd > 0)) {
		close(epollfd);
		epollfd = -1;
	}

	pthread_exit(NULL);
}


void *thr_socket_end_engine(void *p)
{
	struct l7_worker_arg *arg = p;
	cJSON *conf = arg->conf;
	int pipe_fd = work_pipe[arg->index];
	int n, i, j, ret, val;
	struct epoll_event evarr[EVENT_BATCH_SIZE], ev;
	struct sockaddr_in client_addr;
	socklen_t client_addr_len;
	int epollwait_timeout;
	int client_sd;
	struct socket_end_st *se, *head;

	pthread_cleanup_push(socket_end_cleanup, NULL);

	/* SOCKET_END_MAX is restricted in range [CONCURRENT_UNDERLIMIT, CONCURRENT_UPPERLIMIT].
	 * CONCURRENT_UNDERLIMIT and CONCURRENT_UPPERLIMIT is defined in socket_end.h
	 */
	SOCKET_END_MAX = conf_get_int("ConcurrentMax", conf);
	if (SOCKET_END_MAX<CONCURRENT_UNDERLIMIT) {
		SOCKET_END_MAX = CONCURRENT_UNDERLIMIT;
	} else if (SOCKET_END_MAX > CONCURRENT_UPPERLIMIT) {
		SOCKET_END_MAX = CONCURRENT_UPPERLIMIT;
	}
	socket_end_arr_max = SOCKET_END_MAX/nr_threads+1;
	socket_end_arr = calloc(1, sizeof(*socket_end_arr)*socket_end_arr_max);
	if (socket_end_arr==NULL) {
		mylog(L_ERR, "Insufficent memory for socket_end_arr[].");
		goto quit;
	}

	timeout_index = olist_new(CONCURRENT_UPPERLIMIT, se_timeout_cmp);
	if (unlikely(timeout_index == NULL)) {
		mylog(L_ERR, "Init timeout index failed");
		goto quit;
	}

	http_xff = conf_get_bool("HttpXff", conf) ? 0 : 1;

	epollfd = epoll_create(EVENT_BATCH_SIZE);	// For old kernel compatible. 1 is OKZ too.
	if (unlikely(epollfd == -1)) {
		mylog(L_ERR, "Init epollfd failed");
		goto quit;
	}

	ev.events = EPOLLIN;
	ev.data.u32 = U32_SOCKET_CONNECT;
	ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, pipe_fd, &ev);
	if (unlikely(ret < 0)) {
		mylog(L_ERR, "Watch listen socket failed");
		goto quit;
	}

	client_addr_len = sizeof(client_addr);
	while (1) {
		now=systimestamp_ms();
		head = olist_peek_head(timeout_index);
		if (head) {
			epollwait_timeout = head->min_timeout_abs_ms - now;
			if (epollwait_timeout < 0) {
				epollwait_timeout = 0;
			}
		} else {
			epollwait_timeout = 500;
		}

		n=epoll_wait(epollfd, evarr, EVENT_BATCH_SIZE, epollwait_timeout);

		for (i=0; i<n; ++i) {
			if (evarr[i].data.u32 == U32_SOCKET_CONNECT) { /* accept is ready */
				evarr[i].data.ptr = NULL;
				mylog(L_DEBUG, "Socket end arr nr is %d", socket_end_arr_nr);
				while (1) {
					ret = read(pipe_fd, &client_sd, sizeof(int));
					if (ret < 0) {
						if (errno==EAGAIN) {
							break;
						} else {
							mylog(L_ERR, "get client sd from pipe error: %m");
							goto quit;
						}
					}
					if (ret == 0) {
						continue;
					}

					mylog(L_DEBUG, "Worker got a new fd: %d", client_sd);
					atomic_decrease(socket_in_pipe);

					if (likely((socket_end_arr_nr >= (socket_end_arr_max - 1)) && (socket_end_total_nr < SOCKET_END_MAX))) {
						mylog(L_ERR, "Thread process too many socket_ends, close");
						close(client_sd);
						break;
					} 

					if (unlikely(socket_end_total_nr >= SOCKET_END_MAX)) {
						mylog(L_ERR, "TOO many socket_ends! Ignored!");
						close(client_sd);
					} else {
						val = 1;
						if (setsockopt(client_sd, IPPROTO_TCP, TCP_CORK, &val, sizeof(val))< 0) {
							mylog(L_ERR, "Set client sd cork failed");
						}
						se = socket_end_new(client_sd);
						if (unlikely(se == NULL)) {
							mylog(L_ERR, "Create socket end failed");
							goto quit;
						}

						while (socket_end_arr[socket_end_arr_tail]!=NULL) {
							socket_end_arr_tail++;
							if (unlikely(socket_end_arr_tail>=socket_end_arr_max)) {
								socket_end_arr_tail=0;
								mylog(L_DEBUG, "Socket_end arr tail return to 0");
							}
						}
						socket_end_arr[socket_end_arr_tail] = se;
						socket_end_arr[socket_end_arr_tail]->id = socket_end_arr_tail;
						mylog(L_DEBUG, "Create socket end, se[%d]", se->id);

						socket_end_arr_nr++;
						mylog(L_DEBUG, "Socket end arr nr is %d", socket_end_arr_nr);
						atomic_increase(&socket_end_total_nr);
						mylog(L_DEBUG, "Socket end total nr is %d", socket_end_total_nr);
					}
				}
				break; /* break after while */
			}
		}

		for (i=0; i<n; ++i) {
			if (evarr[i].data.ptr == NULL) {
				continue;
			}
			/* evarr[] 排重 */
			for (j=i+1;j<n;++j) {
				if (evarr[i].data.ptr == evarr[j].data.ptr) {
					evarr[j].data.ptr = NULL;
				}
			}
			se = evarr[i].data.ptr;
			if (unlikely(socket_end_driver(se)==-EINVAL)) {
				mylog(L_DEBUG, "Remove entry engine %p, se[%d]", se, se->id);
				if (unlikely(olist_remove_entry_by_datap(timeout_index, se)!=0)) {
					/* should not be here */
					mylog(L_ERR, "Critical exception: socket end missed in epollfd, se[%d]", se->id);
					goto quit;
					//abort();
				}
				socket_end_arr[se->id]=NULL;
				socket_end_destroy(se);
				socket_end_arr_nr--;
				atomic_decrease(&socket_end_total_nr);
			}

		}

		now = systimestamp_ms();
		while (1) {
			se = olist_fetch_head(timeout_index);
			if (se == NULL) {
				//mylog(L_DEBUG, "timeout_index is empty.");
				break;
			} 
			if (se->min_timeout_abs_ms != 0 && se->min_timeout_abs_ms < now) {
				mylog(L_INFO, "Socket end is timed out, se[%d]", se->id);
				socket_end_process_timeout(se, now);
			} else {
				if (se->min_timeout_abs_ms != 0) {

					if (olist_add_entry(timeout_index, se)) {
						mylog(L_DEBUG, "Add entry engine %p failed, se[%d]", se, se->id);
					} else {
						mylog(L_DEBUG, "Add entry engine %p success, se[%d]", se, se->id);
					}
					break;
				}
			}
		}
	}

quit:

	mylog(L_DEBUG, "Quit thr engine");

	pthread_cleanup_pop(1);

	if (timeout_index) {
		olist_destroy(timeout_index);
		timeout_index = NULL;
	}

	if (socket_end_arr) {
		free(socket_end_arr);
	}

	if (likely(epollfd > 0)) {
		close(epollfd);
		epollfd = -1;
	}

	pthread_exit(NULL);
}

int socket_end_msg_enqueue(struct socket_end_st *socket_end, int flag, internal_msg_t *msg, int plid) {
	ssize_t size;
	int ret = -1;
	struct pipeline_end_st *pe;
	struct frame_st *dst = NULL;
	struct streambuf_iov_st *iov = NULL;

	mylog(L_DEBUG, "Socket end msg send");

	dst = malloc(MSG_FRAME_MAX);
	if (dst == NULL) {
		mylog(L_ERR, "Malloc dst failed");
		goto error;
	}

	size = frame_encode(dst, MSG_FRAME_BODY_MAX, msg, flag, socket_end->shared_key);
	if (unlikely(size <= 0)) {
		mylog(L_ERR, "Frame encode failed");
		goto error;
	}

	iov = streambuf_iov_construct(dst, size);
	if (unlikely(iov == NULL)) {
		mylog(L_ERR, "Iov construct failed");
		goto error;
	}

	ret = streambuf_write_nb(socket_end->send_buffer, iov);
	if (ret == ENOMEM) {
		mylog(L_INFO, "Send buffer hard limit exceeded, se[%d] pe[%d]", socket_end->id, plid);
		if (plid >= 0) {
			pe = socket_end->pipeline_end[plid];

			if (pe->iov_recv_pending) {
				mylog(L_INFO, "Pe receive pending buffer is exist");
				pe->iov_recv_pending = streambuf_iov_merge(pe->iov_recv_pending, iov);
				if (pe->iov_recv_pending == NULL) {
					/* Should not be here */
					mylog(L_ERR, "Iov merge failed");
					abort();
				}
				streambuf_iov_free(iov);
			} else {
				pe->iov_recv_pending = iov;
			}
		}
	}

	return ret;

error:
	if (iov) {
		free(iov);
		iov = NULL;
	}
	if (dst) {
		free(dst);
		dst = NULL;
	}

	return ret;
}

static int socket_end_cert_request(struct socket_end_st *se) {
	int ret, crt_len;
	uint8_t *crt_bin;
	internal_msg_t response;

	crt_len = socket_end_generate_cert(&crt_bin, &l7_param);
	if (crt_len < 0) {
		mylog(L_ERR, "Generate certificate failed, client %s:%u, se[%d]", se->client_str, se->client_port, se->id);
		return -1;
	}

	response.msg_type = 1;
	response.ctl_frame_body.code = CTL_SOCKET_CERT;
	response.ctl_frame_body.arg.socket_cert.crt_bin = crt_bin;
	response.ctl_frame_body.arg.socket_cert.crt_len = crt_len;

	ret = socket_end_msg_enqueue(se, 0, &response, -1);
	free(crt_bin);

	return ret;
}

static int socket_end_generate_cert(uint8_t **bin, struct l7_param_st *lp)
{
	uint8_t *cert;
	size_t len = lp->server_cert_bin_size;

	mylog(L_DEBUG, "Socket end generate cert");

	cert = malloc(len);
	if (cert == NULL) {
		return -1;
	}
	memcpy(cert, lp->server_cert_bin, len);

	*bin = cert;

	return len;
}


static int socket_end_key_sync(struct socket_end_st *se, struct internal_ctl_socket_key_sync_st *cks) {
	uint32_t crc32;
	uint8_t plainkey[SHAREDKEY_BYTESIZE];

	mylog(L_DEBUG, "Socket end key sync, se[%d]", se->id);
	if (se->shared_key_flag) {
		mylog(L_ERR, "Shared key is existed, client %s:%u, se[%d]", se->client_str, se->client_port, se->id);
		socket_end_send_key_reject(se);
	}

	if (cks->encrypted_shared_key_len != RSA_KEYSIZE) {
		mylog(L_ERR, "Key len error");
		socket_end_send_key_reject(se);
		return -1;
	}

	if (decrypt_synckey(cks->encrypted_shared_key,
				plainkey,
				l7_param.server_privkey) < 0) {
		mylog(L_ERR, "Decrypt from encrypted shared key failed, client %s, se[%d]", se->client_str, se->id);
		socket_end_send_key_reject(se);
		return -1;
	}

	crc32 = mycrc32(plainkey, SHAREDKEY_BYTESIZE);
	if (cks->crc32 != crc32) {
		mylog(L_ERR, "Check key crc32 failed, client %s, se{%d}", se->client_str, se->id);
		socket_end_send_key_reject(se);
		return -1;
	} 

	memcpy(se->shared_key, plainkey, SHAREDKEY_BYTESIZE);
	se->shared_key_flag = 1;

	socket_end_send_key_ok(se);

	return 0;
}

static int socket_end_send_key_reject(struct socket_end_st *se) {
	internal_msg_t response;

	mylog(L_DEBUG, "Socket end send key reject, se[%d]", se->id);

	response.msg_type = 1;
	response.ctl_frame_body.code = CTL_SOCKET_KEY_REJ;

	return socket_end_msg_enqueue(se, 0, &response, -1);
}

static int socket_end_send_key_ok(struct socket_end_st *se) {
	internal_msg_t response;

	mylog(L_DEBUG, "Socket end send key ok, se[%d]", se->id);

	response.msg_type = 1;
	response.ctl_frame_body.code = CTL_SOCKET_KEY_OK;

	return socket_end_msg_enqueue(se, 0, &response, -1);
}

static int socket_end_driver_pipeline_connect(struct socket_end_st *se)
{
	int i, next, ret;
	struct pipeline_end_st *pe;

	for (i=se->pipeline_1; i!=-1; i=next) {
		pe = se->pipeline_end[i];
		next = pe->next_id;
		if (pe->connect_pending==0) {
			continue;
		}
		ret = pipeline_try_connect(pe);
		if (ret==-EINVAL) {
			mylog(L_ERR, "Pipeline upstream connect failed, client %s, se[%d] pe[%d]", se->client_str, se->id, i);
			se->pipeline_end[i]->error_code = PIPELINE_FAILURE_CONNECT_FAILED;
			if (pipeline_failure(pe) != ENOMEM) {
				socket_end_delete_pipeline(se, i);
			}
		} else if (ret==-EINPROGRESS) {
			if (pe->connect_timeout_abs_ms == 0) {
				pe->connect_timeout_abs_ms = now + pe->connect_timeout;
			}
		} else if (ret==0) {
			/* clean connect timeout abs */
			pe->connect_timeout_abs_ms = 0;
		}
	}
	return 0;
}

static int socket_end_driver_socket_send(struct socket_end_st *se)
{
	ssize_t ret=0;
	int flag = 0;
	int total = 0;
	size_t size;

	size = streambuf_nr_bytes(se->send_buffer);

	while (size > 0) {
		ret = streambuf_send(se->socket, se->send_buffer);
		/* speed limit */
		if (ret > 0) {
			size -= ret;
			total += ret;
			if (total > SOCKET_END_SEND_MAX) {
				if (se->timeout_abs_ms == 0 || flag) {
					se->timeout_abs_ms = DEFAULT_SE_SEND_TIMEOUT + now;
					mylog(L_DEBUG, "Too much data, set se timeout to %ld", se->timeout_abs_ms);
				}
				break;
			}
		}
		if (ret<0) {
			if (ret == -EAGAIN || ret == -EWOULDBLOCK) {
				mylog(L_DEBUG, "Socket_end send nonblock");

				if (se->timeout_abs_ms == 0 || flag) {
					se->timeout_abs_ms = DEFAULT_SE_SEND_TIMEOUT + now;
					mylog(L_DEBUG, "Send to se nonblock timeout is %lu", se->timeout_abs_ms);
				}
			} else {
				mylog(L_ERR, "Socket end send failed, client %s, se[%d]", se->client_str, se->id);
				return -EINVAL;
			}

			break;
		}

		flag = 1;
	}

	if (size == 0) {
		se->timeout_abs_ms = now + ONE_DAY;
	}

	return 0;
}

static int socket_end_driver_pipeline_send(struct socket_end_st *se)
{
	int i, next, ret;
	struct pipeline_end_st *pe;

	for (i=se->pipeline_1; i!=-1; i=next) {
		pe = se->pipeline_end[i];
		next = pe->next_id;
		if (pe->connect_pending) {
			continue;
		}
		if (pe->closed) {
			continue;
		}

		if (pe->iov_send_pending) {
			ret = streambuf_write_nb(pe->upstream_send_buf, pe->iov_send_pending);
			if (ret != ENOMEM) {
				pe->iov_send_pending = NULL;
				se->send_pending_count--;
				mylog(L_DEBUG, "Write pending to send buffer done, count is %d, se[%d] pe[%d]", se->send_pending_count, se->id, i);
			} 
		}

		if (streambuf_nr_bytes(pe->upstream_send_buf)==0) {
			continue;
		}

		ret = pipeline_upstream_send(pe);
		/* send success, left data in buffer, set timeout */
		if (ret == -EAGAIN) {
			if (pe->send_timeout_abs_ms == 0) {
				pe->send_timeout_abs_ms = now + pe->send_timeout;
				mylog(L_DEBUG, "Set pipeline send timeout is %lu, se[%d] pe[%d]", pe->timeout_abs_ms, se->id, i);
			}
		} else if (ret == -EINVAL) {
			mylog(L_ERR, "Send to upstream failed, se[%d] pe[%d]", se->id, i);
			pe->error_code = PIPELINE_FAILURE_SEND_FAILED;
			if (likely(pipeline_failure(pe) != ENOMEM)) {
				socket_end_delete_pipeline(se, i);
			}
		} else {
			mylog(L_DEBUG, "Sent %d to upstream, se[%d] pe[%d]", ret, se->id, pe->id);
			if (pe->iov_send_pending) {
				ret = streambuf_write_nb(pe->upstream_send_buf, pe->iov_send_pending);
				if (ret != ENOMEM) {
					pe->iov_send_pending = NULL;
					se->send_pending_count--;
					mylog(L_DEBUG, "Write pending to send buffer done, count is %d, se[%d] pe[%d]", se->send_pending_count, se->id, i);
				} 
			}
			/* Data in buffer set send timeout and update pe timeout */
			if (streambuf_nr_bytes(se->pipeline_end[i]->upstream_send_buf) > 0) {
				se->pipeline_end[i]->send_timeout_abs_ms = now + se->pipeline_end[i]->send_timeout;
				mylog(L_DEBUG, "Set pipeline send timeout is %lu, se[%d] pe[%d]", se->pipeline_end[i]->send_timeout_abs_ms, se->id, i);

			} else {
				se->pipeline_end[i]->send_timeout_abs_ms = 0;
				mylog(L_DEBUG, "All data sent, clean pipeline send timeout, se[%d] pe[%d]", i);
			}
			if (se->pipeline_end[i]->service_start==0) {
				se->pipeline_end[i]->service_start = now;
			}
		}
	}
	return 0;
}

static int socket_end_driver_socket_receive(struct socket_end_st *se)
{
	char buf[SOCKET_END_BUFFER_SIZE];
	ssize_t pos, size;
	int ret;

	if (se->send_pending_count > 0) {
		return 0;
	}

	size = recv(se->socket, buf, SOCKET_END_BUFFER_SIZE, MSG_DONTWAIT);
	mylog(L_DEBUG, "Receive %d from client, se[%d]", size, se->id);
	if (size<0 && errno!=EAGAIN) {
		mylog(L_ERR, "Receive from client failed: %m, client %s, se[%d]", se->client_str, se->id);
		return -EINVAL;
	} else if (size==0) {
		mylog(L_INFO, "Socket closed by client, client %s, se[%d]", se->client_str, se->id);
		return -EINVAL;
	} else if (size>0) {
		pos = 0;
		while (pos<size) {
			switch (se->recv_state) {
				case SOCKET_RECV_STATE_LEN:
					if (se->buf_len_pos==0 && size-pos>=2) {
						memcpy(&se->buf_len, buf+pos, 2);
						pos+=2;
						if (ntohs(se->buf_len)>SOCKET_END_BUFFER_SIZE) {
							mylog(L_ERR, "Frame length %d seems bad, client %s, se[%d]", (ntohs(se->buf_len)), se->client_str, se->id);
							return -EINVAL;
						}
						se->buf_tail = malloc(ntohs(se->buf_len));
						se->buf_tail_pos = 0;
						se->recv_state = SOCKET_RECV_STATE_TAIL;
					} else if (se->buf_len_pos==0 && size-pos==1) {
						memcpy(&se->buf_len, buf+pos, 1);
						pos+=1;
						se->buf_len_pos=1;
					} else if (se->buf_len_pos==1) {
						memcpy(((char*)(&se->buf_len))+1, buf+pos, 1);
						pos+=1;
						if (ntohs(se->buf_len)>SOCKET_END_BUFFER_SIZE) {
							mylog(L_ERR, "Frame length %d seems bad, client %s, se[%d]", (ntohs(se->buf_len)), se->client_str, se->id);
							return -EINVAL;
						}
						se->buf_tail = malloc(ntohs(se->buf_len));
						se->buf_tail_pos = 0;
						se->recv_state = SOCKET_RECV_STATE_TAIL;
					} else {
						/* Should not be here */
						mylog(L_ERR, "Socket end receive state %d is illegal, client %s, se[%d]", se->recv_state, se->client_str, se->id);
						return -EINVAL;
					}
					break;
				case SOCKET_RECV_STATE_TAIL:
					if ((size-pos) >= (ntohs(se->buf_len)-se->buf_tail_pos)) {
						memcpy(se->buf_tail+se->buf_tail_pos, buf+pos, ntohs(se->buf_len)-se->buf_tail_pos);
						ret = socket_end_protocol(se);
						free(se->buf_tail);

						se->buf_tail = NULL;
						if (ret < 0) {
							return -EINVAL;
						}
						pos+=ntohs(se->buf_len)-se->buf_tail_pos;
						se->buf_len_pos = 0;
						se->recv_state = SOCKET_RECV_STATE_LEN;
					} else {
						memcpy(se->buf_tail+se->buf_tail_pos, buf+pos, size-pos);
						se->buf_tail_pos += size-pos;
						pos += size - pos;
					}
					break;
				default:
					mylog(L_ERR, "Socket end receive state %d is illegal, client %s, se[%d]", se->recv_state, se->client_str, se->id);
					return -EINVAL;
			}
		}
	} else {
		/* EAGAIN */
	}
	return 0;
}

static int socket_end_driver_pipeline_receive(struct socket_end_st *se)
{
	int i, next, ret;
	ssize_t len;
	struct pipeline_end_st *pe;

	for (i=se->pipeline_1; i!=-1; i=next) {
		pe = se->pipeline_end[i];
		next = pe->next_id;
		if (pe->connect_pending) {
			continue;
		}

		if (pe->iov_recv_pending) {
			ret = streambuf_write_nb(se->send_buffer, pe->iov_recv_pending);
			if (ret == ENOMEM) {
				mylog(L_INFO, "Write pe iov recv pending to se send buffer no memory, se[%d] pe[%d]", se->id, i);
				break;
			} 
			pe->iov_recv_pending = NULL;
		}

		if (pe->closed) {
			mylog(L_INFO, "Pipeline is closed delete pipeline, se[%d] pe[%d]", se->id, i);
			socket_end_delete_pipeline(se, i);
			continue;
		}

		len = pipeline_upstream_recv(pe);
		if (len==-EPIPE) {
			if (likely(pipeline_close(pe) != ENOMEM)) {
				mylog(L_DEBUG, "Upstream closed send pe close to client, client %s, se[%d] pe[%d]", se->client_str, se->id, i);
				socket_end_delete_pipeline(se, i);
			}
			continue;
		}
		if (len==-EINVAL) {
			pe->error_code = PIPELINE_FAILURE_RECV_FAILED;
			if (likely(pipeline_failure(pe) != ENOMEM)) {
				mylog(L_ERR, "Receive from upstream failed, send pe failure to client, client %s, se[%d] pe[%d]", se->client_str, se->id, i);
				socket_end_delete_pipeline(se, i);
			}
			continue;
		}

		/* return EAGAIN: receive some data, there is still more data, update recv timeout */
		if (len == EAGAIN) {
			se->pipeline_end[i]->recv_timeout_abs_ms = now + se->pipeline_end[i]->recv_timeout;
			mylog(L_DEBUG, "Receive from pe %d nonblock recv timeout is %lu, se[%d] pe[%d] ", i, se->pipeline_end[i]->recv_timeout_abs_ms, se->id, i);
		}

		/* first nonblock recv */
		if (len == -EAGAIN && se->pipeline_end[i]->recv_timeout_abs_ms == 0) {
			se->pipeline_end[i]->recv_timeout_abs_ms = now + se->pipeline_end[i]->recv_timeout;
			mylog(L_DEBUG, "Receive from pe %d nonblock recv timeout is %lu, se[%d] pe[%d]", i, se->pipeline_end[i]->recv_timeout_abs_ms, se->id, i);

		}
		if (len == -1) {
			mylog(L_INFO, "Pipeline receive enqueue se send buffer no memory, se[%d] pe[%d]", se->id, i);
			break;
		}
		/* return -EAGAIN do not update timeout */
	}
	return 0;
}

static int socket_end_driver_flush_ioev(struct socket_end_st *se)
{
	size_t size;
	int i, ret;
	time_t timeout;
	int socket_end_recvblock;
	struct pipeline_end_st *pe;
	struct epoll_event ev_socket, ev_pipeline;

	timeout = se->timeout_abs_ms;
	mylog(L_DEBUG, "Set timeout from se timeout abs to: %lu, se[%d]", timeout, se->id);

	socket_end_recvblock=0;
	ev_socket.data.ptr = se;
	ev_socket.events = 0;
	ev_pipeline.data.ptr = se;

	for (i=se->pipeline_1; i!=-1; i=se->pipeline_end[i]->next_id) {
		pe = se->pipeline_end[i];
		if (pe->closed) {
			continue;
		}

		ev_pipeline.events = EPOLLRDHUP;

		if (pe->connect_pending) {
			ev_pipeline.events |= EPOLLOUT;
		} else {
			size = streambuf_nr_bytes(pe->upstream_send_buf);
			if (size > 0 || pe->iov_send_pending) {
				ev_pipeline.events |= EPOLLOUT;
			}
			if (pe->iov_recv_pending==NULL) {
				ev_pipeline.events |= EPOLLIN;
			}
			if (size > PE_BUF_HARD) {
				socket_end_recvblock=1;
			}
		}

		if (pe->connect_pending) {
			pe->timeout_abs_ms = pe->connect_timeout_abs_ms;
		} else {
			if (pe->send_timeout_abs_ms > pe->recv_timeout_abs_ms) {
				if (pe->recv_timeout_abs_ms == 0) {
					pe->timeout_abs_ms = pe->send_timeout_abs_ms;
				} else {
					pe->timeout_abs_ms = pe->recv_timeout_abs_ms;
				}
			} else {
				if (pe->send_timeout_abs_ms == 0) {
					pe->timeout_abs_ms = pe->recv_timeout_abs_ms;
				} else {
					pe->timeout_abs_ms = pe->send_timeout_abs_ms;
				}
			}
		}

		if (pe->timeout_abs_ms > 0 &&
				(pe->timeout_abs_ms < timeout || timeout == 0)) {
			timeout = pe->timeout_abs_ms;
			mylog(L_DEBUG, "Set timeout from pe timeout abs to: %lu, se[%d] pe[%d]", timeout, se->id, i);
		}
		if (unlikely(epoll_ctl(epollfd, EPOLL_CTL_MOD, pe->upstream_sd, &ev_pipeline)!=0)) {
			mylog(L_ERR, "Critical exception! pipeline upstream_sd lost in epollfd, se[%d] pe[%d]", se->id, i);
			abort();
		}
	}

	ev_socket.events = EPOLLRDHUP;
	if (streambuf_nr_bytes(se->send_buffer)>0) {
		ev_socket.events |= EPOLLOUT;
	}
	if (!socket_end_recvblock && se->send_pending_count == 0) {
		ev_socket.events |= EPOLLIN;
	}
	if (unlikely(epoll_ctl(epollfd, EPOLL_CTL_MOD, se->socket, &ev_socket)!=0)) {
		mylog(L_ERR, "Critical exception: socket_end->socket lost in epollfd, se[%d]", se->id);
		abort();
	}

	if (se->min_timeout_abs_ms != 0) {
		ret = olist_remove_entry_by_datap(timeout_index, se);
		if (unlikely(ret < 0)) {
			mylog(L_ERR, "Critical exception: socket_end lost in timeout_index, se[%d]", se->id);
			abort();
		}
	}
	se->min_timeout_abs_ms = timeout;
	if (olist_add_entry(timeout_index, se)) {
		mylog(L_ERR, "Socket end register timeout failed, se[%d]", se->id);
	} else {
		mylog(L_DEBUG, "Socket end will be timed out at: %lu, se[%d]", timeout, se->id);
	}
	return 0;
}

static int socket_end_driver(struct socket_end_st *se)
{
	int ret;

	now = systimestamp_ms();
	/* Process pipeline_end connecting pending. */
	ret = socket_end_driver_pipeline_connect(se);
	if (ret != 0) {
		return ret;
	}

	// Send socket_end
	ret = socket_end_driver_socket_send(se);
	if (ret != 0) {
		return ret;
	}

	// Send pipeline_end
	ret = socket_end_driver_pipeline_send(se);
	if (ret != 0) {
		return ret;
	}

	// Recv socket_end
	ret = socket_end_driver_socket_receive(se);
	if (ret != 0) {
		return ret;
	}

	// Recv pipeline_end
	ret = socket_end_driver_pipeline_receive(se);
	if (ret != 0) {
		return ret;
	}

	// Rearrage io events.
	ret = socket_end_driver_flush_ioev(se);
	if (ret != 0) {
		return ret;
	}

	return 0;
}

cJSON *socket_end_serialize(struct socket_end_st *se) {
	cJSON *result, *pipelines;
	char keybuf[SHAREDKEY_BYTESIZE*4], byte[8];
	int i;

	result = cJSON_CreateObject();
	pipelines = cJSON_CreateArray();

	cJSON_AddNumberToObject(result, "id", se->id);
	keybuf[0]=0;
	for (i=0;i<SHAREDKEY_BYTESIZE;++i) {
		snprintf(byte, 8, "%.2x ", se->shared_key[i]);
		strcat(keybuf, byte);
	}
	cJSON_AddStringToObject(result, "SharedKey", keybuf);
	cJSON_AddNumberToObject(result, "SendBuffer", streambuf_nr_bytes(se->send_buffer));
	for (i=se->pipeline_1; i!=-1; i=se->pipeline_end[i]->next_id) {
		cJSON_AddItemToArray(pipelines, pipeline_end_serialize(se->pipeline_end[i]));
	}
	cJSON_AddItemToObject(result, "Pipelines", pipelines);
	return result;
}

