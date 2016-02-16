#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <string.h>
#include <math.h>

#include <weibo_socket.h>
#include <protocol.h>
#include <context.h>

static pthread_mutex_t send_ok_mut = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t send_ok_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t done_mut = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t done_cond = PTHREAD_COND_INITIALIZER;
static int send_ok = 1;
static uint64_t totalread = 0;
static int requests = 0;
static int done = 0;
static int heartbeatres=100;

struct req_st {
	int index,plid,outfd;
	wsocket_context_t *context;
	callback_t cb;
	int done, content_len, committed, sent;
};

static time_t systimestamp_ms(void)
{
        struct timeval tv;

        gettimeofday(&tv, NULL);

        return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

void recv_cb(void *p, void *data, size_t len)
{
	struct req_st *req=p;

	if (data != NULL) {
		if(req->outfd >= 0) write(req->outfd, data, len);
		req->content_len += len;
		totalread +=len;
	}
	//fprintf(stderr, "req[%d][%d]:RECV,recv:%dbytes.\n", req->index, req->plid, (int)len);
}

void sendok_cb(void *p)
{
	struct req_st *req=p;

	pthread_mutex_lock(&send_ok_mut);
	send_ok = 1;
	pthread_cond_broadcast(&send_ok_cond);
	pthread_mutex_unlock(&send_ok_mut);
}

void eof_cb(void *p, void *data, size_t len)
{
	struct req_st *req=p;
	struct wsocket_stat_st *stat=NULL;

	if (data != NULL) {
		totalread +=len;
	}
	stat = wsocket_stat(req->context, NULL);
	//fprintf(stderr, "req[%d][%d]:EOF,sent:%dbytes,recv:%dbytes,time:%lldms.\n", req->index, req->plid, stat->send_bytes, stat->recv_bytes, stat->end_time-stat->start_time);

	req->done = 1;
	if(req->outfd >= 0) {
		close(req->outfd);
	}
	if(stat != NULL) {
		free(stat);
		stat = NULL;
	}
	pthread_mutex_lock(&done_mut);
	if(heartbeatres && !(++done % heartbeatres)) {
		fprintf(stderr, "Completed %d requests\n", done);
		pthread_cond_broadcast(&done_cond);
	} else if(done == requests || !(done % 100)) {
		pthread_cond_broadcast(&done_cond);
	}
	pthread_mutex_unlock(&done_mut);
}

void except_cb(void *p, int code)
{
	struct req_st *req=p;
	struct wsocket_stat_st *stat=NULL;

	stat = wsocket_stat(req->context, NULL);
	fprintf(stderr, "req[%d][%d]:EXCEPTION,sent:%dbytes,recv:%dbytes,time:%lldms.\n", req->index, req->plid, stat->send_bytes, stat->recv_bytes, stat->end_time-stat->start_time);

	req->done = -1;
	if(req->outfd >= 0) {
		close(req->outfd);
	}
	if(stat != NULL) {
		free(stat);
		stat = NULL;
	}
	pthread_mutex_lock(&done_mut);
	if(heartbeatres && !(++done % heartbeatres)) {
		fprintf(stderr, "Completed %d requests\n", done);
		pthread_cond_broadcast(&done_cond);
	} else if(done == requests || !(done % 100)) {
		pthread_cond_broadcast(&done_cond);
	}
	pthread_mutex_unlock(&done_mut);
}

void init_env(char *argv[])
{
	struct sigaction sa;

	if(getenv("WSOCKET_SERVER")==NULL) {
		setenv("WSOCKET_SERVER", "10.75.13.92", 1);
		setenv("WSOCKET_PORT", "8002", 1);
		setenv("WSOCKET_KEEPALIVE", "0", 1);
		setenv("WSOCKET_CERT_CA", "/tmp/ca.crt", 1);
		setenv("WSOCKET_CERT_SERVER", "/tmp/client.crt", 1);
		execv(argv[0], argv);
	}

	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGPIPE, &sa, NULL);
}

int main(int argc, char *argv[])
{
	int ret, i, j, N, C;
	int crypt=0;
	int zip=0;
	int output=0;
	char *url="http://10.75.13.92/1k.html";

	char hashkey[64],fname[1024];
	size_t hashkey_len = 64;
	char header[4096];
	size_t header_len = 0;
	size_t data_len = 0;
	struct req_st *request;
	struct wsocket_context_st *ple;

	switch (argc) {
		case 8:
			output = strtol(argv[7], NULL, 10);
		case 7:
			zip = strtol(argv[6], NULL, 10);
		case 6:
			crypt = strtol(argv[5], NULL, 10);
		case 5:
			data_len = strtol(argv[4], NULL, 10);
		case 4:
			url = argv[3];
			N = strtol(argv[2], NULL, 10);
			C = strtol(argv[1], NULL, 10);
			break;
		case 3:
		case 2:
		case 1:
		default:
			fprintf(stderr, "Usage: %s Concurrency Num URL [DATA_LEN] [CRYPT] [ZIP] [OUTPUT]\n", argv[0]);
			return -1;
	}

	if(data_len > 0) {
		header_len = snprintf(header, 4096, "POST %s HTTP/1.0\r\nContent-Length:%d\r\n\r\n", url, data_len);
	} else {
		header_len = snprintf(header, 4096, "GET %s HTTP/1.0\r\n\r\n", url);
	}

	char data[data_len];
	for(i=0;i<data_len;++i) {
		data[i] = i%63;
	}

	init_env(argv);
	strncpy(hashkey, "10.75.13.92", hashkey_len);

context_init:
	request = malloc(N*sizeof(struct req_st));
	for(i=0; i<N; ++i) {
		hashkey_len = snprintf(hashkey, 64, "10.73.31.119_%d", i%C);
		request[i].context = wsocket_context_new();
		wsocket_context_set_hashkey(request[i].context, hashkey, hashkey_len);
		wsocket_context_set_flag(request[i].context, FRAME_FLAG_MAKE(1, crypt, zip), FRAME_FLAG_MAKE(1, crypt, zip));
		wsocket_context_set_recv_timeout(request[i].context, 3000);
		wsocket_context_set_data(request[i].context, header, header_len);

		request[i].cb.recv_cb = recv_cb;
		request[i].cb.recv_cb_arg1 = (void *)(request+i);
		request[i].cb.sendok_cb = sendok_cb;
		request[i].cb.sendok_cb_arg1 = (void *)(request+i);
		request[i].cb.eof_cb = eof_cb;
		request[i].cb.eof_cb_arg1 = (void *)(request+i);
		request[i].cb.except_cb = except_cb;
		request[i].cb.except_cb_arg1 = (void *)(request+i);
		wsocket_context_set_callback(request[i].context, &request[i].cb);

		request[i].index = i;
		request[i].plid = i;
		request[i].content_len = 0;
		request[i].done = 0;
		request[i].committed = 0;
		request[i].sent = data_len > 0 ? 0 : 1;

		if(output) {
			snprintf(fname, 1024, "output/req_%d", i);
			request[i].outfd = open(fname, O_WRONLY|O_CREAT|O_TRUNC, 0600);
		} else {
			request[i].outfd = -1;
		}
	}
	
	requests = N;
	if((heartbeatres) && (N > 150)) {
        heartbeatres = N / 10;
        if (heartbeatres < 100)
            heartbeatres = 100;
	}

	/** open and send */
    	time_t start;
	start = systimestamp_ms();
	for(i=0; i<N; ++i) {
wsocket_wait:
		pthread_mutex_lock(&send_ok_mut);
		while(!send_ok) {
			pthread_cond_wait(&send_ok_cond, &send_ok_mut);
		}
		pthread_mutex_unlock(&send_ok_mut);

		if(!request[i].committed) {
wsocket_run:
			ret = wsocket_run(request[i].context);
			if(ret == -EAGAIN) {
				pthread_mutex_lock(&send_ok_mut);
				send_ok = 0;
				pthread_mutex_unlock(&send_ok_mut);
				goto wsocket_wait;
			} else if(ret < 0) {
				pthread_mutex_lock(&done_mut);
				pthread_cond_wait(&done_cond, &done_mut);
				pthread_mutex_unlock(&done_mut);
				goto wsocket_run;
			} else {
				ple = request[i].context;
				request[i].plid = ple->pipeline_id;
				request[i].committed = 1;
			}
		}

		if(!request[i].sent && request[i].committed && !request[i].done) {
			ret = wsocket_send(request[i].context, data, data_len);
			if(ret == -EAGAIN) {
				pthread_mutex_lock(&send_ok_mut);
				send_ok = 0;
				pthread_mutex_unlock(&send_ok_mut);
				goto wsocket_wait;
			} else if(ret < 0) {
				request[i].sent = -1;
				request[i].done = -1;
				fprintf(stderr, "req[%d][%d]:ERROR,send data failed.\n", i, request[i].plid);
			} else {
				request[i].sent = 1;
			}
		}
	}

	/** stats */
	pthread_mutex_lock(&done_mut);
	while(done < requests) {
		pthread_cond_wait(&done_cond, &done_mut);
	}
	pthread_mutex_unlock(&done_mut);
	double timetaken = systimestamp_ms() - start;
	fprintf(stderr, "Finished %d requests\n", done);

	int committed=0, sent=0, succ=0, failed=0;
	for(i=0; i<N; ++i) {
		if(request[i].committed == 1) {
			committed++;
		}
		if(request[i].sent == 1) {
			sent++;
		}
		if(request[i].done == 1) {
			succ++;
		}
		if(request[i].done == -1) {
			failed++;
		}
		wsocket_context_delete(request[i].context);
		request[i].context = NULL;
	}

	char *uri,*pos;
	char size[16];
	for(pos=(char *)url+8; *pos!='/' && *pos!='\0'; ++pos);
	uri = pos;
	for(pos+=1; *pos!='.'; ++pos);
	memcpy(size, uri+1, pos-uri-1);

	fprintf(stderr, "\r\n");
	fprintf(stderr, "Server Hostname:      %s\r\n", getenv("WSOCKET_SERVER"));
	fprintf(stderr, "Server Port:          %s\r\n", getenv("WSOCKET_PORT"));
	fprintf(stderr, "\r\n");
	fprintf(stderr, "Document Path:        %s\n", uri);
	fprintf(stderr, "Document Length:      %s\n", size);
	fprintf(stderr, "\r\n");
	fprintf(stderr, "Concurrency Level:    %d\n", C);
	fprintf(stderr, "Time taken for tests: %.3f seconds\n", (double) timetaken/1000);
	fprintf(stderr, "Complete requests:    %d\n", done);
	fprintf(stderr, "Failed requests:      %d\n", failed);
	fprintf(stderr, "Total transferred:    %lld bytes\n", totalread);
	fprintf(stderr, "Total transferred html:    %lld bytes\n", totalread);
	fprintf(stderr, "Requests per second:  %.2f [#/sec]\n", (double) done/(timetaken/1000));
	fprintf(stderr, "Time per request:     %.3f [ms]\n", (double) (C*timetaken)/done);
	fprintf(stderr, "Time per request:     %.3f [ms] (mean, across all concurrent requests)\n", (double) timetaken/done);
	fprintf(stderr, "Transfer rate:        %.2f [Kbytes/sec]\n", (double) (totalread/1024)/(timetaken/1000));

	free(request);
	request = NULL;
/*
	N += 100;
	if(N < 65535) {
		goto context_init;
	}
*/
	exit(0);
}
