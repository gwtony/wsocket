/** \cond 0 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <netdb.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h> 
#include <errno.h> 
#include <signal.h>
#include <sys/resource.h>
#include "cJSON.h"
/** \endcond */

#include "conf.h"
#include "l7server.h"
#include "util_log.h"
#include "upstream.h"
#include "socket_end.h"
#include "util_time.h"

#define DEFAULT_LOG_FILE "l7_nginx_phpfpm.log"
#define DEFAULT_FD_NUM 10240
#define DEFAULT_DATA_MAX 32

extern int nr_cpus;

int l7_listen_socket=-1;
//char *l7_name=NULL;
struct upstream_st *l7_upstream=NULL;
struct l7_param_st l7_param;
int nr_threads=0;
int *socket_in_pipe = NULL;

struct l7_worker_arg work_arg[MAX_THREADS];
int accept_pipe[MAX_THREADS];
int work_pipe[MAX_THREADS];

struct socket_info_st {
	struct sockaddr_storage peer_addr;
	struct socket_end_st *socket_end;
} socket_info;

//static pthread_t monitor_tid;

static volatile int loop=1;

static void l7_server_exit()
{
	loop = 0;
}

static void l7_signal_init(void)
{
	struct sigaction sa; 

	sa.sa_handler = l7_server_exit;
	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGTERM);
	sa.sa_flags = 0;

	sigaction(SIGTERM, &sa, NULL);

	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	sigaction(SIGINT, &sa, NULL);
}

static int load_l7_param(cJSON *conf)
{
	int fd = -1;
	struct stat crt_stat;
	char *ca_crt_filename;
	char *server_crt_filename;
	char *server_key_filename;

	ca_crt_filename = conf_get_str("CA_crt", conf);
	server_crt_filename = conf_get_str("Server_crt", conf);
	server_key_filename = conf_get_str("Server_key", conf);

	l7_param.server_privkey = load_privkey(server_key_filename);
	if (l7_param.server_privkey == NULL) {
		mylog(L_ERR, "Load private key failed");
		goto err;
	}
	l7_param.server_cert = load_x509(server_crt_filename);
	if (l7_param.server_cert == NULL) {
		mylog(L_ERR, "Load server cert failed");
		goto err;
	}
	l7_param.ca_cert = load_x509(ca_crt_filename);
	if (l7_param.ca_cert == NULL) {
		mylog(L_ERR, "Load ca cert failed");
		goto err;
	}
	
	fd = open(server_crt_filename, O_RDONLY);
	if (fd<0) {
		mylog(L_ERR, "Open certificate file: %m");
		return -1;
	}
	if (fstat(fd, &crt_stat)<0) {
		mylog(L_ERR, "Stat certificate file: %m");
		close(fd);
		return -1;
	}
		
	l7_param.server_cert_bin = mmap(NULL, crt_stat.st_size, PROT_READ, MAP_SHARED | MAP_LOCKED, fd, 0);	
	if (l7_param.server_cert_bin == MAP_FAILED) {
		mylog(L_ERR, "Mmap server cert: %m");
		goto err;
	}
	close(fd);
	
	l7_param.server_cert_bin_size = crt_stat.st_size;

	/* Verify server_cert by ca_cert */
	if (verify_cert(l7_param.server_cert, l7_param.ca_cert) != 0) {
		mylog(L_ERR, "verify server cert by ca cert failed");
		goto err;
	}
	/* check private key by server_cert */
	if (check_private_key(l7_param.server_cert, l7_param.server_privkey) != 0) {
		mylog(L_ERR, "Check private key by cert failed");
		goto err;
	}

	l7_param.server_pubkey = EVP_PKEY_IN_X509(l7_param.server_cert);

	return 0;

err:
	if (l7_param.server_privkey) {
		free_key(l7_param.server_privkey);
		l7_param.server_privkey = NULL;
	}
	if (l7_param.server_cert) {
		free_cert(l7_param.server_cert);
		l7_param.server_cert = NULL;
	}
	if (l7_param.ca_cert) {
		free_cert(l7_param.ca_cert);
		l7_param.ca_cert = NULL;
	}
	if (l7_param.server_cert_bin) {
		munmap(l7_param.server_cert_bin, l7_param.server_cert_bin_size);
	}
	if (fd != -1) {
		close(fd);
	}
	return -1;
}

static int listen_socket(cJSON *conf)
{
	int sd, f, timeo = 5;
	char *addr;
	struct sockaddr_in local_addr;

	sd = socket(AF_INET, SOCK_STREAM, 0);

	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &timeo, sizeof(timeo))<0) {
		mylog(L_ERR, "Can't set SO_REUSEADDR to listen socket.");
		close(sd);
		return -1;
	}
	
	if (setsockopt(sd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &timeo, sizeof(timeo))) {
		mylog(L_INFO, "Can't set TCP_DEFER_ACCEPT to listen socket.");
	}

	local_addr.sin_family = AF_INET;
	local_addr.sin_port = htons((uint16_t)conf_get_int("ListenPort", conf));

	addr = conf_get_str("ListenAddr", conf);
	if (addr == NULL) {
		mylog(L_ERR, "Get listen addr failed");
		close(sd);
		return -1;
	}

	inet_pton(AF_INET, addr, &local_addr.sin_addr);

	if (bind(sd, &local_addr, sizeof(local_addr))<0) {
		mylog(L_ERR, "Bind failed: %m");
		close(sd);
		return -1;
	}

	if (listen(sd, 500)<0) {
		mylog(L_ERR, "Listen failed: %m");
		close(sd);
		return -1;
	}

	f = fcntl(sd, F_GETFL);
	if (fcntl(sd, F_SETFL, f|O_NONBLOCK)<0) {
		mylog(L_ERR, "Can't set listen sd to nonblock mode: %m");
		close(sd);
		return -1;
	}

	return sd;
}

static void init_l7_upstream(cJSON *conf)
{
	int i, n;
	cJSON *value, *ups_item;
	static struct addrinfo hint;

	value = cJSON_GetObjectItem(conf, "Upstream");
	if (value->type!=cJSON_Array) {
		mylog(L_ERR, "Upstream value is not an array.");
		abort();
	}

	memset(&hint, 0, sizeof(struct addrinfo));
	hint.ai_family = AF_INET;
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_protocol = IPPROTO_TCP;
	l7_upstream = upstream_new(&hint);

	n = cJSON_GetArraySize(value);
	for (i=0; i<n; ++i) {
		ups_item = cJSON_GetArrayItem(value, i);
		upstream_entry_append(l7_upstream, ups_item);
	}
}

static rlim_t rlimit_try(rlim_t left, rlim_t right)
{
	struct rlimit r;

	if (left>right) {
		mylog(L_ERR, "Call: rlimit_try(%d, %d) is illegal!", left, right);
		abort();
	}
	if (left==right || left==right-1) {
		return left;
	}
	r.rlim_cur = right;
	r.rlim_max = r.rlim_cur;
	if (setrlimit(RLIMIT_NOFILE, &r)==0) {
		return right;
	}
	r.rlim_cur = (right-left)/2+left;
	r.rlim_max = r.rlim_cur;
	if (setrlimit(RLIMIT_NOFILE, &r)==0) {
		return rlimit_try(r.rlim_cur, right);
	} else {
		return rlimit_try(left, r.rlim_cur);
	}
}

static void rlimit_init(int fd_max)
{
	int limit;
	if (fd_max < DEFAULT_FD_NUM) {
		fd_max = DEFAULT_FD_NUM;
		mylog(L_INFO, "Open files limit is to small, set to default num");
	}
	limit = rlimit_try(1024, fd_max);
	mylog(L_INFO, "Open files limits set to %d", limit);
}

static void l7_server(cJSON *config, int status_socket)
{
	cJSON *conf;
	cpu_set_t mask;
	int i, level, ret, affinity_on = 0;
	char *logfile, *conf_path, *l7_name;
    pthread_t actid, tids[MAX_THREADS];
	char l7_data[DEFAULT_DATA_MAX];
	int pipefd[2];

	l7_signal_init();
	
	conf_path = config->valuestring;
	if (conf_path == NULL) {
		mylog(L_ERR, "Config path is null");
		send(status_socket, "1", 1, 0);
		return;
	}
	conf = conf_load(conf_path);
	if (conf == NULL) {
		mylog(L_ERR, "Load l7server conf failed: path is %s", conf_path);
		send(status_socket, "1", 1, 0);
		return;
	}

	l7_name = conf_get_str("Name", conf);
	if (l7_name==NULL) {
		l7_name = "_Undefined_";
	}

	mylog_reset();
	logfile = conf_get_str("LogFile", conf);
	if (logfile == NULL) {
		logfile = DEFAULT_LOG_FILE;
	}
	mylog_set_target(LOGTARGET_FILE, logfile);

	level = conf_get_int("LogLevel", conf);
	if (level == 0) {
		level = L_ERR;
	}
	mylog_least_level(level);

	rlimit_init(conf_get_int("FdMax", conf));

	if (load_l7_param(conf) < 0) {
		mylog(L_ERR, "Load server conf failed");
		send(status_socket, "1", 1, 0);
		return;
	}

	init_l7_upstream(conf);

	l7_listen_socket = listen_socket(conf);
	if (l7_listen_socket<0) {
		mylog(L_ERR, "Init l7_listen_socket: %m");
		send(status_socket, "1", 1, 0);
		return;
	}

	/* Count processor cores */
	nr_threads = conf_get_int("NrThreads", conf);
	if (nr_threads > MAX_THREADS) {
		nr_threads = MAX_THREADS;
	} else if (nr_threads < 1) {
		nr_threads = nr_cpus;
		affinity_on = 1;
	}

	for (i = 0; i < nr_threads; i++) {
		ret = pipe2(pipefd, O_NONBLOCK);
		if (ret < 0) {
			mylog(L_ERR, "Create control pipe failed");
			send(status_socket, "1", 1, 0);
			return;
		}
		accept_pipe[i] = pipefd[1];
		work_pipe[i] = pipefd[0];
	}

	pthread_create(&actid, NULL, thr_socket_end_accepter, NULL);
	pthread_detach(actid);

    for (i=0; i<nr_threads; ++i) {
		work_arg[i].conf = conf;
		work_arg[i].index = i;
        pthread_create(&tids[i], NULL, thr_socket_end_engine, &work_arg[i]);
        pthread_detach(tids[i]);
    }
	
	if (affinity_on) {
		for (i = 0; i < nr_cpus; i++) {
			CPU_ZERO(&mask);
			CPU_SET(i, &mask);
			pthread_setaffinity_np(tids[i], sizeof(cpu_set_t), &mask);
		}
	}

	if (strlen(l7_name) > DEFAULT_DATA_MAX - 3) {
		snprintf(l7_data, DEFAULT_DATA_MAX, "0 %s", l7_name);
	} else {
		snprintf(l7_data, strlen(l7_name) + 3, "0 %s", l7_name);
	}
	mylog(L_DEBUG, "Write %s to master", l7_data);
	send(status_socket, l7_data, strlen(l7_data), 0);

	while (loop) {
		pause();
	}

	mylog(L_DEBUG, "Cancel threads");
	pthread_cancel(actid);
    for (i=0; i<nr_threads; ++i) {
        pthread_cancel(tids[i]);
    }

	for (i = 0; i < nr_threads; i++) {
		close(accept_pipe[i]);
		close(work_pipe[i]);
	}
	close(status_socket);

	free_cert(l7_param.ca_cert);
	free_cert(l7_param.server_cert);
	free_key(l7_param.server_pubkey);
	free_key(l7_param.server_privkey);

	upstream_delete(l7_upstream);

	close(l7_listen_socket);

	cJSON_Delete(conf); 

	sleep(1);
}

int l7_spawn(cJSON *conf, struct l7_info_st *info)
{
	int pd[2], ret;
	char child_data[DEFAULT_DATA_MAX];
	//int child_code=0;

	if (socketpair(AF_LOCAL, SOCK_DGRAM, 0, pd)<0) {
		return -1;
	}
	
	info->socket_in_pipe = 0;
	socket_in_pipe = &info->socket_in_pipe;

	info->pid = fork();
	if (info->pid==0) {
		close(pd[0]);
		l7_server(conf, pd[1]);
		close(pd[1]);
		exit(0);
	}
	mylog(L_DEBUG, "Pid is %d", info->pid);
	close(pd[1]);
	info->monitor_fd = pd[0];
	info->conf = conf;
	info->start_time = systimestamp_ms() / 1000;

	while (1) {
		ret = recv(info->monitor_fd, child_data, 32, 0);
		if (ret <= 0) {
			continue;
		}
		if (errno == EINTR) {
			continue;
		}
		
		break;
	}

	mylog(L_DEBUG, "Result from child is %s", child_data);

	if (ret == 1) {
		return -1;
	}

	memset(info->name, 0, MAX_NAME);
	strncpy(info->name, child_data + 2, ret - 2); 
	info->name[ret - 2] = '\0';
	info->name_size = ret - 2;

	return 0;
}
