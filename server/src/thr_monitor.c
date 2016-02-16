#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>

#include "cJSON.h"
#include "json_conf.h"
#include "util_log.h"
#include "thr_monitor.h"

#define CLIENT_HOST_STR 16
#define DEFAULT_ADMIN "127.0.0.1"
#define DEFAULT_MONITOR_BUF_SIZE 256

#define CMD_INFO	"info"
#define CMD_RELOAD	"reload"
#define CMD_LIST	"list"

static pthread_t tid_monitor;
static struct l7_info_st *l7info;
static int l7_num;

static void monitor_process(int fd, cJSON *conf, int is_admin)
{
	int i, ret;
	char *arg;
	cJSON *result;
	size_t arg_size, buf_size = DEFAULT_MONITOR_BUF_SIZE;
	char recv_buf[DEFAULT_MONITOR_BUF_SIZE], send_buf[DEFAULT_MONITOR_BUF_SIZE];

	/* Only admin can send command ? */
	if (!is_admin) {
		close(fd);
		return;
	}

	memset(recv_buf, 0, buf_size);
	memset(send_buf, 0, buf_size);

	ret = read(fd, recv_buf, buf_size);
	if (ret <= 0) {
		close(fd);
		return;
	}

	if (ret > 0) {
		if (!strncmp(recv_buf, CMD_INFO, strlen(CMD_INFO))) {
			/* Return main.conf */
			cJSON_fdPrint(fd, conf);
			close(fd);

		} else if (!strncmp(recv_buf, CMD_RELOAD, strlen(CMD_RELOAD))) {
			arg = recv_buf + strlen(CMD_RELOAD) + 1; /* skip space */
			arg_size = ret - strlen(CMD_RELOAD) - 1;

			if (recv_buf[ret - 1] == '\n') {
				arg_size--;
			}

			mylog(L_DEBUG, "Receive reload command: %s", arg);
			for (i = 0; i < l7_num; i++) {
				if (arg_size != l7info[i].name_size) {
					continue;
				}
				if (strncmp(arg, l7info[i].name, arg_size) == 0) {
					break;	
				}
			}

			result = cJSON_CreateObject();
			if (i < l7_num) {
				kill(l7info[i].pid, SIGTERM);
				sprintf(send_buf, "Reload success l7server: %s", arg);
				cJSON_AddStringToObject(result, "ok", send_buf);
			} else {
				sprintf(send_buf, "Reload failed, not found l7server: %s", arg);
				cJSON_AddStringToObject(result, "error", send_buf);
			}

			cJSON_fdPrint(fd, result);
			cJSON_Delete(result);
			close(fd);
		} else if (!strncmp(recv_buf, CMD_LIST, strlen(CMD_LIST))) {
			mylog(L_DEBUG, "Receive list command");
			result = cJSON_CreateObject();
			for (i = 0; i < l7_num; i++) {
				cJSON_AddStringToObject(result, "l7_server", l7info[i].name);
				//snprintf(send_buf + pos, l7info[i].name_size + 2, "%s\n", l7info[i].name);
				//pos += l7info[i].name_size + 2;
			}

			cJSON_fdPrint(fd, result);
			cJSON_Delete(result);
			close(fd);
		} else {
			result = cJSON_CreateObject();
			cJSON_AddStringToObject(result, "error", "Unknown command!");
			cJSON_fdPrint(fd, result);
			cJSON_Delete(result);
			close(fd);
		}
	}
}

static void *thr_monitor(void *p)
{
	cJSON *conf = p;
	char *admin_ip;
	socklen_t addr_len;
	int sd, client, is_admin, val = 1;
	char client_ip[CLIENT_HOST_STR];
	struct sockaddr_in local_addr, client_addr;

	if (conf_get_int("MonitorPort", conf)==-1) {
		mylog(L_WARNING, "MonitorPort not defined, monitor thread not created!");
		pthread_exit(NULL);
	}
	admin_ip = conf_get_str("MonitorAdminIp", conf);
	if (admin_ip == NULL) {
		admin_ip = DEFAULT_ADMIN;
	}

	sd = socket(AF_INET, SOCK_STREAM, 0);
	
	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val))<0) {
		mylog(L_ERR, "Can't set SO_REUSEADDR to admin_socket.");
		close(sd);
		abort();
	} 

	local_addr.sin_family = AF_INET;
	local_addr.sin_port = htons((uint16_t)conf_get_int("MonitorPort", conf));
	inet_pton(AF_INET, "0.0.0.0", &local_addr.sin_addr);
	if (bind(sd, &local_addr, sizeof(local_addr))<0) {
		mylog(L_ERR, "Monitor bind failed: %m");
		close(sd);
		abort();
	}

	if (listen(sd, 1)<0) {
		mylog(L_ERR, "Monitor listen failed: %m");
		close(sd);
		abort();
	}

	while (1) {
		client = accept(sd, NULL, NULL);
		if (client < 0) {
			mylog(L_WARNING, "Monitor accept failed: %m");
			continue;
		}

		is_admin = 0;

		addr_len = sizeof(struct sockaddr);
		getpeername(client, (struct sockaddr *)&client_addr, &addr_len);
		inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, (socklen_t)CLIENT_HOST_STR);
		if (!strcmp(client_ip, admin_ip) || !strcmp(client_ip, DEFAULT_ADMIN)) {
			is_admin = 1;
		}

		monitor_process(client, conf, is_admin);
	
		//result = cJSON_CreateObject();
		//cJSON_fdPrint(client, result);
		//cJSON_Delete(result);
		//close(client);
	}
}


void monitor_init(cJSON *conf, struct l7_info_st *info, int num)
{
	l7info = info;
	l7_num = num;
	pthread_create(&tid_monitor, NULL, thr_monitor, conf);
}

void monitor_destroy(void)
{
	if (tid_monitor != 0) {
		pthread_cancel(tid_monitor);
		pthread_join(tid_monitor, NULL);
	}
}


