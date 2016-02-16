/**
	\file main.c
	main()
*/

/** \cond 0 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
/** \endcond */

#include "l7server.h"
#include "thr_monitor.h"
#include "util_log.h"
#include "conf.h"

int nr_cpus = 0;
static struct l7_info_st *l7_info=NULL;
static int nr_l7=0;

static char *conf_path=NULL;
static cJSON *config;

static char pid_path[256];
static int pid_fd;

static int create_pidfile(char *fname)
{
	char pid_str[64];
	struct flock fl;
	int len, pid_num;

	pid_num = getpid();

	pid_fd = open(fname, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
	if (pid_fd == -1) {
		mylog(L_ERR, "Open pid file failed: %m");	
		return -1;
	}

	fl.l_type = F_WRLCK;
	fl.l_start = 0;
	fl.l_whence = SEEK_SET;
	fl.l_len = 0;
	fl.l_pid = pid_num;

	if (fcntl(pid_fd, F_SETLK, &fl) < 0) {
		mylog(L_ERR, "Another server is already running.");
		close(pid_fd);
		return -1;
	}

	ftruncate(pid_fd, 0);
	len = snprintf(pid_str, 64, "%d\n", pid_num);

	if (write(pid_fd, pid_str, len) == -1) {
		mylog(L_ERR, "Write pid to file failed");
		close(pid_fd);
		return -1;
	}

	return 0;
}

static void delete_pidfile(char *fname)
{
	if (pid_fd > 0) {
		close(pid_fd);
	}
	unlink(fname);
}

static int get_nrcpu(void)
{   
	cpu_set_t set;
	int i, num = 0;

	if (sched_getaffinity(0, sizeof(set), &set)<0) {
		mylog(L_ERR, "Sched_getaffinity failed: %m");
		return 1;
	}   

	for(i = 0; i < sizeof(set) * 8; i++){
		num += CPU_ISSET(i, &set);
	}   
	return num;
} 

/** Daemon exit. Handles most of signals. */
static void daemon_exit(int s)
{
	int i;

	if (s>0) {
		mylog(L_INFO, "Signal %d caught, exit now.", s); 
	} else {
		mylog(L_INFO, "Synchronized exit."); 
	}
	monitor_destroy();

	for (i = 0; i < nr_l7; i++) {
		if (l7_info[i].pid) {
			kill(l7_info[i].pid, SIGTERM);
		}
	}

	free(l7_info); 
	cJSON_Delete(config); 
	delete_pidfile(pid_path);

	mylog_reset();

	exit(0);
}

static void do_nothing(int s){}

/** Initiate signal actions */
static void signal_init(void)
{
	struct sigaction sa; 

	sa.sa_handler = daemon_exit;
	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGTERM);
	sigaddset(&sa.sa_mask, SIGQUIT);
	sigaddset(&sa.sa_mask, SIGINT);
	sa.sa_flags = 0;

	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGPIPE, &sa, NULL);

	sa.sa_handler = do_nothing;	/* But not ignored. */
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGUSR1, &sa, NULL);
}

static void usage(const char *a0)
{   
	fprintf(stderr, "Usage: \n\t"				\
			"%1$s -h\t\t"                       	\
			"Print usage and exit.\n\t"           \
			"%1$s -v\t\t"                      \
			"Print version info and exit.\n\t"    \
			"%1$s -c CONFIGFILE\t"                \
			"Start program with CONFIGFILE.\n\t"  \
			"%1$s\t\t"                       \
			"Start program with default configure file(%2$s)\n", a0, DEFAULT_CONFPATH);
}

static void log_init(cJSON *conf)
{
	mylog_reset();
	mylog_set_target(LOGTARGET_SYSLOG, APPNAME, LOG_DAEMON);
	if (conf_get_int("LogLevel", conf) == 7) {
		mylog_set_target(LOGTARGET_STDERR);
	} else {
		//TODO:
		mylog_set_target(LOGTARGET_STDERR);
	}
}

static void version(void)
{   
	fprintf(stdout, "%s\n", APPVERSION);
}

static int get_options(int argc, char **argv)
{
	int c;

	while (-1 != (c = getopt(argc, argv,
					"c:" /* configure file */
					"v" /* version */
					"h" /* help */
					))) {
		switch (c) {
			case 'c': /* configure file path */
				conf_path = optarg;
				break;
			case 'v': /* show version */
				version();
				break;
			case 'h': /* usage */
				usage(argv[0]);
				exit(EXIT_SUCCESS);
			default:
				fprintf(stderr, "Invalid arguments");
				return -1;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	pid_t pid;
	int i, j;
	char *basepath, *pidfname;
	cJSON *l7_conf, *l7_conf_elm;

	/*
	 * Parse arguments
	 */
	if (get_options(argc, argv) == -1) {
		return -1;
	}

	/*
	 * Parse config file
	 */
	if (conf_path == NULL) {
		conf_path = DEFAULT_CONFPATH;
	}

	config = conf_load(conf_path);
	if (config == NULL) {
		fprintf(stderr, "Cannot load configure file: [%s], give up.\n", conf_path);
		return -1;
	}

	/*
	 * Init
	 */
	log_init(config);

	/* set open files number */
	//rlimit_init();

	if (conf_get_bool("Daemon", config)) {
		daemon(1, 0);
	}

	basepath = conf_get_str("BaseDir", config);
	if (basepath == NULL) {
		mylog(L_WARNING, "BaseDir not set, use /.");
		chdir("/");
	} else {
		chdir(basepath);
	}

	pidfname = conf_get_str("PidFile", config);
	if (pidfname == NULL) {
		mylog(L_ERR, "Not set PidFile");
		cJSON_Delete(config); 
		return -1;
	}
	if (create_pidfile(pidfname) < 0) {
		mylog(L_ERR, "Create pid file failed");
		cJSON_Delete(config); 
		return -1;
	}

	signal_init();

	nr_cpus = get_nrcpu();
	if (nr_cpus<=0) {
		nr_cpus = 1;
	}
	mylog(L_INFO, "%d CPU(s) detected", nr_cpus);

	l7_conf = conf_get("L7_Configs", config);
	if (l7_conf->type!=cJSON_Array) {
		mylog(L_ERR, "L7_Configs must be an array!");
		daemon_exit(0);
	}

	nr_l7 = cJSON_GetArraySize(l7_conf);
	if (nr_l7<=0) {
		mylog(L_ERR, "No available l7 definitions found.");
		daemon_exit(0);
	}
	l7_info = malloc(sizeof(struct l7_info_st)*nr_l7);
	if (l7_info==NULL) {
		mylog(L_ERR, "Out of memory!");
		daemon_exit(0);
	}
	for (i=0; i<nr_l7; ++i) {
		l7_conf_elm = cJSON_GetArrayItem(l7_conf, i);
		if (l7_spawn(l7_conf_elm, l7_info+i)<0) {
			mylog(L_ERR, "Layer7[%s] start up failed.", conf_get_str("Name", l7_conf_elm));
			daemon_exit(0);
		}
	}

	for (i = 0; i < nr_l7; ++i) {
		for (j = i + 1; j < nr_l7; ++j) {
			if (!strcmp(l7_info[i].name, l7_info[j].name)) {
				mylog(L_ERR, "L7server name duplicated, server exit");
				daemon_exit(0);
				return -1;
			}
		}
	}

	monitor_init(config, l7_info, nr_l7);

	int l7_status;

	while (1) {
		pid = waitpid(-1, &l7_status, 0);
		if (pid<0) {
			mylog(L_INFO, "Waitpid failed: %m, continue!");
			continue;
		}
		for (i=0;i<nr_l7;++i) {
			if (l7_info[i].pid==pid) {
				mylog(L_INFO, "L7 server exit detected, lifetime = %d seconds, respawn it!", time(NULL)-l7_info[i].start_time);
				if (l7_spawn(l7_info[i].conf, l7_info+i)<0) {
					mylog(L_ERR, "L7 server respawn failed: %m");
					daemon_exit(0);
				}
				break;
			}
		}
		for (i = 0; i < nr_l7; ++i) {
			for (j = i + 1; j < nr_l7; ++j) {
				if (!strcmp(l7_info[i].name, l7_info[j].name)) {
					mylog(L_ERR, "L7server name duplicated, server exit");
					daemon_exit(0);
					return -1;
				}
			}
		}
	}

	daemon_exit(0);
	return 0;
}

