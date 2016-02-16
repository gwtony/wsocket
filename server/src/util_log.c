#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define SYSLOG_NAMES 1
#include "util_log.h"
#include "util_syscall.h"

/* level name */
char *lname[8] = {"", "", "", "error", "notice", "warning", "info", "debug"};

static FILE *clog_fp;

static int flog_fd = -1;

//static int slog_facility;
//static int slog_ident;

static int log_target_set = 0;
static int log_targets_count = 0;

int log_base_level_=L_INFO;

__thread char log_buffer_[LOG_BUFFER_SIZE];

int mylog_set_target(enum log_target_en code, ...)
{
	va_list va;
	int fd;
	char *ident;
	int fac;
	char *path;

	if (code & LOGTARGET_FILE) {
		va_start(va, code);
		path = va_arg(va, char*);
		fd = open(path, O_WRONLY|O_APPEND|O_CREAT, 0644);
		if (fd < 0) {
			va_end(va);
			return -1;
		}
		if (flog_fd != -1) {
			close(flog_fd);
			flog_fd = fd;
			return log_targets_count;
		} else {
			flog_fd = fd;
			log_target_set |= LOGTARGET_FILE;
			return ++log_targets_count;
		}
	}
	if (code & LOGTARGET_SYSLOG) {
		va_start(va, code);
		ident = va_arg(va, char*);
		fac = va_arg(va, int);
		openlog(ident, LOG_PID, fac);
		va_end(va);
		log_target_set |= LOGTARGET_SYSLOG;
		return ++log_targets_count;
	}
	if (code & LOGTARGET_CONSOLE) {
		if (clog_fp==NULL) {
			clog_fp = fopen("/dev/console", "a");
			if (clog_fp==NULL) {
				return -1;
			}
			log_target_set |= LOGTARGET_CONSOLE;
			return ++log_targets_count;
		}
		return log_targets_count;
	}
	if (code & LOGTARGET_STDERR) {
		if (!(log_target_set & LOGTARGET_STDERR)) {
			log_target_set |= LOGTARGET_STDERR;
			return ++log_targets_count;
		}
		return log_targets_count;
	}
	return -1;
}

int mylog_clear_target(enum log_target_en code)
{
	if (code & LOGTARGET_FILE) {
		if (log_target_set & LOGTARGET_FILE) {
			log_target_set &= ~LOGTARGET_FILE;
			close(flog_fd);
			flog_fd = -1;
			return --log_targets_count;
		}
		return log_targets_count;
	}
	if (code & LOGTARGET_SYSLOG) {
		if (log_target_set & LOGTARGET_SYSLOG) {
			log_target_set &= ~LOGTARGET_SYSLOG;
			return --log_targets_count;
		}
		return log_targets_count;
	}
	if (code & LOGTARGET_CONSOLE) {
		if (log_target_set & LOGTARGET_CONSOLE) {
			fclose(clog_fp);
			log_target_set &= ~LOGTARGET_CONSOLE;
			return --log_targets_count;
		}
		return log_targets_count;
	}
	if (code & LOGTARGET_STDERR) {
		if (log_target_set & LOGTARGET_STDERR) {
			log_target_set &= ~LOGTARGET_STDERR;
			return --log_targets_count;
		}
		return log_targets_count;
	}
	return -1;
}

int mylog_least_level(int loglevel)
{
	if (loglevel<L_MINVALUE || loglevel>L_MAXVALUE) {
		return -EINVAL;
	}
	log_base_level_ = loglevel;
	return 0;
}

void do_mylog(int loglevel, char *fmt, ...)
{
	int size;
	va_list va;
	char tm[20];
	time_t now;
	struct tm breakdown;
	char tmp_fmt[LOG_BUFFER_SIZE];

	if (loglevel>log_base_level_) {
		return;
	}
	
	now = time(NULL);
	strftime(tm, 20, "%Y/%m/%d %H:%M:%S", localtime_r(&now, &breakdown)); 
	snprintf(tmp_fmt, LOG_BUFFER_SIZE, "%s[%d] [%s] [%s] %s\n", APPNAME, gettid(), tm, lname[loglevel], fmt);

	va_start(va, fmt);
	if (log_target_set & LOGTARGET_FILE) {
		size = vsnprintf(fmt, LOG_BUFFER_SIZE, tmp_fmt, va);
		write(flog_fd, fmt, size);
	}
	if (log_target_set & LOGTARGET_STDERR) {
		size = vsnprintf(fmt, LOG_BUFFER_SIZE, tmp_fmt, va);
		write(STDERR_FILENO, fmt, size);
	}
	if (log_target_set & LOGTARGET_SYSLOG) {
		vsyslog(loglevel, tmp_fmt, va);
	}
	if (log_target_set & LOGTARGET_CONSOLE) {
		vfprintf(clog_fp, tmp_fmt, va);
	}
	va_end(va);
}

void mylog_reset(void)
{
	mylog_clear_target(LOGTARGET_FILE);
	mylog_clear_target(LOGTARGET_SYSLOG);
	mylog_clear_target(LOGTARGET_CONSOLE);
	mylog_clear_target(LOGTARGET_STDERR);
}

int get_log_value(const char *str)
{
	int i;
	for (i=0;facilitynames[i].c_val!=-1;++i) {
		if (strcmp(facilitynames[i].c_name, str)==0) {
			return facilitynames[i].c_val;
		}
	}
	return -1;
}

