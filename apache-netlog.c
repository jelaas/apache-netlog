/*
 * File: apache-netlog.c
 * Implements:
 *
 * Copyright: Jens L��s, 2010
 * Copyright license: According to GPL, see file COPYING in this directory.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/wait.h>
#include <poll.h>
#include <libgen.h>

#include "rijndael.h"
#include "jelopt.h"
#include "strbase64.h"
#include "http.h"
#include "jelist.h"

struct dst {
	char *url;
	char nonce[16];
	unsigned long long logid;
	time_t disabled_until;
	pid_t pid;
	int failures;
};

struct logentry {
	char *msg;
	unsigned long long id;
	int deliver_count;
};

struct {
	unsigned char key[256/8];
	struct jlhead *dsts;
	struct jlhead *log;
	unsigned long long idx;
	char *logfile;
	char *host;
	int maxfail, disabletime_s;
	int timeout_ms, interval_ms;
	int bufsize;
	
	/* syslog */
	int facility;
} conf;

struct {
	int active;
} var;

struct logentry *log_find(struct jlhead *log, unsigned long long id)
{
	struct logentry *logentry;
	
	jl_foreach(log, logentry) {
		if(logentry->id == id)
			return logentry;
	}
	return NULL;
}

/* logs logentry with dst->logid */
int dst_log(struct dst *dst, struct jlhead *log)
{
	struct logentry *logentry;
	RIJNDAEL_context ctx;
	unsigned char iv[16];
	char *inbuf, *msg, *ivs;
	unsigned char *outbuf;
	int fd, nblocks;
	size_t bufsize;
	char *err;
	int rc;
	
	logentry = log_find(log, dst->logid);
	if(logentry == NULL) return 0;

	if(!strncmp(dst->url, "file://", 7)) {
		/* log to file */
		if(*(dst->url+7) != '/') {
			if(chdir("/var/log/httpd")) {
				syslog(conf.facility|LOG_CRIT, "chdir(\"/var/log/httpd\") failed");
				return 1;
			}
		}
		fd = open(dst->url+7, O_RDWR|O_APPEND|O_CREAT|O_SYNC, 0664);
		if(fd == -1) {
			syslog(conf.facility|LOG_CRIT, "open(\"%s\") failed", dst->url);
			return 1;
		}
		if(logentry->msg) {
			if(write(fd, logentry->msg, strlen(logentry->msg)) != strlen(logentry->msg)) {
				syslog(conf.facility|LOG_CRIT, "write to \"%s\" failed", dst->url);
				close(fd);
				return 1;
			}
		} else {
			syslog(conf.facility|LOG_WARNING, "empty logentry encountered");
		}
		
		return close(fd);
	}
	
	fd = open("/dev/urandom", O_RDONLY);
	if(fd == -1) {
		syslog(conf.facility|LOG_ERR, "open(\"/dev/urandom\") failed");
		return 1;
	}
	read(fd, iv, sizeof(iv));
	close(fd);
	*(time_t *)iv = time(NULL);

	ivs =  bintobase64(iv, sizeof(iv));
	
	/* create buffer with nonce+line */
	bufsize = strlen(dst->nonce)+1 + strlen(logentry->msg)+1;
	inbuf = malloc(bufsize+16);
	outbuf = malloc(bufsize+16);
	if(!inbuf) {
		syslog(conf.facility|LOG_ERR, "malloc(%u) for encryption buffer failed", bufsize+16);
		return 1;
	}
	
	memset(inbuf, 0, bufsize+16);
	sprintf(inbuf, "%s\n%s", dst->nonce, logentry->msg);
	
	/* create + encrypt + base64code logmessage (nonce,line) */
	rijndael_setkey(&ctx, conf.key, sizeof(conf.key));
	
	nblocks = (bufsize+16)/16;

	rijndael_cfb_enc(&ctx, iv, 
			 outbuf, inbuf,
			 nblocks);
	msg = bintobase64(outbuf, nblocks*16);

	if((rc=http_post(dst->url, conf.timeout_ms,
			 dst->nonce, conf.host, conf.logfile, ivs,
			 msg, &err))) {
		if(err)
			syslog(conf.facility|LOG_ERR, "http_post() failed: %s", err);
		else
			syslog(conf.facility|LOG_ERR, "http_post() failed: %d", rc);
		return 1;
	}
	return 0;
}

int dst_nonce(struct dst *dst)
{
	sprintf(dst->nonce, "%ld:%llu", time(NULL), conf.idx);
	return 0;
}

unsigned long long log_first_id(struct jlhead *log)
{
	struct logentry *logentry;

	logentry = jl_head_first(log);
	if(logentry) return logentry->id;
	
	return 0;
}

int deliver()
{
	struct dst *dst;
	pid_t pid;

	var.active = 0;
	
	jl_foreach(conf.dsts, dst) {
		if(dst->disabled_until > time(NULL))
			continue;
		if(!dst->pid) {
			if(dst->logid == 0) {
				if(conf.log->len) {
					dst->logid = log_first_id(conf.log);
				}
			}
			if(log_find(conf.log, dst->logid) == NULL) {
				/* nothing to do */
				continue;
			}
			var.active++;
			
			dst_nonce(dst);
			pid = fork();
			if(pid == 0) {
				_exit(dst_log(dst, conf.log));
			}
			if(pid == -1) {
				syslog(conf.facility|LOG_ERR, "fork(): failed to create delivery process");
			}
			if( pid != -1) {
				dst->pid = pid;
			}
		}
	}
	
	return 0;
}

int collect()
{	
	int status, rc;
	struct dst *dst;
	struct logentry *logentry;

	/* remove logentry when delivered to all */
	jl_foreach(conf.dsts, dst) {
		if(dst->pid == 0)
			continue;
		
		var.active++;
		
		if(waitpid(dst->pid, &status, WNOHANG) != dst->pid)
			continue;
		
		rc = -1;
		if(WIFEXITED(status))
			rc = WEXITSTATUS(status);
		dst->pid = 0;
		if(rc == 0) {
			logentry = log_find(conf.log, dst->logid);
			if(logentry) {
				logentry->deliver_count++;
				if(logentry->deliver_count >= conf.dsts->len) {
					jl_del(logentry);
					free(logentry->msg);
				}
			}
			dst->logid++;
		} else {
			dst->failures++;
			if(dst->failures >= conf.maxfail) {
				syslog(conf.facility|LOG_CRIT, "disabling destination %s for %d seconds", dst->url, conf.disabletime_s);
				dst->disabled_until = time(NULL) + conf.disabletime_s;
				dst->failures = 0;
			}
		}
	}
	
	return 0;
}

int log_add(struct jlhead *log, char *line)
{
	struct logentry *logentry;
	
	logentry = malloc(sizeof(struct logentry));
	if(!logentry) {
		syslog(conf.facility|LOG_CRIT, "malloc of logentry failed! message lost!");
		return -1;
	}
	memset(logentry, 0, sizeof(struct logentry));
	logentry->msg = strdup(line);
	logentry->id = conf.idx;
	conf.idx++;

	jl_ins(log, logentry);
	return 0;
}

int main(int argc, char **argv)
{
	int rc, pos, err=0;
	ssize_t got;
	char *buf, *p, *line, *value;
	int ivalue;
	struct pollfd fds[1];
	struct dst *dst;
	char name[256];
	
	conf.bufsize = 2048;

	conf.log = jl_new();
	conf.dsts = jl_new();
	conf.idx = 1;
	conf.maxfail = 2;
	conf.disabletime_s = 10;
	conf.timeout_ms = 1000;
	conf.facility = LOG_DAEMON;
	conf.interval_ms = 10;
	
	if(gethostname(name, sizeof(name))==0) {
		conf.host = strdup(name);
	}
	if(!conf.host)
		conf.host = "unknown_host";
	
	strcpy((char*)conf.key, "dansahulahula");
	
	/* parse options */
	if(jelopt(argv, 'h', "help", NULL, NULL)) {
		printf("apache-netlog\n"
		       " Apache custom logger that logs locally and over the network.\n"
		       " -u --url URL           Add a log destination.\n"
		       " -H --host              Value host in HTTP POST message.\n"
		       " -l --logfile           Value of logfile in HTTP POST message.\n"
		       " -f --keyfile KEYFILE   Shared key for AES encryption in file.\n"
		       " -k --key KEY           Shared key for AES encryption.\n"
		       " -a --facility FAC      Syslog facility to use [daemon].\n"
		       " -D --disabletime S     Disabling time before retry of failed URL in seconds [10].\n"
		       " -T --timeout MS        Timeout for establishing connection in milliseconds [1000].\n"
		       " -I --interval MS       Polling interval when delivery processes are active in milliseconds [10].\n"
		       " -F --maxfail N         Maximum number of failures before disabling URL [2].\n"
			);
		exit(0);
	}

	while(jelopt_int(argv, 'D', "disabletime",
		     &ivalue, &err)) {
		conf.disabletime_s = ivalue;
	}
	while(jelopt_int(argv, 'T', "timeout",
		     &ivalue, &err)) {
		conf.timeout_ms = ivalue;
	}
	while(jelopt_int(argv, 'I', "interval",
		     &ivalue, &err)) {
		conf.interval_ms = ivalue;
	}
	while(jelopt_int(argv, 'F', "maxfail",
		     &ivalue, &err)) {
		conf.maxfail = ivalue;
	}

	while(jelopt(argv, 'u', "url",
		     &value, &err)) {
		dst = malloc(sizeof(struct dst));
		if(!dst) {
			fprintf(stderr, "failed to alloc destination struct!\n");
			exit(1);
		}
		memset(dst, 0, sizeof(struct dst));
		dst->logid = 1;
		dst->url = value;
		if(!conf.logfile) {
			if(strncmp(value, "file://", 7)==0) {
				conf.logfile = basename(strdup(value+7));
			}
		}
		jl_ins(conf.dsts, dst);
	}

	while(jelopt(argv, 'k', "key",
		     &value, &err)) {
		memcpy(conf.key, value, strlen(value));
	}
	while(jelopt(argv, 'a', "facility",
		     &value, &err)) {
		if(!strcmp(value, "daemon")) conf.facility = LOG_DAEMON;
		if(!strcmp(value, "user")) conf.facility = LOG_USER;
		if(!strcmp(value, "ftp")) conf.facility = LOG_FTP;
		if(!strcmp(value, "news")) conf.facility = LOG_NEWS;
		if(!strcmp(value, "local0")) conf.facility = LOG_LOCAL0;
		if(!strcmp(value, "local1")) conf.facility = LOG_LOCAL1;
		if(!strcmp(value, "local2")) conf.facility = LOG_LOCAL2;
		if(!strcmp(value, "local3")) conf.facility = LOG_LOCAL3;
		if(!strcmp(value, "local4")) conf.facility = LOG_LOCAL4;
		if(!strcmp(value, "local5")) conf.facility = LOG_LOCAL5;
		if(!strcmp(value, "local6")) conf.facility = LOG_LOCAL6;
		if(!strcmp(value, "local7")) conf.facility = LOG_LOCAL7;
	}

	while(jelopt(argv, 'f', "keyfile",
		     &value, &err)) {
		int fd;
		fd = open(value, O_RDONLY);
		if(fd == -1) exit(5);
		read(fd, conf.key, sizeof(conf.key));
		close(fd);
	}

	while(jelopt(argv, 'H', "host",
		     &value, &err)) {
		conf.host = value;
	}
	while(jelopt(argv, 'l', "logfile",
		     &value, &err)) {
		conf.logfile = value;
	}

	argc = jelopt_final(argv, &err);
	
	if(err) {
		fprintf(stderr, "Error in options.\n");
		exit(2);
	}

	if(!conf.logfile) conf.logfile = "access.log";
	
	/* check configuration */
	if(conf.dsts->len == 0) {
		fprintf(stderr, "You must give atleast one destination!\n");
		exit(2);
	}
	
	/* allocate receive buffer */
	buf = malloc(conf.bufsize+1);
	
	syslog(conf.facility|LOG_INFO, "apache-netlog startup");
	
	pos = 0;
	buf[pos] = 0;
	while(1) {
		fds[0].fd = 0;
		fds[0].events = POLLIN;
		fds[0].revents = 0;
		rc = poll(fds, 1, var.active?conf.interval_ms:1000);
		
		if(rc != 0) {
			/* read input */
			got = read(0, buf+pos, conf.bufsize - pos - 1);
			if(got == 0) {
				/* EOF parent died? */
			}
			if(got > 0) {
				pos += got;
				if(pos >= (conf.bufsize-1)) {
					syslog(conf.facility|LOG_ERR, "buffer full: %d", conf.bufsize);
					buf[conf.bufsize-1] = '\n';
				} else {
					buf[pos] = 0;
				}
			}
			
			/* do we have a whole line? */
			if((p=strchr(buf, '\n'))) {
				/* extract line and remove from buf */
				line = strndup(buf, p-buf+1);

				memmove(buf, p, conf.bufsize - pos);
				pos = 0;
				
				/* put logentry in list */
				if(line) {
					log_add(conf.log, line);
					free(line);
				} else {
					syslog(conf.facility|LOG_CRIT, "malloc of logline failed! message lost!");
				}
			}
		}
		
		/* deliver to each dst */
		deliver();
		
		/* collect children */
		collect();
	}
}
