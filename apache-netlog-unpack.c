/*
 * File: apache-netlog-unpack.c
 * Implements: program for unpacking encrypted messages sent with apache-netlog
 *
 * Copyright: Jens Låås Uppsala University, 2011
 * Copyright license: According to GPL, see file COPYING in this directory.
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include "rijndael.h"
#include "jelopt.h"
#include "strbase64.h"

struct {
	unsigned char key[256/8];
	unsigned char iv[16];
} conf;

int unpack(const char *nonce, const char *in, int inlen)
{
	char *out, *p;
	RIJNDAEL_context ctx;
	
	out = malloc(inlen+1);
	if(!out) return 2;
	
	memset(out, 0, inlen+1);
	
	if(rijndael_setkey(&ctx, conf.key, sizeof(conf.key))) {
		fprintf(stderr, "rijndael_setkey failed\n");
		return 1;
	}
	
	rijndael_cfb_dec(&ctx, conf.iv, 
			 out, in,
			 inlen/16);
	
	/* check nonce */
	if(strncmp(out, nonce, strlen(nonce))) {
		/* nonce did not match */
		return 3;
	}
	
	p = strchr(out, '\n');
	if(!p) {
		return 4;
	}
	
	printf("%s", p+1);
	return 0;
}

int main(int argc, char **argv)
{
	int msglen, err=0;
	int len, rc=1;
	char *nonce=NULL;
	unsigned char *msg=NULL, *ivs=NULL;
	char *value;

	/* same default key: must match default key in apache-netlog.c !! */
	strcpy((char*)conf.key, "dansahulahula");
	
	/* parse options */
	if(jelopt(argv, 'h', "help", NULL, NULL)) {
		printf("apache-netlog-unpack\n"
		       " Unpack an encrypted message sent from apache-netlog.\n"
		       " -n --nonce NONCE     Nonce value.\n"
		       " -i --iv IV           IV - initial vector.\n"
		       " -m --msg MSG         Message.\n"
		       " -k --key KEY         Shared KEY for AES decryption.\n"
		       " -f --keyfile KEYFILE Shared KEY for AES decryption in file.\n"
		       " IV and MSG must be base64 encoded strings.\n"
			);
		exit(0);
	}

	while(jelopt(argv, 'n', "nonce",
		     &nonce, &err)) {
		;
	}

	while(jelopt(argv, 'i', "iv",
		     &value, &err)) {
		ivs = base64tostr(value, &len);
		if(ivs) {
			ivs[len] = 0;
			memcpy(conf.iv, ivs, sizeof(conf.iv));
		}
	}
	
	while(jelopt(argv, 'm', "msg",
		     &value, &err)) {
		msg = base64tostr(value, &msglen);
	}
	
	while(jelopt(argv, 'k', "key",
		     &value, &err)) {
		memcpy(conf.key, value, strlen(value));
	}
	while(jelopt(argv, 'f', "keyfile",
		     &value, &err)) {
		int fd;
		fd = open(value, O_RDONLY);
		if(fd == -1) exit(5);
		read(fd, conf.key, sizeof(conf.key));
		close(fd);
	}
	
	if(msg && nonce && ivs)
		rc = unpack(nonce, (char*)msg, msglen);
	else
		fprintf(stderr, "message, nonce or ivs not set!\n");
	
	exit(rc);
}
