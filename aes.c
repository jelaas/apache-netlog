/*
 * File: aes.c
 * Implements:
 *
 * Copyright: Jens Låås, 2010
 * Copyright license: According to GPL, see file COPYING in this directory.
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include "rijndael.h"

RIJNDAEL_context ctx;
unsigned char key[256/8];
unsigned char iv[16];
char in[1024], out[1024];

int main(int argc, char **argv)
{
	if(argc > 1)
		strncpy((char*)key, argv[1], sizeof(key));
	
	rijndael_setkey (&ctx, key, sizeof(key));

	if(argc > 2) {
		read(0, iv, sizeof(iv));
		
		read(0, in, sizeof(in));
		
		rijndael_cfb_dec (&ctx, &iv, 
				  out, in,
				  sizeof(in)/16);
	} else {
		int fd;
		
		/* IV must be random. The IV in itself is not secret and can be transported plain */
		fd = open("/dev/urandom", O_RDONLY);
		read(fd, iv, sizeof(iv));
		close(fd);
		write(1, iv, sizeof(iv));
		
		read(0, in, sizeof(in));
		
		rijndael_cfb_enc (&ctx, &iv, 
				  out, in,
				  sizeof(in)/16);
	}
	write(1, out, sizeof(out));
	exit(0);
}
