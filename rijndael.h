#include <inttypes.h>
typedef unsigned char byte;
typedef uint32_t u32;

#define MAXKC			(256/32)
#define MAXROUNDS		14


typedef struct {
    int   ROUNDS;                   /* key-length-dependent number of rounds */
    int decryption_prepared;
    byte  keySched[MAXROUNDS+1][4][4];	/* key schedule		*/
    byte  keySched2[MAXROUNDS+1][4][4];	/* key schedule		*/
} RIJNDAEL_context;

void rijndael_cfb_enc (RIJNDAEL_context *ctx, unsigned char *iv, 
		       void *outbuf_arg, const void *inbuf_arg,
		       unsigned int nblocks);
void rijndael_cfb_dec (RIJNDAEL_context *ctx, unsigned char *iv, 
		       void *outbuf_arg, const void *inbuf_arg,
		       unsigned int nblocks);
int rijndael_setkey (RIJNDAEL_context *ctx, const byte *key, const unsigned keylen);
