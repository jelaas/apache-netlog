#ifndef STRBASE64_H
#define STRBASE64_H
/*

  Copyright: Jens Låås, SLU 2003
  Copying: According to GPL2, see file COPYING in this directory.
  
*/

char *strtobase64(char *ascii_string);
unsigned char *base64tostr(const char *in_string, int *opt_len);
unsigned char *base64ntostr(const char *in_string, int *opt_len, int len);
char *bintobase64(unsigned char *bin_string, int len);

#endif
