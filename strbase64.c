/*
 * File: strbase64.c
 * Implements:
 *
 * Copyright: Jens Låås, SLU 2007
 * Copyright license: According to GPL, see file COPYING in this directory.
 *
 */

#include <stdlib.h>
#include <string.h>

#include "strbase64.h"

char *bintobase64(unsigned char *bin_string, int len)
{
  int n = len;
  int v, i, phase, end;
  unsigned int c;
  unsigned char *s = bin_string;
  char *p = malloc(n*2+2);
  char *out_string;
  out_string = p;
  
  end = v = i = c = phase = 0;
  while(!end || phase > 0)
    {
      if( (!len) && (!end)) end = phase+1;
      if(len && (phase < 3))
	{
	  c = *s++;
	  len--;
	}
      else
	c = 0;
      
      switch(phase)
	{
	case 0:
	  i = (c >> 2);
	  v = c;
	  break;
	case 1:
	  i = ((c & 0xf0)>>4) + ((v & 3) << 4);
	  v = c;
	  break;
	case 2:
	  i = ((v & 0xf)<<2) + ( (c & 255) >> 6);
	  v = c;
	  break;
	case 3:
	  i = v & 0x3f;
	  break;
	}
      
      if( end && phase >= end)
	{ i = 64; }
      if(i == 64)
	*p++ = '=';
      if(i == 63)
	*p++ = '/';
      if(i == 62)
	*p++ = '+';
      if(i >= 52 && i < 62)
	*p++ = '0' + i - 52;
      if(i >= 26 && i < 52)
	*p++ = 'a' + i - 26;
      if(i >= 0 && i < 26)
	*p++ = 'A' + i;
      if(phase == 3) phase = 0;
      else phase++;
    }
  *p = 0;
  return out_string;
}

char *strtobase64(char *ascii_string)
{
  int n = strlen(ascii_string);
  int v, i, phase, end;
  unsigned int c;
  unsigned char *s = (unsigned char*) ascii_string;
  char *p = (char*)malloc(n*2+2);
  char *out_string;
  out_string = p;
  
  end = v = i = c = phase = 0;
  while(!end || phase > 0)
    {
      if( (!*s) && (!end)) end = phase+1;
      if(*s && (phase < 3))
	c = *s++;
      else
	c = 0;
      
      switch(phase)
	{
	case 0:
	  i = (c >> 2);
	  v = c;
	  break;
	case 1:
	  i = ((c & 0xf0)>>4) + ((v & 3) << 4);
	  v = c;
	  break;
	case 2:
	  i = ((v & 0xf)<<2) + ( (c & 255) >> 6);
	  v = c;
	  break;
	case 3:
	  i = v & 0x3f;
	  break;
	}
      
      if( end && phase >= end)
	{ i = 64; }
      if(i == 64)
	*p++ = '=';
      if(i == 63)
	*p++ = '/';
      if(i == 62)
	*p++ = '+';
      if(i >= 52 && i < 62)
	*p++ = '0' + i - 52;
      if(i >= 26 && i < 52)
	*p++ = 'a' + i - 26;
      if(i >= 0 && i < 26)
	*p++ = 'A' + i;
      if(phase == 3) phase = 0;
      else phase++;
    }
  *p = 0;
  return out_string;
}


unsigned char *base64tostr(const char *in_string, int *opt_len)
{
  return base64ntostr(in_string, opt_len, strlen(in_string));
}

unsigned char *base64ntostr(const char *in_string, int *opt_len, int len)
{
  const unsigned char *s = (unsigned char*) in_string;
  unsigned char *ascii_string;
  int v, i, phase;
  unsigned char *p;
  p = malloc(len+1);
  ascii_string = p;
  v = i = phase = 0;
  while(*s && len--)
    {
      unsigned int c = *s++;
      i = -1;
      if(c >= 'A' && c <= 'Z')
	i = c - 'A';
      if(c >= 'a' && c <= 'z')
	i = c - 'a' + 26;
      if(c >= '0' && c <= '9')
	i = c - '0' + 52;
      if(c == '+')
	i = 62;
      if(c == '/')
	i = 63;
      if(i >= 0)
	{
	  switch(phase)
	    {
	    case 0:
	      v = i;
	      break;
	    case 1:
	      *p++ = (v << 2) + ((i & 0x30) >> 4);
	      v = i << 4;
	      break;
	    case 2:
	      *p++ = v + (i >> 2);
	      v = i & 3;
	      break;
	    case 3:
	      *p++ = (v << 6) + i;
	      phase = -1;
	      break;
	    }
	  phase++;
	}
      *p = 0;
    }
  if(opt_len) *opt_len = p-ascii_string;
  return ascii_string;
}

#ifdef TEST
#include <stdio.h>
int main()
{
  char *b, *s = strdup("hejarne");
  int len = strlen(s);
  
  b = strtobase64(s);
  printf("%s -> %s\n", s, base64tostr(b, NULL));
  b = bintobase64(s, len);
  printf("%s -> %s\n", s, base64tostr(b, NULL));
  *s=0;
  b = bintobase64(s, len);
  printf("%s -> %s\n", s+1, base64tostr(b, NULL)+1);
  return 0;
}
#endif
