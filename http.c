/*
 * File: http.c
 * Implements:
 *
 * Copyright: Jens Låås, 2010
 * Copyright license: According to GPL, see file COPYING in this directory.
 *
 */

#include <curl/curl.h>
#include <curl/types.h>
#include <curl/easy.h>
#include <string.h>

#include "http.h"

size_t wrfunc( void *ptr, size_t size, size_t
		 nmemb, void *stream)
{
	return size*nmemb;
}

int http_post(const char *url, int timeout_ms,
	      const char *nonce, const char *host, const char *logfile,
	      const char *ivs, const char *msg, char **err)
{
	CURL *curl;
	CURLcode res = -1;
	long code=0;
	
	struct curl_httppost *formpost=NULL;
	struct curl_httppost *lastptr=NULL;
//	static const char buf[] = "Expect:";
	
	if(err) *err = NULL;
	
	curl_global_init(CURL_GLOBAL_ALL);
	
	/* Fill in the filename field */
	curl_formadd(&formpost,
		     &lastptr,
		     CURLFORM_COPYNAME, "nonce",
		     CURLFORM_COPYCONTENTS, nonce,
		     CURLFORM_END);
	curl_formadd(&formpost,
		     &lastptr,
		     CURLFORM_COPYNAME, "iv",
		     CURLFORM_COPYCONTENTS, ivs,
		     CURLFORM_END);
	curl_formadd(&formpost,
		     &lastptr,
		     CURLFORM_COPYNAME, "logfile",
		     CURLFORM_COPYCONTENTS, logfile,
		     CURLFORM_END);
	curl_formadd(&formpost,
		     &lastptr,
		     CURLFORM_COPYNAME, "host",
		     CURLFORM_COPYCONTENTS, host,
		     CURLFORM_END);
	curl_formadd(&formpost,
		     &lastptr,
		     CURLFORM_COPYNAME, "msg",
		     CURLFORM_COPYCONTENTS, msg,
		     CURLFORM_END);
	
	curl = curl_easy_init();
	if(curl) {
		
		/* what URL that receives this POST */
		curl_easy_setopt(curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);
		
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
		
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &wrfunc);
		
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, timeout_ms);
		
		res = curl_easy_perform(curl);

		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code );
		
		/* always cleanup */
		curl_easy_cleanup(curl);
		
		/* then cleanup the formpost chain */
		curl_formfree(formpost);
	}
	if(res) {
		if(err) *err = curl_easy_strerror(res);
		if( code >= 400 ) {
			char error[64];
			sprintf(error, "http resp code %ld\n", code);
			*err = strdup(error);
			res = -2;
		}
	}
	
	return res;
}
