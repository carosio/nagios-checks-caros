/*
* check_radius_adv - Nagios(r) radius plugin
* Copyright (C) 2006 Gerd Mueller / Netways GmbH
* $Id: check_iftraffic.pl 1125 2006-02-16 12:56:34Z gmueller $
*
* based on radauth.c  1.00  01/13/01  mmiller@hick.org  Matt Miller
*
* Send us bug reports, questions and comments about this plugin.
* Latest version of this software: http://www.nagiosexchange.org
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307
*/


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>
#include <regex.h>

#include "md5.h"

#define DEBUGx

#define MAX_BUFFER 255
#define MAX_COLS 6

/*
 * Radius codes we'll need.
 */
#define CODE_ACCESS_REQUEST	1
#define CODE_ACCESS_ACCEPT	2
#define	CODE_ACCESS_REJECT	3

/*
 * Radius attribute types we'll need.
 */
#define	ATTR_TYPE_USER_NAME			1
#define ATTR_TYPE_USER_PASSWORD		2
#define ATTR_TYPE_VENDOR_SPECIFIC	26

/*
 * Data types for attributes
 */
#define DATATYPE_STRING		1
#define DATATYPE_ADDRESS		2
#define DATATYPE_INTEGER		3
#define DATATYPE_TIME		4
#define DATATYPE_VENDOR		26

/*
 * radius's port (so is it 1812 or 1645?)
 * RFC says 1812, my server is 1645...
 */
#define RADIUS_PORT		1812

/* 
 * Request Authenticator defs
 */
#define REQ_AUTH_LENGTH		16

/*
 * default auth timeout (seconds)
 */
#define AUTH_TIMEOUT		30

typedef struct vendor_nvalue {					/* all written		*/
	union {
		int address;			/* 4   octets		*/
		int integer;			/* 4   octets		*/
		int time;			/* 4   octets		*/
	} value;
} VENDOR_NATTR;

typedef struct vendor {
			int32_t id;			/*  4 octets */
			unsigned char type; 	/* 1 octet */
			unsigned char length; /*1 octet */
			unsigned char value[254];	/* 254 octets		*/
		} VENDOR_ATTR;

typedef struct radius_attr_st {
	unsigned char attr_type;		/* 1 octet (written)	*/
	unsigned char attr_length;		/* 1 octet (written)	*/
	union {					/* all written		*/
		unsigned char string[254];	/* 254 octets		*/
		int address;			/* 4   octets		*/
		int integer;			/* 4   octets		*/
		int time;			/* 4   octets		*/
		VENDOR_ATTR vendor;
	} attr_data;

	unsigned int datatype;			/* 4   octets (IGNORED)	*/
	struct radius_attr_st *next;		/* 4   octets (IGNORED)	*/
} RADIUS_ATTR;					

typedef struct radius_header_st {
	unsigned char 	rad_code;		  /* 1  octet		*/
	unsigned char 	rad_id;			  /* 1  octet		*/
	short 		rad_length;		  /* 2  octets		*/
	unsigned char 	rad_auth[REQ_AUTH_LENGTH];/* 16 octets		*/
	RADIUS_ATTR	*rad_attr;		  /* variable octets	*/
} RADIUS_HEADER;

typedef struct radius_rc {
	unsigned char 	rad_code;
	unsigned char 	rad_id;
	short			rad_length;
	unsigned char 	rad_auth[REQ_AUTH_LENGTH];
} RADIUS_RC_HEADER;

typedef struct global_st {
	char username[254];			/* username at suggested size			*/

	struct password_st {
		unsigned char pw_clear[128];	/* clear text password (128 = max)		*/
		unsigned char pw_hash[128];	/* hash password (128 = max)			*/
	} password;

	char sharedsecret[32];			/* shared secret				*/
	char radiusserver[128];			/* radius server				*/
	unsigned int radiusport;		/* radius port					*/
	unsigned int authtimeout;		/* authentication timeout			*/
	
	char customattributes[256];
	unsigned char okstate;
    unsigned char errorcode;
	char replymsg[MAX_BUFFER];

	int verbose;
} GLOBAL;

GLOBAL global;					/* global variables 				*/

#define LEGAL_SIZE(x) sizeof((x))-1		/* calculate useable string space		*/

void fnInitialize();
void fnGatherInformation();
void fnPrintInformation();
void fnPrintHelp(char *cmd);
void fnGeneratePacket(RADIUS_HEADER *radhead);
int fnGeneratePasswordHash(RADIUS_HEADER *radhead);
void fnGenerateRequestAuthenticator(unsigned char *auth);
void fnCreateAttribute(RADIUS_HEADER *radhead, unsigned char attr_type, unsigned char attr_length, int data_type, void *attr_value);
void fnCalculateHeaderLength(RADIUS_HEADER *radhead);
void fnPrintHash(unsigned char *,int);
void fnSendAndReceivePacket(RADIUS_HEADER *radhead);
unsigned char escape_semicolons(char *buffer, unsigned char maxlen);

int main(int argc, char **argv)
{
	RADIUS_HEADER radhead;			/* radius header to be sent out			*/
	int c;
	
	fnInitialize(&radhead);			/* initialize the header and global variables	*/

	global.okstate=2;               /* default okstate: ACCESS GRANTED (2) */
    global.errorcode=2;             /* default non-okstate causes CRITICAL */

	while ((c = getopt(argc, argv, "hvu:p:s:r:c:t:a:o:e:m:")) != EOF)
	{
		switch (c)
		{
			case 'v':		/* enable verbose output			*/
				global.verbose = 1;
				break;
			case 'u': {		/* set username					*/
				unsigned char len = escape_semicolons(optarg,LEGAL_SIZE(global.username));
				memcpy(global.username,optarg,len+1);
				break;
			}
			case 'p': {		/* set cleartext password			*/
				unsigned char len = escape_semicolons(optarg,LEGAL_SIZE(global.password.pw_clear));
				memcpy(global.password.pw_clear,optarg,len+1);
				break;
			}
			case 's': {		/* set shared secret				*/
				unsigned char len = escape_semicolons(optarg,LEGAL_SIZE(global.sharedsecret));
				memcpy(global.sharedsecret,optarg,len+1);
				break;
			}
			case 'r':		/* set radius server				*/
				strncpy(global.radiusserver,optarg,LEGAL_SIZE(global.radiusserver));
				break;
			case 'c':		/* set server port				*/
				global.radiusport = atoi(optarg);

				if ((global.radiusport <= 0) || (global.radiusport >= 65535))
					global.radiusport = RADIUS_PORT;

				break;
			case 't':		/* set auth timeout value			*/
				global.authtimeout = atoi(optarg);

				if ((global.authtimeout <= 0) || (global.authtimeout >= 65535))
					global.authtimeout = AUTH_TIMEOUT;
				break;
			case 'a':		/* set custom attributes 			*/
				strncpy(global.customattributes,optarg,LEGAL_SIZE(global.customattributes));
				break;
			case 'o':		/* set ok state	*/
				global.okstate=atoi(optarg);
				break;
            case 'e':       /* set ok state */
                global.errorcode=atoi(optarg);
                break;
			case 'm': {		/* set ok replymsg	*/
				unsigned char len = escape_semicolons(optarg,LEGAL_SIZE(global.replymsg));
				memcpy(global.replymsg,optarg+1,len);
				global.replymsg[len]=0;
				break;
			}
			case 'h':		/* print help menu				*/
				fnPrintHelp(argv[0]);
		}
	}

	fnGatherInformation();			/* read user/pass/shared secret/server info from stdin 	*/

	if (global.verbose)			/* if verbose is on, print verification information	*/
		fnPrintInformation();

	fnGeneratePacket(&radhead);		/* generate our radius packet				*/

	fnSendAndReceivePacket(&radhead);	/* send the radius packet to the server			*/

	return 1;
}

/*
 * fnInitialize
 *
 * This function is responsible for initializing the global structure as well
 * as clearing the radius header.
 *
 */

void fnInitialize(RADIUS_HEADER *radhead)
{
	memset(&global,0,sizeof(GLOBAL));
	memset(radhead,0,sizeof(RADIUS_HEADER));

	radhead->rad_attr = NULL;

	global.radiusport = RADIUS_PORT;	/* set default port				*/
	global.authtimeout = AUTH_TIMEOUT;	/* set default auth timeout			*/

	srand(time(NULL));			/* seed random with current time		*/

	return;
}

/*
 * fnGatherInformation
 *
 * Read username/password/shared secret/server information from stdin.
 *
 */

void fnGatherInformation()
{
	if (!global.username[0])		/* if username isn't set, ask for it	*/
	{
		fprintf(stdout,"\nEnter Username: ");
		fflush(stdout);
		
		fgets(global.username,LEGAL_SIZE(global.username),stdin);
		global.username[strlen(global.username)-1] = 0;
		escape_semicolons(global.username,LEGAL_SIZE(global.username));
	}

	if (!global.password.pw_clear[0]) {	/* if password isn't set, ask for it	*/
#ifdef SUNOS
		strncpy(global.password.pw_clear,getpassphrase("\nEnter Password: "),LEGAL_SIZE(global.password.pw_clear));
#else
		strncpy((char *)global.password.pw_clear,getpass("\nEnter Password: "),LEGAL_SIZE(global.password.pw_clear));
#endif
		escape_semicolons(global.password.pw_clear,LEGAL_SIZE(global.password.pw_clear));
	}
	
	if (!global.sharedsecret[0]) {		/* if shared secret isn't set, ask for it 	*/
#ifdef SUNOS
		strncpy(global.sharedsecret,getpassphrase("\nEnter shared secret: "),LEGAL_SIZE(global.sharedsecret));
#else
		strncpy(global.sharedsecret,getpass("\nEnter shared secret: "),LEGAL_SIZE(global.sharedsecret));
#endif
		escape_semicolons(global.sharedsecret,LEGAL_SIZE(global.sharedsecret));
	}
	
	if (!global.radiusserver[0])		/* if radius server isn't set, ask for it	*/
	{
		fprintf(stdout,"\nEnter Radius Server: ");
		fflush(stdout);

		fgets(global.radiusserver,LEGAL_SIZE(global.radiusserver),stdin);
		global.radiusserver[strlen(global.radiusserver)-1] = 0;

		if (global.radiusserver[0] == 0)	/* if still not set, abort	*/
		{
			fprintf(stdout,"no radius server defined, aborting.\n");

			exit(3);
		}
	}

	
/*
	fprintf(stdout,"\n");
*/

	return;
}

/*
 * fnPrintInformation
 *
 * Print the information the person entered so that there's no question as to
 * whether or not there was a typo.
 *
 */

void fnPrintInformation()
{
	fprintf(stdout,"\nUsing the following information\n");
    fprintf(stdout,"%s","-------------------------------\n");
	fprintf(stdout,"username:                 %-*s\n",global.username[0],global.username+1);
	fprintf(stdout,"password:                 %-*s\n",global.password.pw_clear[0],global.password.pw_clear+1);
	fprintf(stdout,"shared secret:            %-*s\n",global.sharedsecret[0],global.sharedsecret+1);
	fprintf(stdout,"server:                   %s\n",global.radiusserver);
	fprintf(stdout,"path of attributes file : %s\n\n",global.customattributes);

	return;
}

/*
 * fnPrintHelp
 *
 * Print the help menu.
 *
 */

void fnPrintHelp(char *cmd)
{
	fprintf(stdout,"check_radius_adv  \n");
	fprintf(stdout,"  Usage: # %s [OPTIONS]...\n\n",cmd);
	fprintf(stdout,"\tOPTIONS\n");
	fprintf(stdout,"\t-v\t\t\tverbose (output with verification)\n");
	fprintf(stdout,"\t-u [username]\t\tcleartext username\n");
	fprintf(stdout,"\t-p [password]\t\tcleartext password\n");
	fprintf(stdout,"\t-s [shared secret]\tshared secret for RADIUS server\n");
	fprintf(stdout,"\t-r [radius server]\tradius server to auth\n");
	fprintf(stdout,"\t-c [radius port]\tradius server port (default: 1812)\n");
	fprintf(stdout,"\t-t [auth timeout]\tinterval to wait until auth timeout in seconds (default: 30 sec.)\n");
	fprintf(stdout,"\t-a [attributes]\t\tfilename of the attributes file (see samplefile)\n");
	fprintf(stdout,"\t-o [ok state]\t\tauth reply code which will return ok state (default: 2 = accepted)\n");
    fprintf(stdout,"\t-e [error code]\t\tplugin error-code in case reply code differs (default: 2 = critical)\n");
	fprintf(stdout,"\t-m [replymsg]\t\texpected replymsg (type=18) (default: \"\", not checking)\n");
	fprintf(stdout,"\t-h\t\t\tthis menu\n");

	exit(3);
}

/*
 * fnGeneratePacket
 *
 * Generate the packet to be sent to the radius server
 *
 */

void fnGeneratePacket(RADIUS_HEADER *radhead)
{
	int hashpwlen = 0;
	FILE * fp;
	char buffer[MAX_BUFFER];
	char atype;
	char value[MAX_BUFFER];
	
	VENDOR_ATTR vendor;
	VENDOR_NATTR nvendor;

	radhead->rad_code = CODE_ACCESS_REQUEST;	/* set our radius code to Access-Request	*/
	radhead->rad_id	  = (getpid()%253) + 1;		/* set our rad id to the current process pid
							   modulas 253 + 1				*/

	fnGenerateRequestAuthenticator(radhead->rad_auth); /* Generate authenticator field		*/
	hashpwlen = fnGeneratePasswordHash(radhead);	/* Generate hashed password			*/

	/* Create the attributes, User-Name and User-Password 	*/
	fnCreateAttribute(radhead,ATTR_TYPE_USER_NAME,2 + global.username[0],DATATYPE_STRING,global.username+1);
	fnCreateAttribute(radhead,ATTR_TYPE_USER_PASSWORD,2 + hashpwlen,DATATYPE_STRING,global.password.pw_hash);
	
	/* read custom attributes */
	if(global.customattributes[0]) {
		fp=fopen(global.customattributes,"r");

		/* open worked? */
		if(fp) {
			/* read lines */

			while (fgets(buffer, MAX_BUFFER, fp) != NULL) {
				
				/* ignor comments */
				
				if(buffer[0]!='#' && (buffer[1])) {
					
			        regex_t regex;
        				regmatch_t regex_pmatch[MAX_COLS];
        				char dummy[MAX_BUFFER];
        				char pattern[]="([0-9]+)[ \t]+([0-9]+)[ \t]+([0-9]+)[ \t]+([aistAIST]+)[ \t]*(.*)";

					/* remove lf */
					buffer[strlen(buffer)-1]=0;
					
					memset(regex_pmatch,0,sizeof(regmatch_t)*MAX_COLS);
			 
        			if(regcomp(&regex,pattern,REG_EXTENDED)==0 &&
        				   regexec(&regex,buffer,MAX_COLS,regex_pmatch,0)==0) {
		
						int dtype=0;
						int attrib;
						
			 			memset(&vendor,0,sizeof(vendor));

						memset(dummy,0,MAX_BUFFER);
						strncpy (dummy, buffer + regex_pmatch[1].rm_so,regex_pmatch[1].rm_eo - regex_pmatch[1].rm_so);
						attrib=atoi(dummy);

						memset(dummy,0,MAX_BUFFER);
						strncpy (dummy, buffer + regex_pmatch[2].rm_so,regex_pmatch[2].rm_eo - regex_pmatch[2].rm_so);
						vendor.id=htonl(atol(dummy)); 

						memset(dummy,0,MAX_BUFFER);
						strncpy (dummy, buffer + regex_pmatch[3].rm_so,regex_pmatch[3].rm_eo - regex_pmatch[3].rm_so);
						vendor.type=atoi(dummy);
						
						strncpy (dummy, buffer + regex_pmatch[4].rm_so,regex_pmatch[4].rm_eo - regex_pmatch[4].rm_so);
						atype=buffer[regex_pmatch[4].rm_so];

			 			memset(value,0,sizeof(value));
						strncpy (value, buffer + regex_pmatch[5].rm_so,regex_pmatch[5].rm_eo - regex_pmatch[5].rm_so);
						
						switch(tolower(atype)) {
							case 's': {
								unsigned char len = escape_semicolons(value,LEGAL_SIZE(buffer));
								dtype=DATATYPE_STRING;
								vendor.length=len+2;
								memcpy(vendor.value,value+1,len);
								break;
							}
							case 'i':
								dtype=DATATYPE_INTEGER;
								vendor.length=4+2; 
								nvendor.value.integer=htonl(atol(value));
								break;
							case 'a':
								dtype=DATATYPE_ADDRESS;
								nvendor.value.address=inet_addr(value);
								vendor.length=4+2;
								break;
							case 't':
								dtype=DATATYPE_TIME;
								vendor.length=4+2;
								if(strcmp(value,"")) 
									nvendor.value.time=htonl(atol(value));
								else {
									time_t clock;
									clock=time(NULL); 
									nvendor.value.time=htonl(clock);
									strcpy(value,"actual time");
								}
								break;
							default:
								continue;
								break;
						}
	
						
						/* Vendor-specific Attribute? */
						if(vendor.id) {					
							if (global.verbose)			/* if verbose is on, print verification information	*/
								fprintf(stdout,"Type: %5i\tVendor-ID: %5u\tVendor-Type: %5i\tAttribute-Type: %c => [%s] %d\n",attrib,htonl(vendor.id),vendor.type,atype,value,nvendor.value.integer);

							if(dtype!=DATATYPE_STRING) {
								memcpy(vendor.value,&nvendor,sizeof(VENDOR_NATTR));
							}							
							fnCreateAttribute(radhead,attrib,vendor.length+6,DATATYPE_VENDOR,&vendor);
						} else {
							
							if (global.verbose)			/* if verbose is on, print verification information	*/
								fprintf(stdout,"Type: %5i\t\t\t\t\t\t\tAttribute-Type: %c => [%s]\n",attrib,atype,value);

							if(dtype!=DATATYPE_STRING) {
								memcpy(vendor.value,&nvendor.value,sizeof(int));
							}							
							fnCreateAttribute(radhead,attrib,vendor.length,dtype,&vendor.value);
			
						}
					} else {
						if (global.verbose)			/* if verbose is on, print verification information	*/
							fprintf(stdout,"Wrong format. Ignored line! [%s]\n",buffer);
	
        				}
			        regfree(&regex);					
				}
				memset(buffer,0,MAX_BUFFER);
			}
			fclose(fp);
		/* opened faile => file does not exist => abort */
		} else {
			fprintf(stdout,"cannot open attributes file, aborting.\n");
			
			exit(3);
		}		
	}

	/* Calculate the radius header length			*/
	fnCalculateHeaderLength(radhead);

#ifdef DEBUG	/* Print debug information if debugging		*/
	fprintf(stdout,"rad_code = %i\n",radhead->rad_code);
	fprintf(stdout,"rad_id   = %i\n",radhead->rad_id);
	fprintf(stdout,"hashpwlen= %i\n",hashpwlen);
	fnPrintHash(global.password.pw_hash,hashpwlen);
	fprintf(stdout,"rad_length = %i\n",radhead->rad_length);
#endif
}

/*
 * fnGenerateRequestAuthenticator
 *
 * Generates a 16 octet string with pseudo-random numbers.
 * I had issues with actually using large random numbers, as radius seems to
 * not like packets that aren't full (or something).  I switched to something
 * sure for randomness and made every field a mininum of 127.
 *
 */

void fnGenerateRequestAuthenticator(unsigned char *auth)
{
	int x, randnumb;

	for (x = 0; x < REQ_AUTH_LENGTH;x++)	/* until then end of auth field has been reached 	*/
	{
		randnumb = rand()%128+127;
#ifdef DEBUG
		fprintf(stdout,"randnumb is = %i\n",randnumb);
#endif
		auth[x] = randnumb;
	}

	return;
}

/*
 * fnGeneratePasswordHash
 *
 * This generates the users password hashed with the shared secret.  A
 * more indepth description on how this is done can be found in RFC 2138
 *
 */

int fnGeneratePasswordHash(RADIUS_HEADER *radhead)
{
	unsigned char b[8][16], p[8][16], c[8][16];
	unsigned char ssra[49];
	int currlen = 0, pwlen = global.password.pw_clear[0], bpos = 0, ppos = 0, cpos = 0, x, sslen;

	/* clear our storage arrays */
	memset(b,0,128);	
	memset(p,0,128);
	memset(c,0,128);
	memset(ssra,0,49);

	sslen = global.sharedsecret[0];

	/* concatenate the shared secret and the radius authenticator field */
	// snprintf((char *)ssra,48,"%s%s",global.sharedsecret,radhead->rad_auth);
	memcpy(ssra,global.sharedsecret+1,global.sharedsecret[0]);
	memcpy(ssra+global.sharedsecret[0],radhead->rad_auth,48-global.sharedsecret[0]);

	/* do the follow atleast once */
	do
	{
		/* copy the, in 16 octet blocks, the users clear text password
		 * starting at position 0 in the clear text password array.
		 */
		memcpy((char *)p[ppos],(char *)global.password.pw_clear+currlen+1,16);
	
		/* if the current length of the hashed password is not set,
		 * that means this is our first time through.  Therefore we
		 * calculate our first hash value (stored in b[0]) with the
		 * concatenated shared secret and radius authenticator.
		 */
		if (!currlen)
			md5_calc(b[0],ssra,sslen + REQ_AUTH_LENGTH);
		/* if this isn't our first time through, we must caculate our
		 * next hash value based off the shared secert concatentated
		 * XOR'd version of the clear text password and the original
		 * hash.
		 */
		else
		{
			// snprintf((char *)ssra,48,"%s%s",global.sharedsecret,c[cpos]);
			memcpy(ssra,global.sharedsecret+1,global.sharedsecret[0]);
			memcpy(ssra+global.sharedsecret[0],c[cpos],48-global.sharedsecret[0]);
			 
			md5_calc(b[bpos],ssra,sslen + REQ_AUTH_LENGTH);

			cpos++;
		}

		/* from 0 to 16, XOR the clear text password with the hashed
		 * md5 output
		 */
		for (x = 0; x < 16; x++)
			c[cpos][x] = p[ppos][x] ^ b[bpos][x];

		/* increment out password position and temp position */
		bpos++; ppos++;

		currlen += 16;
	} while (currlen < pwlen); 

	x = 0;

	/* as long as the cipher block is valid, concatenate it onto our hash
	 * password
	 */
	while ((x <= 8) && (c[x][0]))
	{
		memcpy(global.password.pw_hash+(x*16),c[x],16);

		x++;
	}

	return currlen;
}

/*
 * fnCreateAttribute
 *
 * Responsible for adding an attribute which will be located in the attributes
 * field of the radius header.
 *
 */

void fnCreateAttribute(RADIUS_HEADER *radhead, unsigned char attr_type,unsigned char attr_length, int data_type, void *attr_value)
{
	RADIUS_ATTR *curr = radhead->rad_attr;	
	int *intval = (int *)attr_value;

	if (!curr)	/* if there aren't any attributes set, create the first one	*/
	{
		radhead->rad_attr = (RADIUS_ATTR *)malloc(sizeof(RADIUS_ATTR));
		curr = radhead->rad_attr;
	}
	else		/* otherwise find the last position and append to it		*/
	{
		while (curr->next)
			curr = curr->next;

		curr->next = (RADIUS_ATTR *)malloc(sizeof(RADIUS_ATTR));
		curr = curr->next;
	}

	if (!curr)		/* malloc failure.	*/
	{
		fprintf(stderr,"malloc failure, abort.\n");

		exit(3);
	}

	curr->next = NULL;

	curr->attr_type   = attr_type;		/* set the attribute type		*/
	curr->attr_length = attr_length;	/* set the attribute length		*/
	curr->datatype   = data_type;		/* set the attribute datatype.  this
						   value is NOT sent to the radius server*/

	switch (data_type)			/* copy based on our datatype		*/
	{
		case DATATYPE_STRING:
			memcpy(curr->attr_data.string,attr_value,LEGAL_SIZE(curr->attr_data.string)-1);
			break;
		case DATATYPE_ADDRESS: 
			curr->attr_data.address = *intval;
			break;
		case DATATYPE_INTEGER: 
			curr->attr_data.integer = *intval;	
			break;
		case DATATYPE_TIME:
			curr->attr_data.time = *intval;
			break;
		case DATATYPE_VENDOR:
			memcpy(&curr->attr_data.vendor,(VENDOR_ATTR *)attr_value,sizeof(VENDOR_ATTR));
			break;
	}

	return;
}

/*
 * fnCalculateHeaderLength
 *
 * Calculates the radius header length once everything is established.
 *
 */

void fnCalculateHeaderLength(RADIUS_HEADER *radhead)
{
	int headlength = 20;	/* smallest header is 20 bytes	code(1) + id(1) + length(2) + auth(16) */
	RADIUS_ATTR *curr = radhead->rad_attr;

	while (curr)		/* until we reach the end of our attributes, keep adding		*/	
	{
		headlength += curr->attr_length;

#ifdef DEBUG
		fprintf(stdout,"attr length = %i\n",curr->attr_length);
#endif

		curr = curr->next;
	}

	radhead->rad_length = headlength;	/* set the final length					*/

	return;
}

/*
 * fnPrintHash
 *
 * Prints the hexidecimal version of the md5 hash'd password.  This is a debug
 * function only.
 *
 */

#ifdef DEBUG
void fnPrintHash(unsigned char *hash, int len)
{
	int x = 0;

	fprintf(stdout,"hash: ");

	for (;x < len;x++)
		fprintf(stdout,"%02x",hash[x]);

	fprintf(stdout,"\n");

	return;
}
#endif

/*
 * fnSendAndReceivePacket
 *
 * Send our radius header to the server and wait for a reply
 *
 */

void fnSendAndReceivePacket(RADIUS_HEADER *radhead)
{
	RADIUS_RC_HEADER rad_rc;
	void *rad_rc_attribs=NULL;
	unsigned char * pos;
	int act_pos=0;
	char replymsg[MAX_BUFFER];

	RADIUS_ATTR *curr = radhead->rad_attr;
	unsigned char packet[radhead->rad_length];
	int pktpos = 0, sock;
	unsigned int slen;
	struct sockaddr_in s;
	struct hostent *h;
	struct timeval tv;
	fd_set fdread;
	char rw[MAX_BUFFER];
	int rc;
	struct timeval start,stop;
	double diff;
	
	gettimeofday(&start,NULL); 
	
	/* clear the packet to be sent */
	memset(packet,0,radhead->rad_length);

	/* copy the first 20 bytes of the radius header.  this size is static
	 * per RFC.
	 */
	radhead->rad_length=(htons(radhead->rad_length));
	memcpy(packet,(char *)radhead,20);		

	/* set the current position in the packet to 20 */
	pktpos = 20;


	/* until we reach the end of our attributes, do the following	*/
	while (curr)	
	{
		/* copy the first 2 bytes of the attribute field (type
		 * and length) 
		 */
		memcpy(packet+pktpos,curr,2);	

		/* increment the packet position by 2 */
		pktpos += 2;

		/* copy to the packet and increment depending on our datatype
		 */
		switch (curr->datatype)
		{
			case DATATYPE_STRING:
				memcpy(packet+pktpos,curr->attr_data.string,curr->attr_length-2);
				pktpos += curr->attr_length-2;
				break;
			case DATATYPE_ADDRESS:
				memcpy(packet+pktpos,&curr->attr_data.address,curr->attr_length-2);
				pktpos += curr->attr_length-2;
				break;
			case DATATYPE_INTEGER:
				memcpy(packet+pktpos,&curr->attr_data.integer,curr->attr_length-2);
				pktpos += curr->attr_length-2;
				break;
			case DATATYPE_TIME:
				memcpy(packet+pktpos,&curr->attr_data.time,curr->attr_length-2);
				pktpos += curr->attr_length-2;
				break;
			case DATATYPE_VENDOR:
				memcpy(packet+pktpos,&curr->attr_data.vendor,curr->attr_length-2);
				pktpos += curr->attr_length-2;
				break;
		}

		curr = curr->next;
	}

	/* create UDP socket */
	if ((sock = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP)) <= 0)
	{
		fprintf(stdout,"unable to allocate udp socket, abort.\n");

		exit(3);
	}

	s.sin_family = AF_INET;
	s.sin_addr.s_addr = inet_addr(global.radiusserver);
	s.sin_port = htons(global.radiusport);

	if (s.sin_addr.s_addr == -1)
	{
		if (!(h = gethostbyname(global.radiusserver)))
		{
			fprintf(stdout,"unable to resolve radius server: %s. abort.\n",global.radiusserver);

			exit(3);
		}

		memcpy(&s.sin_addr.s_addr,h->h_addr,h->h_length);
	}

	/* send the packet to the radius server */

	if (sendto(sock,(char *)packet,htons(radhead->rad_length),0,(struct sockaddr *)&s,sizeof(s)) < 0)
	{
		fprintf(stdout,"error sending UDP packet to radius server. abort.\n");

		exit(3);
	}

/*	fprintf(stdout,"Authentication request sent to %s:%i ... (timeout = %i)\n",global.radiusserver,global.radiusport,global.authtimeout);
*/

	slen = sizeof(s);

	FD_ZERO(&fdread);
	FD_SET(sock,&fdread);

	tv.tv_sec = global.authtimeout;
	tv.tv_usec = 0;

	/* if nothing is received in 30 seconds, authentication has failed. */
	if (!select(sock + 1, &fdread, NULL, NULL, &tv))
	{
		fprintf(stdout,"failed to receive a reply from the server, authentication FAILED.\n");
		exit(2);

		return;
	}
	
	/* otherwise receive the packet and calculate the ret code */
	recvfrom(sock,&rad_rc,sizeof(RADIUS_RC_HEADER),MSG_PEEK,(struct sockaddr *)&s,&slen);

	rad_rc.rad_length=ntohs(rad_rc.rad_length);

	if(rad_rc.rad_length-sizeof(RADIUS_RC_HEADER)) {

		rad_rc_attribs = malloc(rad_rc.rad_length);
		if (!rad_rc_attribs)		/* malloc failure.	*/
		{
			fprintf(stderr,"malloc failure, abort.\n");
			exit(3);
		}
		
		recvfrom(sock,rad_rc_attribs,rad_rc.rad_length,0,(struct sockaddr *)&s,&slen);
		pos=rad_rc_attribs+sizeof(RADIUS_RC_HEADER);
		act_pos=sizeof(RADIUS_RC_HEADER);
	
		do {
			unsigned char type=*pos;
			unsigned char length=*(pos+1);
			
			memset(replymsg,0,MAX_BUFFER);
			memcpy(replymsg,(pos+2),length-2);
			
			if (global.verbose)			/* if verbose is on, print verification information	*/
				fprintf (stdout,"Reply-Msg t=%d l=%d: %s\n",type,length,replymsg); 

			if(type==18) break;

			pos+=length;
			act_pos+=length;
		
		
		} while (act_pos<rad_rc.rad_length);
	}
	

	switch (rad_rc.rad_code)
	{
		case 2:		/* Access-Accept	*/
			strcpy(rw,"Access ACCEPT.");
			break;
		case 3:		/* Access-Reject	*/
			strcpy(rw,"Access REJECT.");
			break;
		case 11:
			strcpy(rw,"callenge issued, ignored.");
			break;
		default:
			strcpy(rw,"unknown code..");
			break;
	}

	if(global.okstate!=rad_rc.rad_code) {
        rc=global.errorcode;
        if(rc==1) {
		  fprintf(stdout,"WARNING: ");
        } else {
          fprintf(stdout,"CRITICAL: ");
        } 
	} else {
		if ((!*global.replymsg) || (strncmp(global.replymsg,replymsg,strlen(global.replymsg))==0 && strlen(global.replymsg) == strlen(replymsg))) {
			fprintf(stdout,"OK: ");
			rc=0;
		} else {
			fprintf(stdout,"WARNING: Reply-Msg differs! ('%s' != '%s') ",global.replymsg,replymsg);
			rc=1;
		}
	}
	
	gettimeofday(&stop,NULL);
	
	if(rad_rc_attribs) free(rad_rc_attribs);

	diff = -0.0000001 + (stop.tv_sec - start.tv_sec) +
      		((1.0 + stop.tv_usec - start.tv_usec) / 1000000.0);
	fprintf(stdout,"%s (code = %i) | rtt=%.4lf rttms=%.4lf \n",rw,rad_rc.rad_code,diff,diff*1000.0);


	exit(rc);
	return;
}

unsigned char escape_semicolons(char *buffer, unsigned char maxlen){
	int len = 0;
	int pos = 0;
	int x = 0;
	char hex[3];
	int  val;
	
	hex[2]=0;
	
	len = (int)strlen(buffer);
	
	for(pos=0;pos<len && pos < 255 && x < maxlen;pos++) {
		if(buffer[pos]=='/' && pos+1<len) {
			if(buffer[pos+1]=='/') {
				pos++;
			} else if(buffer[pos+1]=='n') {
				buffer[++pos]='\n';
			} else if(buffer[pos+1]=='t') {
				buffer[++pos]='\t';
			} else if(buffer[pos+1]=='x' && pos+3<len) {
				hex[0]=buffer[pos+2];
				hex[1]=buffer[pos+3];
				sscanf(hex,"%x",&val);
				pos+=3;
				buffer[pos]=(char)val;
			} else {
				continue;
			}
		}
		buffer[x]=buffer[pos];
		x++;
	}
	
	// convert buffer from c-style to pascal-style to support null-characters as well
	memmove(buffer+1,buffer,x);
	buffer[0]=x;

	return x;
}

