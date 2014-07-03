/*

gadoyanspam - a dspam agent for qmail 
Mohammad DAMT [mdamt at bisnisweb dot com] 
(c) 2004, PT Cakram Datalingga Duaribu
   
This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "libdspam.h"

#define SPAM_TAG "-spam"
#define INNOCENT_TAG "-notspam"

int dot_qmail = 1;
int drop_spam = 1;

void die_fail ()
{
	if (drop_spam) {
		if (dot_qmail)
			exit (99);
		else
			exit (90); /* vmailmgr uses exit (90) to drop email? */
	} else 
		exit (0);
}

void die_temp (char *message)
{
	fprintf(stderr, message);
	exit(111);
}

int main (int argc, char **argv) 
{
	char buffer [1024];
	char *message = malloc (1);
	char *home = getenv ("HOME");
	char *spam_tag = NULL, *innocent_tag = NULL;
	char *local = NULL, *temp; 
	char *sublocal = NULL;
	int local_len = 0;
	long len = 1;
	int result = -1, i = 0;
	int addspam = 0;

	DSPAM_CTX *CTX;

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"spam-tag", 1, 0, 0},
			{"innocent-tag", 1, 0, 0},
			{"deliver-spam", 0, 0, 0},
			{"vmailmgr", 0, 0, 0},
			{0, 0, 0, 0}
		};

		i = getopt_long (argc, argv, "", long_options, &option_index);
		if (i == -1)
		break;

		if (i == 0) {
			if (strcmp ("spam-tag", long_options[option_index].name) == 0) {
				if (optarg)
					spam_tag = strdup (optarg);
			}
			else if (strcmp ("innocent-tag", long_options[option_index].name) == 0) {
				if (optarg)
					innocent_tag = strdup (optarg);
			}
			else if (strcmp ("deliver-spam", long_options[option_index].name) == 0) {
				drop_spam = 0;
			}
			else if (strcmp ("vmailmgr", long_options[option_index].name) == 0) {
				dot_qmail = 0;
			}
		}
	}
	
	if (spam_tag == NULL)
		spam_tag = strdup (SPAM_TAG);

	if (spam_tag == NULL) {
		if (innocent_tag)
			free (innocent_tag);
		die_temp ("spam-tag is empty");
	}
	
	if (innocent_tag == NULL)
		innocent_tag = strdup (INNOCENT_TAG);
	
	if (innocent_tag == NULL) {
		if (spam_tag)
			free (spam_tag);
		die_temp ("innocent-tag is empty");
	}
			
	if (strcmp (spam_tag, innocent_tag) == 0) {
		die_temp ("SPAM and FALSE POSITIVE can't have the same tag");
	}
	
	if (home == NULL)
		die_temp ("$HOME is not set\n");

	if ((temp = getenv ("LOCAL")) == NULL)
		die_temp ("$LOCAL is not set\n");
	
	local = strdup (temp);
	
	if (local == NULL)
		die_temp ("out of memory #0\n");

	temp = local;
	len = strlen (temp);
	if (len <= 0)
		die_temp ("$LOCAL is not set\n");
	
	while (i ++ < len) {
		temp [i] = tolower (temp [i]);
	}
	
	if ((sublocal = strstr (local, spam_tag)) != NULL) {
		temp = local;

		local_len = strlen (local) - strlen (sublocal) + 1;
		local = malloc (local_len + 1);
		if (local == NULL)
			die_temp ("out of memory #sublocal spam_tag\n");

		bzero (local, local_len + 1);
		snprintf (local, local_len, "%s", temp);
		addspam = 1;
	}	
	else if ((sublocal = strstr (local, innocent_tag)) != NULL) {
		temp = local;

		local_len = strlen (local) - strlen (sublocal) + 1;
		local = malloc (local_len + 1);
		if (local == NULL)
			die_temp ("out of memory #sublocal innocent_tag\n");

		bzero (local, local_len + 1);
		snprintf (local, local_len, "%s", temp);
		addspam = -1;
	}	

	free (innocent_tag);
	free (spam_tag);

	message [0] = 0;
	while (fgets (buffer, sizeof (buffer), stdin) != NULL) {
		len += strlen (buffer);
		message = realloc (message, len);
		if (message == NULL) 
			die_temp ("out of memory #message\n");
		strcat(message, buffer);
	}

	dspam_init_driver ();
	if (addspam == 1)
		CTX = dspam_init(local, NULL, DSM_ADDSPAM, DSF_CHAINED | DSF_IGNOREHEADER);
	else if (addspam == -1)
		CTX = dspam_init(local, NULL, DSM_FALSEPOSITIVE, DSF_CHAINED | DSF_IGNOREHEADER);
	else
		CTX = dspam_init(local, NULL, DSM_PROCESS, DSF_CHAINED);

	free (local);
	
	if (CTX == NULL) {
		die_temp ("failure initializing dspam\n");
	}

	if (dspam_process(CTX, message)!=0) 
		die_temp ("dspam_process failed\n"); 

	free (message);
	result = CTX->result;

	if (dspam_destroy(CTX)!=0) 
		die_temp ("dspam_destroy failed!\n");
	
	if (addspam)
		return 0;

	if (result == DSR_ISSPAM)
		die_fail ();

	return 0;
}
