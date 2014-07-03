/*

gadoyanspam - a spam killer for qmail.
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
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>

#include "libdspam.h"

#define SPAM_TAG "-spam"
#define INNOCENT_TAG "-notspam"

int quarantine = 1;
int force_single = 0;
int drop_spam = 1;

void die_fail ()
{
	if (drop_spam) {
		exit (99);
	} else 
		exit (0);
}

void die_temp (char *message)
{
	fprintf(stderr, message);
	exit(111);
}

void save_maildir (char *path, char *message)
{
	time_t now = time (NULL);
	char hostname [512];
	pid_t pid = getpid ();
	char *filename, *new;
	int filename_len;
	struct stat st;
	int fd;
	int ret;

	bzero (hostname, 512);
	if (gethostname (hostname, 512) != 0)
		strcpy (hostname, "localhost");

	mkdir (path, 0700);
	if (chdir (path) != 0)
		die_temp ("couldnt chdir() to maildir path");

	mkdir ("tmp", 0700);
	mkdir ("new", 0700);
	mkdir ("cur", 0700);

	for (;;sleep (2)) {
		filename_len =	4 + /* tmp/ */
						strlen (hostname) +
						20 + /* now */
						10 + /* pid */
						4; /* \0 */

		filename = malloc (filename_len);
		bzero (filename, filename_len);
		snprintf (filename, filename_len, "tmp/%d.%d.%s", (unsigned int) now, (int) pid, hostname);

		if (stat (filename, &st) == 0)
			continue;

		if ((fd = creat (filename, 0600)) == -1)
			die_temp ("couldn't create quarantine message");
		
		
		if ((ret = write (fd, message, strlen (message))) < 0) {
			die_temp ("couldn't write quarantine message");
		}

		fsync (fd);
		close (fd);
		break;
	}
	
	new = strdup (filename);
	if (new == NULL)
		die_temp ("no memory for new/");

	new [0] = 'n'; new [1] = 'e'; new [2] = 'w';

	link (filename, new);

	unlink (filename);
	free (filename);
	free (new);
}

int main (int argc, char **argv) 
{
	char buffer [1024];
	char *message = malloc (1);
	char *home = getenv ("HOME");
	char *spam_tag = NULL, *innocent_tag = NULL;
	char *local = NULL, *temp, *quarantine_path = NULL;
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
			{"quarantine", 1, 0, 0},
			{"no-quarantine", 0, 0, 0},
			{"deliver-spam", 0, 0, 0},
			{"force-single", 0, 0, 0},
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
			else if (strcmp ("quarantine", long_options[option_index].name) == 0) {
				if (optarg)
					quarantine_path = strdup (optarg);
			}
			else if (strcmp ("deliver-spam", long_options[option_index].name) == 0) {
				drop_spam = 0;
			}
			else if (strcmp ("force-single", long_options[option_index].name) == 0) {
				force_single = 1;
			}
			else if (strcmp ("no-quarantine", long_options[option_index].name) == 0) {
				quarantine = 1;
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

	if (getenv ("EXT") == NULL)
		die_temp ("$EXT is not set\n");

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
	
	if ((sublocal = strstr (local, innocent_tag)) != NULL) {
		if (force_single == 0) {
			local_len = strlen (local) - strlen (sublocal) + 1;
			local = malloc (local_len + 1);
			if (local == NULL)
				die_temp ("out of memory #sublocal innocent_tag\n");

			bzero (local, local_len + 1);
			snprintf (local, local_len, "%s", temp);
		}
		addspam = -1;
		if (temp)
			free (temp);
	} else if ((sublocal = strstr (local, spam_tag)) != NULL) {
		if (force_single == 0) {
			local_len = strlen (local) - strlen (sublocal) + 1;
			local = malloc (local_len + 1);
			if (local == NULL)
				die_temp ("out of memory #sublocal spam_tag\n");

			bzero (local, local_len + 1);
			snprintf (local, local_len, "%s", temp);
		}
		addspam = 1;
		if (temp)
			free (temp);
	}	

	if (force_single == 1) {
		local = strdup (getenv ("USER"));
		if (local == NULL) 
			die_temp ("out of memory #force_single");
	} 

	if (quarantine) {
		if (force_single) {
			if (quarantine_path == NULL)
				quarantine_path = strdup (spam_tag);

			if (quarantine_path == NULL)
				die_temp ("out of memory\n");

			temp = quarantine_path;

			i = strlen (home) + strlen (temp) + 2;
			quarantine_path = malloc (i);

			if (quarantine_path == NULL)
				die_temp ("out of memory\n");

			sprintf (quarantine_path, "%s/%s", home, temp);
			quarantine_path [i] = 0;
		} else {
			if (quarantine_path == NULL)
				quarantine_path = strdup (getenv ("EXT"));

			if (quarantine_path == NULL)
				die_temp ("out of memory\n");

			temp = quarantine_path;

			i = strlen (home) + strlen (temp) + strlen (spam_tag) + 2;
			quarantine_path = malloc (i);

			if (quarantine_path == NULL)
				die_temp ("out of memory\n");

			sprintf (quarantine_path, "%s/%s%s", home, temp, spam_tag);
			quarantine_path [i] = 0;
		}
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

	if (local)
		free (local);
	
	if (CTX == NULL) {
		die_temp ("failure initializing dspam\n");
	}

	if (dspam_process(CTX, message)!=0) 
		die_temp ("dspam_process failed\n"); 

	result = CTX->result;

	if (dspam_destroy(CTX)!=0) 
		die_temp ("dspam_destroy failed!\n");
	
	if (addspam) {
		free (message);
		return 0;
	}

	if (result == DSR_ISSPAM) {
		if (quarantine) {
			save_maildir (quarantine_path, message);
			free (quarantine_path);
		}
		die_fail ();
	}

	free (message);

	return 0;
}
