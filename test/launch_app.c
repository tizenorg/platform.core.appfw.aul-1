/*
Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved 
PROPRIETARY/CONFIDENTIAL
This software is the confidential and proprietary information of 
SAMSUNG ELECTRONICS ("Confidential Information"). You agree and acknowledge that 
this software is owned by Samsung and you 
shall not disclose such Confidential Information and shall 
use it only in accordance with the terms of the license agreement 
you entered into with SAMSUNG ELECTRONICS.  SAMSUNG make no 
representations or warranties about the suitability 
of the software, either express or implied, including but not 
limited to the implied warranties of merchantability, fitness for 
a particular purpose, or non-infringement. 
SAMSUNG shall not be liable for any damages suffered by licensee arising out of or 
related to this software.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#include <Ecore.h>
#include "aul.h"

#define ROOT_UID 0
#define TMP_FILE "/tmp/.testpkg"

static char **gargv;
static int gargc;

static bundle *create_internal_bundle(int start)
{
	bundle *kb;
	int i;

	kb = bundle_create();
	for (i = start; i < gargc - 1; i++) {
		if ((i + 1) > gargc - 1)
			bundle_add(kb, gargv[i], " ");
		else
			bundle_add(kb, gargv[i], gargv[i + 1]);
	}

	return kb;
}

int launch()
{
	bundle *kb = NULL;
	FILE *fp;
	int ret = -1;
	int pid = -1;

	kb = create_internal_bundle(2);
	if (NULL == kb) {
		printf("bundle creation fail\n");
		return -1;
	}

	pid = aul_launch_app(gargv[1], kb);

	if (kb) {
		bundle_free(kb);
		kb = NULL;
	}
	/* Write the package name to TMP_FILE*/
	fp = fopen(TMP_FILE, "w");
	if (fp == NULL)
		return -1;
	ret = fprintf(fp, "%d", pid);
	fclose(fp);
	if (ret < 0)
		return -1;

	return pid;
}

void print_usage(char *progname)
{
	printf("[usage] %s <pkgname> <key1> <val1> <key2> <val2> ...\n",
	       progname);
}

static Eina_Bool run_func(void *data)
{
	if (launch() > 0) {
		printf("... successfully launched\n");
	} else {
		printf("... launch failed\n");
	}

	ecore_main_loop_quit();

	return 0;
}

int main(int argc, char **argv)
{

	/* Checking the User ID*/
	if (getuid() != ROOT_UID) {
		fprintf(stderr, "permission error\n");
		exit(EXIT_FAILURE);
	}

	if (argc < 2) {
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	ecore_init();

	gargc = argc;
	gargv = argv;

	aul_launch_init(NULL, NULL);

	ecore_idler_add(run_func, NULL);

	ecore_main_loop_begin();

	return 0;
}

