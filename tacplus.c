/*-
 * Copyright (c) 2023 Klara, Inc.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <err.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <taclib.h>

/* missing in FreeeBSD < 14.0 */
#ifndef TAC_AUTHEN_TYPE_NOT_SET
#define TAC_AUTHEN_TYPE_NOT_SET	0x00
#endif

static int method	 = TAC_AUTHEN_METH_NOT_SET;
static int type		 = TAC_AUTHEN_TYPE_NOT_SET;
static int service	 = TAC_AUTHEN_SVC_NONE;
static bool verbose;

struct lookup {
	const char	*key;
	int		 val;
};

static const struct lookup methods[] = {
	{ "notset",	TAC_AUTHEN_METH_NOT_SET },
	{ "none",	TAC_AUTHEN_METH_NONE },
	{ "krb5",	TAC_AUTHEN_METH_KRB5 },
	{ "line",	TAC_AUTHEN_METH_LINE },
	{ "enable",	TAC_AUTHEN_METH_ENABLE },
	{ "local",	TAC_AUTHEN_METH_LOCAL },
	{ "tacacsplus",	TAC_AUTHEN_METH_TACACSPLUS },
	{ "rcmd",	TAC_AUTHEN_METH_RCMD },
	{ 0 }
};

static const struct lookup types[] = {
	{ "notset",	TAC_AUTHEN_TYPE_NOT_SET },
	{ "ascii",	TAC_AUTHEN_TYPE_ASCII },
	{ "pap",	TAC_AUTHEN_TYPE_PAP },
	{ "chap",	TAC_AUTHEN_TYPE_CHAP },
	{ "arap",	TAC_AUTHEN_TYPE_ARAP },
	{ "mschap",	TAC_AUTHEN_TYPE_MSCHAP },
	{ 0 }
};

static const struct lookup services[] = {
	{ "none",	TAC_AUTHEN_SVC_NONE },
	{ "login",	TAC_AUTHEN_SVC_LOGIN },
	{ "enable",	TAC_AUTHEN_SVC_ENABLE },
	{ "ppp",	TAC_AUTHEN_SVC_PPP },
	{ "arap",	TAC_AUTHEN_SVC_ARAP },
	{ "pt",		TAC_AUTHEN_SVC_PT },
	{ "rcmd",	TAC_AUTHEN_SVC_RCMD },
	{ "x25",	TAC_AUTHEN_SVC_X25 },
	{ "nasi",	TAC_AUTHEN_SVC_NASI },
	{ "fwproxy",	TAC_AUTHEN_SVC_FWPROXY },
	{ 0 }
};

static int
lookup(const struct lookup *table, const char *key)
{
	while (table->key) {
		if (strcmp(table->key, key) == 0)
			return (table->val);
		table++;
	}
	return (-1);
}

static void
usage(void)
{
	fprintf(stderr, "usage: tacplus [-v] [-m method] [-s service] [-t type] "
	    "[attr=value [...]] name\n");
	fprintf(stderr, "\nmethod  = ");
	for (int i = 0; methods[i].key; i++)
		fprintf(stderr, i > 0 ? ", %s" : "%s", methods[i].key);
	fprintf(stderr, "\nservice = ");
	for (int i = 0; services[i].key; i++)
		fprintf(stderr, i > 0 ? ", %s" : "%s", services[i].key);
	fprintf(stderr, "\ntype    = ");
	for (int i = 0; types[i].key; i++)
		fprintf(stderr, i > 0 ? ", %s" : "%s", types[i].key);
	fprintf(stderr, "\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct tac_handle *h;
	const char *name;
	char *av;
	int opt, ret;

	while ((opt = getopt(argc, argv, "m:s:t:v")) != -1) {
		switch (opt) {
		case 'm':
			if ((method = lookup(methods, optarg)) < 0)
				usage();
			break;
		case 's':
			if ((service = lookup(services, optarg)) < 0)
				usage();
			break;
		case 't':
			if ((type = lookup(types, optarg)) < 0)
				usage();
			break;
		case 'v':
			verbose = true;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1)
		usage();
	name = argv[argc - 1];

	/* initialize library */
	if ((h = tac_open()) == NULL)
		err(1, "tac_open()");
	if (tac_config(h, NULL) != 0)
		err(1, "tac_config()");

	/* create authorization request */
	if (tac_create_author(h, method, type, service) < 0)
		errx(1, "tac_create_author(): %s", tac_strerror(h));

	/* add user name */
	if (tac_set_user(h, name) < 0)
		errx(1, "tac_set_user(): %s", tac_strerror(h));

	/* add av pairs */
	while (argc > 1) {
		if (strchr(*argv, '=') == NULL)
			usage();
		if (tac_set_av(h, 0, *argv) < 0)
			errx(1, "tac_set_av(): %s", tac_strerror(h));
		argc--;
	}

	/* send request */
	if ((ret = tac_send_author(h)) < 0)
		errx(1, "tac_send_author(): %s", tac_strerror(h));

	/* check response */
	switch (TAC_AUTHOR_STATUS(ret)) {
	case TAC_AUTHOR_STATUS_PASS_ADD:
		if (verbose)
			fprintf(stderr, "authorization passed (add)\n");
		break;
	case TAC_AUTHOR_STATUS_PASS_REPL:
		if (verbose)
			fprintf(stderr, "authorization passed (replace)\n");
		break;
	case TAC_AUTHOR_STATUS_FAIL:
		errx(1, "authorization failed");	
	case TAC_AUTHOR_STATUS_ERROR:
		errx(1, "server error");
	default:
		errx(1, "unrecognized server response: %#x",
		    TAC_AUTHOR_STATUS(ret));
	}

	/* print attributes */
	if (verbose) {
		for (int i = 0; i < TAC_AUTHEN_AV_COUNT(ret); i++) {
			if ((av = tac_get_av(h, i)) == NULL)
				errx(1, "tac_get_av(%d): %s", i, tac_strerror(h));
			fprintf(stderr, "%2d %s\n", i, av);
			free(av);
		}
	}

	/* clean up */
	tac_close(h);
	exit(0);
}
