/* dnstap support for Unbound */

/*
 * Copyright (c) 2013-2014, Farsight Security, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "dnstap/dnstap_config.h"

#ifdef USE_DNSTAP

#include "config.h"
#include "util/config_file.h"
#include "util/log.h"

#include <fstrm.h>

#include "dnstap/dnstap.h"

struct dt_env *
dt_create(const char *socket_path, unsigned num_workers)
{
	char *fio_err;
	struct dt_env *env;
	struct fstrm_io_options *fopt;
	struct fstrm_unix_writer_options *fuwopt;

	verbose(VERB_OPS, "opening dnstap socket %s", socket_path);
	log_assert(socket_path != NULL);
	log_assert(num_workers > 0);

	env = (struct dt_env *) calloc(1, sizeof(struct dt_env));
	if (!env)
		return NULL;

	fuwopt = fstrm_unix_writer_options_init();
	fstrm_unix_writer_options_set_socket_path(fuwopt, socket_path);
	fopt = fstrm_io_options_init();
	fstrm_io_options_set_num_queues(fopt, num_workers);
	fstrm_io_options_set_writer(fopt, fstrm_unix_writer, fuwopt);
	env->fio = fstrm_io_init(fopt, &fio_err);
	if (env->fio == NULL) {
		verbose(VERB_DETAIL, "dt_create: fstrm_io_init() failed: %s",
			fio_err);
		free(fio_err);
		free(env);
		env = NULL;
	}
	fstrm_io_options_destroy(&fopt);
	fstrm_unix_writer_options_destroy(&fuwopt);

	return env;
}

static void
dt_apply_identity(struct dt_env *env, struct config_file *cfg)
{
	char buf[MAXHOSTNAMELEN+1];
	if (!cfg->dnstap_send_identity)
		return;
	free(env->identity);
	if (cfg->dnstap_identity == NULL || cfg->dnstap_identity[0] == 0) {
		if (gethostname(buf, MAXHOSTNAMELEN) == 0) {
			buf[MAXHOSTNAMELEN] = 0;
			env->identity = strdup(buf);
		} else {
			fatal_exit("dt_apply_identity: gethostname() failed");
		}
	} else {
		env->identity = strdup(cfg->dnstap_identity);
	}
	if (env->identity == NULL)
		fatal_exit("dt_apply_identity: strdup() failed");
	env->len_identity = strlen(env->identity);
	verbose(VERB_OPS, "dnstap identity field set to \"%s\"",
		env->identity);
}

static void
dt_apply_version(struct dt_env *env, struct config_file *cfg)
{
	if (!cfg->dnstap_send_version)
		return;
	free(env->version);
	if (cfg->dnstap_version == NULL || cfg->dnstap_version[0] == 0)
		env->version = strdup(PACKAGE_STRING);
	else
		env->version = strdup(cfg->dnstap_version);
	if (env->version == NULL)
		fatal_exit("dt_apply_version: strdup() failed");
	env->len_version = strlen(env->version);
	verbose(VERB_OPS, "dnstap version field set to \"%s\"",
		env->version);
}

void
dt_apply_cfg(struct dt_env *env, struct config_file *cfg)
{
	if (!cfg->dnstap)
		return;

	dt_apply_identity(env, cfg);
	dt_apply_version(env, cfg);
	if ((env->log_resolver_query_messages =
	     cfg->dnstap_log_resolver_query_messages))
	{
		verbose(VERB_OPS, "dnstap Message/RESOLVER_QUERY enabled");
	}
	if ((env->log_resolver_response_messages =
	     cfg->dnstap_log_resolver_response_messages))
	{
		verbose(VERB_OPS, "dnstap Message/RESOLVER_RESPONSE enabled");
	}
	if ((env->log_client_query_messages =
	     cfg->dnstap_log_client_query_messages))
	{
		verbose(VERB_OPS, "dnstap Message/CLIENT_QUERY enabled");
	}
	if ((env->log_client_response_messages =
	     cfg->dnstap_log_client_response_messages))
	{
		verbose(VERB_OPS, "dnstap Message/CLIENT_RESPONSE enabled");
	}
	if ((env->log_forwarder_query_messages =
	     cfg->dnstap_log_forwarder_query_messages))
	{
		verbose(VERB_OPS, "dnstap Message/FORWARDER_QUERY enabled");
	}
	if ((env->log_forwarder_response_messages =
	     cfg->dnstap_log_forwarder_response_messages))
	{
		verbose(VERB_OPS, "dnstap Message/FORWARDER_RESPONSE enabled");
	}
}

int
dt_init(struct dt_env *env)
{
	env->fq = fstrm_io_get_queue(env->fio);
	if (env->fq == NULL)
		return 0;
	return 1;
}

void
dt_delete(struct dt_env *env)
{
	if (!env)
		return;
	verbose(VERB_OPS, "closing dnstap socket");
	fstrm_io_destroy(&env->fio);
	free(env->identity);
	free(env->version);
	free(env);
}

#endif /* USE_DNSTAP */
