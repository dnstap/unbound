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

#ifndef UNBOUND_DNSTAP_H
#define UNBOUND_DNSTAP_H

#include "dnstap/dnstap_config.h"

#ifdef USE_DNSTAP

struct config_file;
struct fstrm_io;
struct fstrm_queue;

struct dt_env {
	/** dnstap I/O socket */
	struct fstrm_io *fio;

	/** dnstap I/O queue */
	struct fstrm_queue *fq;

	/** dnstap "identity" field, NULL if disabled */
	char *identity;

	/** dnstap "version" field, NULL if disabled */
	char *version;

	/** length of "identity" field */
	unsigned len_identity;

	/** length of "version" field */
	unsigned len_version;

	/** whether to log Message/RESOLVER_QUERY */
	unsigned log_resolver_query_messages : 1;
	/** whether to log Message/RESOLVER_RESPONSE */
	unsigned log_resolver_response_messages : 1;
	/** whether to log Message/CLIENT_QUERY */
	unsigned log_client_query_messages : 1;
	/** whether to log Message/CLIENT_RESPONSE */
	unsigned log_client_response_messages : 1;
	/** whether to log Message/FORWARDER_QUERY */
	unsigned log_forwarder_query_messages : 1;
	/** whether to log Message/FORWARDER_RESPONSE */
	unsigned log_forwarder_response_messages : 1;
};

/**
 * Create dnstap environment object. Afterwards, call dt_apply_cfg() to fill in
 * the config variables and dt_init() to fill in the per-worker state. Each
 * worker needs a copy of this object but with its own I/O queue (the fq field
 * of the structure) to ensure lock-free access to its own per-worker circular
 * queue.  Duplicate the environment object if more than one worker needs to
 * share access to the dnstap I/O socket.
 * @param socket_path: path to dnstap logging socket, must be non-NULL.
 * @param num_workers: number of worker threads, must be > 0.
 * @return dt_env object, NULL on failure.
 */
struct dt_env *
dt_create(const char *socket_path, unsigned num_workers);

/**
 * Apply config settings.
 * @param env: dnstap environment object.
 * @param cfg: new config settings.
 */
void
dt_apply_cfg(struct dt_env *env, struct config_file *cfg);

/**
 * Initialize per-worker state in dnstap environment object.
 * @param env: dnstap environment object to initialize, created with dt_create().
 * @return: true on success, false on failure.
 */
int
dt_init(struct dt_env *env);

/**
 * Delete dnstap environment object. Closes dnstap I/O socket and deletes all
 * per-worker I/O queues.
 */
void
dt_delete(struct dt_env *env);

#endif /* USE_DNSTAP */

#endif /* UNBOUND_DNSTAP_H */
