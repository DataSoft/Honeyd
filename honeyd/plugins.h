/*
 * Copyright 2003 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * <LICENSEHERE>
 */
/*
 * Copyright 2003 Christian Kreibich <christian.kreibich@cl.cam.ac.uk>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef _PLUGINS_H_
#define _PLUGINS_H_

/* A Honeyd plugin -- it can implement a few hooks to
 * give some info about itself, and most importantly an
 * init function to register itself against any hooks
 * in the system the plugin is interested in.
 */
struct honeyd_plugin
{
	const char *name;
	const char *description;
	const char *author;
	const char *version;
	
	int         (*init) (void);
};

/**
 * plugins_init - initializes registered plugins.
 *
 * The function hooks in all installed plugins for honeyd and
 * initializes them. For each successfully registered plugin,
 * a message is printed to syslogd.
 */
void    plugins_init(void);


/**
 * plugins_find - looks up a plugin by name.
 * @name: name of plugin to find.
 *
 * The function tries to find a registered plugin whose name() method's
 * result matches @name, case-insensitively. If no such plugin can
 * be found, %NULL is returned.
 *
 * Returns: plugin, or %NULL if not found.
 */
struct honeyd_plugin * plugins_find(const char *name);

#endif
