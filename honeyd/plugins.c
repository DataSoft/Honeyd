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

#include <sys/param.h>
#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/queue.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <dirent.h>

#include "plugins_config.h"
#include "plugins.h"


/* All plugins are simply stored in an array, as
 * we don't have to access them very often -- any direct
 * interactions with the plugin are set up by the plugins
 * themselves via hooks as defined in hooks.h.
 */

HONEYD_PLUGINS_DECLARE;

struct honeyd_plugin *plugins[] = {
	HONEYD_PLUGINS NULL
};

/* The following are the dummy operations we always hook
 * into newly created plugins
 */

static int
plugin_dummy_init(void)
{
	return 0;
}

/**
 * plugin_hook_up - hooks in symbols from dlopenend modules.
 * @plugin: plugin to hook up.
 *
 * The function tries to hook the callback functions that
 * define a plugin's characteristics into the @plugin structure,
 * then initializes the plugin. Note that the callbacks are
 * all initialized with dummy operations so even if we encounter
 * a bad plugin, we should still be safe.
 */

static void       
plugin_hook_up(struct honeyd_plugin *plugin)
{
	const struct honeyd_plugin_cfg *cfg;

	if (plugin->name == NULL)
		plugin->name = "Unnamed plugin.";
	if (plugin->description == NULL)
		plugin->description = "No description given.";
	if (plugin->author == NULL)
		plugin->author = "No author(s) specified.";
	if (plugin->version == NULL)
		plugin->version = "No version specified.";
	if (plugin->init == NULL)
		plugin->init = plugin_dummy_init;

	cfg = plugins_config_find_item(plugin->name, "enable", HD_CONFIG_INT);
	if (cfg == NULL || cfg->cfg_int == 0)
		return;

	syslog(LOG_INFO, "registering plugin '%s' (%s)",
	       plugin->name, plugin->version);
	
	plugin->init();
}

void
plugins_init(void)
{
	struct honeyd_plugin *plugin, **iter = plugins;

	for (plugin = *iter; plugin; plugin = *++iter)
		plugin_hook_up(plugin);
}


struct honeyd_plugin * 
plugins_find(const char *name)
{
	struct honeyd_plugin *plugin, **iter = plugins;

	for (plugin = *iter; plugin; plugin = *++iter) {
		if (strcasecmp(name, plugin->name) == 0)
			return (plugin);
	}

	return (NULL);
}
