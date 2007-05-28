/*
 * Copyright 2003 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>

#include "plugins_config.h"

struct honeyd_plugin_cfgitem {
	TAILQ_ENTRY(honeyd_plugin_cfgitem) next;

	char                       *plugin;
	char                       *option;
	struct honeyd_plugin_cfg    cfg;
};

TAILQ_HEAD(honeyd_plugin_cfg_lh, honeyd_plugin_cfgitem) cfg_items;


static void
plugins_cfg_copy(const struct honeyd_plugin_cfg *cfg_src,
    struct honeyd_plugin_cfg *cfg_dst)
{
	if (cfg_src == NULL|| cfg_dst == NULL)
		return;

	*cfg_dst = *cfg_src;
	
	if (cfg_src->cfg_type == HD_CONFIG_STR) {
		if ((cfg_dst->cfg_str = strdup(cfg_src->cfg_str)) == NULL)
			err(1, "%s: strdup", __func__);
	}      
}

void  
plugins_config_init(void)
{
	TAILQ_INIT(&cfg_items);
}

void  
plugins_config_item_add(const char *plugin, const char *option,
    const struct honeyd_plugin_cfg *cfg)
{
	struct honeyd_plugin_cfgitem *item;

	if (option == NULL|| cfg == NULL)
		return;

	if ((item = calloc(1, sizeof(struct honeyd_plugin_cfgitem))) == NULL)
		err(1, "%s: calloc", __func__);

	if ((item->plugin = strdup(plugin)) == NULL)
		err(1, "%s: strdup", __func__);
	if ((item->option = strdup(option)) == NULL)
		err(1, "%s: strdup", __func__);
	plugins_cfg_copy(cfg, &item->cfg);

	TAILQ_INSERT_HEAD(&cfg_items, item, next);
}


const struct honeyd_plugin_cfg  *
plugins_config_find_item(const char *plugin, const char *option,
    enum honeyd_plugin_cfgtype type)
{
	struct honeyd_plugin_cfgitem *item;

	if (plugin == NULL|| option == NULL)
		return (NULL);

	TAILQ_FOREACH(item, &cfg_items, next) {
		if (strcasecmp(plugin, item->plugin) == 0 &&
		    strcasecmp(option, item->option) == 0 &&
		    type == item->cfg.cfg_type)
			return (&item->cfg);
	}

	return (NULL);
}

