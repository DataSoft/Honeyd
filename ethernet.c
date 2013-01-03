/*
 * Copyright (c) 2004 Niels Provos <provos@citi.umich.edu>
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

#include <sys/types.h>
#include <sys/param.h>
#include <stdint.h>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/tree.h>
#include <syslog.h>

#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <string.h>
#include <ctype.h>

#include <dnet.h>

#include "ethernet.h"

struct etherindex {
	SPLAY_ENTRY(etherindex) node;

	char *index_word;

	struct ethernetcode **list;
	size_t list_size;
	size_t list_mem;
};

struct ethernetcode {
	uint32_t prefix;
	char *vendor;
	int count;
};

static SPLAY_HEAD(ethertree, etherindex) etherroot;

static int
compare(struct etherindex *a, struct etherindex *b)
{
	return (strcmp(a->index_word, b->index_word));
}

SPLAY_PROTOTYPE(ethertree, etherindex, node, compare);

SPLAY_GENERATE(ethertree, etherindex, node, compare);

static int
ethernetcode_index(struct ethertree *etherroot, struct ethernetcode *code)
{
	struct etherindex tmp, *entry;
	char line[1024], *p, *e;

	//printf("Adding %d:%s\n", code->prefix, code->vendor);

	strlcpy(line, code->vendor, sizeof(line));
	e = line;

	/* Walk through every single word and index it */
	while ((p = strsep(&e, " ")) != NULL) {
		tmp.index_word = p;
		if ((entry = SPLAY_FIND(ethertree, etherroot, &tmp)) == NULL) {
			/* Generate a new entry for this word */
			entry = calloc(1, sizeof(struct etherindex));
			if (entry == NULL)
			{
				syslog(LOG_ERR, "%s: calloc, failed to allocate new entry for the current word", __func__);
				exit(EXIT_FAILURE);
			}
				//err(1, "%s: calloc", __func__);

			if ((entry->index_word = strdup(p)) == NULL)
			{
				syslog(LOG_ERR, "%s: strdup", __func__);
				exit(EXIT_FAILURE);
			}
				//err(1, "%s: strdup", __func__);

			entry->list_mem = 32;
			if ((entry->list = calloc(entry->list_mem,
					sizeof(struct ethernetcode *))) == NULL)
			{
				syslog(LOG_ERR, "%s: calloc",__func__);
				exit(EXIT_FAILURE);
			}
				//err(1, "%s: calloc");

			SPLAY_INSERT(ethertree, etherroot, entry);
		}

		if (entry->list_size >= entry->list_mem) {
			struct ethernetcode **tmp;

			/* We require more memory for this key word */
			entry->list_mem <<= 1;
			tmp = realloc(entry->list,
					entry->list_mem * sizeof(struct ethernetcode *));
			if (tmp == NULL)
			{
				syslog(LOG_ERR, "%s: realloc", __func__);
				exit(EXIT_FAILURE);
			}
				//err(1, "%s: realloc", __func__);
			entry->list = tmp;
		}

		entry->list[entry->list_size++] = code;
	}

	return (0);
}
/*
void
ethernetcode_init(void)
{
	struct ethernetcode *code = &codes[0];

	SPLAY_INIT(&etherroot);

	while (code->vendor != NULL) {
		printf("Vendor name is: %s \n", code->vendor);
		printf("the prefix is: %x \n", code->prefix);
		fflush(stdout);
		ethernetcode_index(&etherroot, code);

		++code;
	}
}
*/

void ethernetcode_init(void){//16080 lines counting the 5 comments at the top
	char s[300];//string that contains the current line being read
	char waste[300];//string used to read first five lines of the text file
	char c;
	struct ethernetcode *currentCode;
	struct ethernetcode *codes;
	int counter = 0;
	int numOfLine = 0;
	uint32_t prefix;
	FILE *in_file  = fopen("/usr/share/nova/sharedFiles/nmap-mac-prefixes", "r"); // read only

	if (!in_file)//file pointer is null
	{
		printf("File can't be found\n");
		exit(-1);
	}

	while(fgets( s, 300, in_file ) != NULL)
	{
		numOfLine++;//get the number of lines to dynamically allocate the codes array
	}

	//printf("Found %d lines in the file\n", numOfLine);

	if(numOfLine > 0)
	{
		codes = (struct ethernetcode *)malloc(numOfLine * sizeof(struct ethernetcode));
		currentCode = codes;
	}
	else
	{
		printf("nmap-mac-prefixes file cannot be parsed.");
		exit(EXIT_FAILURE);
	}
	rewind(in_file);//go back to the beginning of the file


	do//used to skip first five lines
	{
		fgets( waste, 300, in_file );
		//skips through first 5 garbage lines
		counter++;
	}while(counter < 5);


	SPLAY_INIT(&etherroot);
	//while there is another line, continue reading
	while (fgets( s, 300, in_file ) != NULL)
	{
		char routerID[10];
		char routerCompany[80];
		//should read in the router numbers/characters
		int i;
		for(i = 0; i < 10; i++)
		{
			c = s[i];
			if(c != ' ')
				{
					routerID[i] = c;
				}
			else
				{
					routerID[i] = '\0';

					break;
				}
		}
		int j;
		int companyNameStart = 0;
		int firstSpaceFound = 0;
		for(j = 0; j < 300; j++)
		{
			c = s[j];

			if(c >=65 && c <= 90)//converts uppercase to lower case
			{
				c = c + 32;
		    }

			if(companyNameStart > 0)
			{
			routerCompany[j-companyNameStart] = c; //we start adding the company name here
			}
			if(c == ' ' && firstSpaceFound == 0)
			{
				firstSpaceFound = 1;
				companyNameStart = j+1;
				//turn flag on and a counter to 1
			}


			if(s[j] == '\0' || s[j] == '\n')
			{
				routerCompany[j-companyNameStart] = '\0';
				break;//quit loop because we reached the end of the string/current line
			}

		}



		prefix = 0;
		sscanf(routerID, "%x", &prefix);
		currentCode->prefix = prefix;
		currentCode->vendor = routerCompany;
		ethernetcode_index(&etherroot, currentCode);
		++currentCode;//move on to the next struct

	}
	fclose(in_file);
}


/*
 * Returns the code that matches the best, 0 on error.
 */

static uint32_t
ethernetcode_find_best(struct etherindex **results, int size, int random)
{
	extern rand_t *honeyd_rand;
	int i, j, max = 0, count = 0;
	struct ethernetcode *code = NULL;

	if (!size)
		return (0);

	/* Reset the counters */
	for (i = 0; i < size; i++) {
		struct etherindex *ei = results[i];
		for (j = 0; j < ei->list_size; j++)
			ei->list[j]->count = 0;
	}

	for (i = 0; i < size; i++) {
		struct etherindex *ei = results[i];
		for (j = 0; j < ei->list_size; j++) {
			ei->list[j]->count++;
			if (ei->list[j]->count > max) {
				max = ei->list[j]->count;
				code = ei->list[j];
				count = 1;
			} else if (ei->list[j]->count == max && random) {
				/* Randomly select one of the best matches */
				count++;
				if (rand_uint8(honeyd_rand) % count == 0)
					code = ei->list[j];
			}
		}
	}

	return (code->prefix);
}

uint32_t
ethernetcode_find_prefix(char *vendor, int random) {
	struct etherindex *results[20];
	struct etherindex tmp, *entry;
	char line[1024], *p, *e;
	int pos = 0;

	strlcpy(line, vendor, sizeof(line));
	e = line;

	/* Walk through every single word and find the codes for it */
	while ((p = strsep(&e, " ")) != NULL && pos < 20) {
		int i;

		/* Change the string to lower case for the match */
		for (i = 0; i < strlen(p); i++)
			p[i] = tolower(p[i]);

		tmp.index_word = p;
		if ((entry = SPLAY_FIND(ethertree, &etherroot, &tmp)) == NULL)
			continue;

		results[pos++] = entry;
	}

	return (ethernetcode_find_best(results, pos, random));
}

struct addr *
ethernetcode_make_address(char *vendor)
{
	extern rand_t *honeyd_rand;
	uint32_t prefix = 0;
	u_char address[ETH_ADDR_LEN], *p;
	struct addr *ea;
	int i;

	/* Check if it is a regular mac address: xx:xx:xx:xx:xx:xx */
	p = address;
	for (i = 0; i < strlen(vendor) && p < address + ETH_ADDR_LEN; i += 3) {
		char hex[3];

		if (!isxdigit(vendor[i]) || !isxdigit(vendor[i+1]))
			break;

		hex[0] = vendor[i];
		hex[1] = vendor[i+1];
		hex[2] = '\0';

		*p++ = strtoul(hex, NULL, 16);

		if (i + 2 < strlen(vendor) && vendor[i + 2] != ':')
			break;
	}

	/* We could not parse the hex digits, so search for a vendor instead */
	if (p < address + ETH_ADDR_LEN) {
		if ((prefix = ethernetcode_find_prefix(vendor, 1)) == 0)
		{
			return (NULL);
		}

		/* We have a 24-bit prefix that is vendor dependant */
		address[2] = prefix & 0xff; prefix >>= 8;
		address[1] = prefix & 0xff; prefix >>= 8;
		address[0] = prefix & 0xff; prefix >>= 8;

		if (prefix != 0)
			return (NULL);

		for (i = 3; i < ETH_ADDR_LEN; i++)
			address[i] = rand_uint8(honeyd_rand);
	}

	if ((ea = calloc(1, sizeof(struct addr))) == NULL)
		return (NULL);

	addr_pack(ea, ADDR_TYPE_ETH, ETH_ADDR_BITS, address, ETH_ADDR_LEN);

	return (ea);
}

struct addr *
ethernetcode_clone(struct addr *src)
{
	extern rand_t *honeyd_rand;
	struct addr *ea;
	int i;

	if ((ea = calloc(1, sizeof(struct addr))) == NULL)
		return (NULL);

	memcpy(ea, src, sizeof(struct addr));

	/* Very low-level hack, might break when dnet changes */
	for (i = 3; i < ETH_ADDR_LEN; i++)
		ea->addr_data8[i] = rand_uint8(honeyd_rand);

	return (ea);
}

#define TEST(x, y) do { \
		if (ethernetcode_find_prefix(x, 0) != (y)) \
		errx(1, "%s: %s does not match %.6x", __func__, x, y); \
} while (0)

void
ethernetcode_test(void)
{
	TEST("cisco", 0x00000c);
	TEST("netkit solutions", 0x0003b8);
	TEST("juniper networks", 0x000585);
	TEST("cooperative linux virtual nic", 0x00ffd1);
	TEST("zzzzzzzz xxxxxxxx", 0x000000);

	fprintf(stderr, "\t%s: OK\n", __func__);
}

void
ethernet_test(void)
{
	ethernetcode_init();

	ethernetcode_test();
}
