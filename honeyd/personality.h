/*
 * Copyright (c) 2002, 2003, 2004 Niels Provos <provos@citi.umich.edu>
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
#ifndef _PERSONALITY_H_
#define _PERSONALITY_H_

enum ackchange { ACK_KEEP = 0, ACK_ZERO, ACK_DECREMENT };

struct personate {
	int window;
	u_char flags;
	u_char df;
	char *options;
	enum ackchange forceack;
};

enum rval { RVAL_OKAY = 0, RVAL_ZERO, RVAL_BAD };

struct persudp {
	uint8_t response;
	uint8_t tos;
	uint8_t df;
	enum rval rid;
	enum rval ripck;
	enum rval uck;
	enum rval dat;
	int riplen;
	int quotelen;
};

#define WHITESPACE	" \t\n"
#define XPRINT		"fingerprint {"
#define FINGERPRINT	"Fingerprint"
#define CMP(y,x)	strncasecmp(y, x, sizeof(x) -1)
#define ID_MAX		1024

/* ---------------------------------------------------------------------------
 * ET - This was designed and added by the students for Xprobe integration
 */

struct xp_fp_flags {
	/* Module A: ICMP ECHO Probe */
	unsigned icmp_echo_code:1;                 // 0 == 0, 1 == !0
	unsigned icmp_echo_ip_id:1;                // 0 == 0, 1 == !0
	unsigned icmp_echo_tos_bits:1;             // 0 == 0, 1 == !0
	unsigned icmp_echo_df_bit:1;               // 0 == 0, 1 == !0
	/* Module B: ICMP Timestamp Probe */
	unsigned icmp_timestamp_reply:1;           // 1 == yes, 0 == no
	/* Module C: ICMP Address Mask Request Probe */
	unsigned icmp_addrmask_reply:1;            // 1 == yes, 0 == no
	/* Module D: ICMP Information Request Probe */
	unsigned icmp_info_reply:1;                // 1 == yes, 0 == no
	/* Module E: UDP -> ICMP Unreachable */
	unsigned icmp_unreach_echoed_dtsize:3;     // [8 (001), 64 (010), >64 (100)]
	unsigned icmp_unreach_precedence_bits:8;   // 0xc0, 0, (hex num)
	unsigned icmp_unreach_df_bit:1;            // [0 , 1]
	unsigned icmp_unreach_echoed_udp_cksum:3;  // [0 (001), OK (010), BAD (100)]
	unsigned icmp_unreach_echoed_ip_cksum:3;   // [0 (001), OK (010), BAD (100)]
	unsigned icmp_unreach_echoed_ip_id:2;      // [OK (01), FLIPPED (10)]
	unsigned icmp_unreach_echoed_total_len:3;  // [>20 (001), OK (010), <20 (100)]
	unsigned icmp_unreach_echoed_3bit_flags:2; // [OK (01), FLIPPED (10)]
};

struct ttl_pair {
                             //together: [>< decimal num]
	unsigned gt_lt:2;    // > == 01, < == 10
	unsigned ttl_val:9;   //ttl value (max TTL size is 9 bits)
};

struct xp_fp_ttlvals {
	struct ttl_pair icmp_echo_reply_ttl;      //Module A
	struct ttl_pair icmp_timestamp_reply_ttl; //Module B
	struct ttl_pair icmp_addrmask_reply_ttl;  //Module C
	struct ttl_pair icmp_info_reply_ttl;      //Module D
	struct ttl_pair icmp_unreach_reply_ttl;   //Module E
};

struct xp_fingerprint {
	SPLAY_ENTRY(xp_fingerprint) node;
	char                 *os_id;   //OS name
	struct xp_fp_flags   flags;    //everything else
	struct xp_fp_ttlvals ttl_vals; //ttl values
};

/* ------------------------------------------------------------------- */

/* JVR - improve IPID sequencing capability */
enum ipidtype {ID_SEQUENTIAL, ID_RANDOM, ID_SEQUENTIAL_BROKEN, ID_ZERO,
               ID_CONSTANT, ID_RPI};
enum seqtype {SEQ_CLASS64K, SEQ_RI, SEQ_TRIVIALTIME, SEQ_RANDOM,
	      SEQ_CONSTANT, SEQ_I800};
enum fragpolicy {FRAG_OLD = 0, FRAG_DROP, FRAG_NEW};

#define SEQ_TRIVIALTIME_MAX	75
#define SEQ_RI_MAX		0xD7CAB8

struct personality {
	SPLAY_ENTRY(personality) node;
	char *name;

	struct personate tests[7];
	struct persudp udptest;

	/* DC & CK added XProbe structures */
	struct xp_fingerprint *xp_fprint;

	/* The three IPID type tests */
	enum ipidtype IPID_type_TI;
	enum ipidtype IPID_type_CI;
	enum ipidtype IPID_type_II;

	uint32_t IPID_constant_val_TI;
	uint32_t IPID_constant_val_CI;
	uint32_t IPID_constant_val_II;

	int ipid_shared_sequence;

	uint8_t valset:1,
	        unused:7;

	/* Used for constant ISNs */
	uint32_t TCP_ISN_constant_val;

	/* TCP ISN gcd */
	uint32_t gcd;

	/* Upper and lower bound for TCP ISN Counter Rate (ISR)*/
	uint32_t TCP_ISR_min;
	uint32_t TCP_ISR_max;

	/* Upper and lower bound for TCP ISN Sequence Predictability Index (SP)*/
	uint32_t TCP_SP_min;
	uint32_t TCP_SP_max;


	uint32_t seqindex_min;
	uint32_t seqindex_max;

	double seqindex_amin;	/* Values calculated from seqindex_{min,max} */
	double seqindex_amax;
	double seqindex_aconst;

	enum seqtype seqt;
        int tstamphz;		/* -1 indicates undefined */

	enum fragpolicy fragp;

	uint8_t disallow_finscan:1,
		reserved:7;
};

void personality_init(void);
int personality_parse(FILE *);
struct personality *personality_find(const char *);
struct personality *personality_clone(const struct personality *);
void personality_declone(struct personality *pers);
struct personality *personality_random(void);
void personality_free(struct personality *);

void ip_personality(struct template *, uint16_t *);
int tcp_personality(struct tcp_con *, uint8_t *, int *, int *,
    uint16_t *, char **);
void tcp_personality_options(struct tcp_con *, struct tcp_hdr *, char *);
int tcp_personality_match(struct tcp_con *, int);

int icmp_error_personality(struct template *, struct addr *,
    struct ip_hdr *ip, uint8_t *, uint8_t *, int *, uint8_t *);

/* ET - This functions loads the Xprobe fingerprints */
int xprobe_personality_parse(FILE *fp);
void xprobe_personality_init(void);
void print_perstree(void);

/* Splay stuff here so other modules can use it */
SPLAY_HEAD(perstree, personality) personalities;
static int
perscompare(struct personality *a, struct personality *b)
{
  return (strcmp(a->name, b->name));
}
SPLAY_PROTOTYPE(perstree, personality, node, perscompare);

SPLAY_HEAD(xp_fprint_tree, xp_fingerprint) xp_fprints;
static int 
xp_fprint_compare(struct xp_fingerprint *a, struct xp_fingerprint *b)
{
  return (strcmp(a->os_id, b->os_id));
}
SPLAY_PROTOTYPE(xp_fprint_tree, xp_fingerprint, node, xp_fprint_compare);

#endif
