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

#define DF1_FRAGMENT_OFFSET_MASK = 16384
#define DF0_FRAGMENT_OFFSET_MASK = 49151

//ACK_KEEP means ack# = sequence of probe+1
//ACK_DECREMENT means ack# = sequence of probe
//ACK_ZERO means ack# is 0
//ACK_OTHER means ack# is something else
enum ackchange { ACK_KEEP = 0, ACK_ZERO, ACK_DECREMENT, ACK_OTHER };

//SEQ_KEEP means seq# = ack of probe+1
//SEQ_DECREMENT means seq# = ack of probe
//SEQ_ZERO means seq# is 0
//SEQ_OTHER means seq# is something else
enum seqchange { SEQ_KEEP = 0, SEQ_ZERO, SEQ_DECREMENT, SEQ_OTHER };

//A struct to contain the TCP options
struct tcp_options
{
	//The number of options included below
	uint count;

	//A pointer to the first option
	struct tcp_option *options;
};

//A single TCP option in the options field
struct tcp_option
{
	//L == End of Options List
	//N = NOP
	//M = MSS
	//W = Window Scale
	//T = Timestamp
	//S = Selectinve ACK permitted
	char opt_type;

	//Used by M and W
	uint value;

	//Used by T only
	char TSval; //'0' or '1'
	char TSecr; //'0' or '1'
};
//NONE = "", RESERVED = "R", URGENT = "U", BOTH = "RU"
//These are the only options Q=<options> may contain
enum q_test {NONE = 0, RESERVED = 1, URGENT = 2, BOTH = 3};

struct personate {
	int window;
	u_char response; 			//Response Y = 1, N = 0
	u_char flags;
	u_char df;
	uint ttl_min;				//the minimum range for TTL
	uint ttl_max; 				//The maximum range for TTL, if TTL is a flat value this == ttl_min
	uint ttl_guess; 			//The TTL initial guess
	uint8_t ttl;
	enum ackchange forceack;	//This is a comparison of the TCP Ack # of the host against the TCP Seq # of the probe
	enum q_test q;				//The Q test flag, more important in ECN than most tests
	enum seqchange forceseq;	//This is a comparison of the TCP Seq # of the host against the TCP Ack # of the probe
	uint resetDatChkSum;		//The best way to explain this is from Nmap:
								/* Some operating systems return ASCII data such as error messages in reset packets.
								 * When Nmap encounters such data, it performs a CRC32 checksum and reports the results.
								 * When there is no data, RD is set to zero.*/
	struct tcp_options options;
};

struct personate_ie {
	u_char response; 	//Response Y = 1, N = 0
	uint ttl_min; 		//the minimum range for TTL
	uint ttl_max; 		//The maximum range for TTL, if TTL is a flat value this == ttl_min
	uint8_t ttl;
	uint ttl_guess; 	//The TTL initial guess
	int sharedSequence; // pers->ipid_shared_sequence, not parsed but needed in this test
	char dfi_test; 		//The Special DFI for the dual ICMP prodbe test this is for the
						//DF bit can be N:00, Y:11, S:echo probe, O:other (both toggle DF bit)
	char replyCode; 	//Z = both val = 0, S = both vals = probe
	uint replyVal;		//N = both use Non-zero number set in replyVal, O = anything else
};

enum rval { RVAL_OKAY = 0, RVAL_ZERO, RVAL_BAD };

struct persudp {
	uint8_t response;
	uint8_t tos;
	uint8_t df;
	uint un;			//The last 4 bytes in the ICMP port unreachable header
	uint ttl_min;		//the minimum range for TTL
	uint ttl_max;		//The maximum range for TTL, if TTL is a flat value this == ttl_min
	uint ttl_guess;		//The TTL initial guess
	uint8_t ttl;
	enum rval rid;
	uint ridVal; 		//If RID isn't good, 'G', value is stored here.
	enum rval ripck;
	enum rval uck;
	uint uckVal;		//If RUCK isn't good, 'G', value is stored here.
	enum rval dat;
	int riplen;
	int quotelen;

};

#define WHITESPACE	" \t\n"
#define XPRINT		"fingerprint {"
#define FINGERPRINT	"Fingerprint"
#define MATCHPOINTS "MatchPoints"
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
enum ipidtype {ID_NONE = 0, ID_SEQUENTIAL, ID_RANDOM, ID_SEQUENTIAL_BROKEN, ID_ZERO,
               ID_CONSTANT, ID_RPI};
enum ipid_protocol {TCP, ICMP, TCP_CLOSED};
enum seqtype {SEQ_CLASS64K, SEQ_RI, SEQ_TRIVIALTIME, SEQ_RANDOM,
	      SEQ_CONSTANT, SEQ_I800};
enum fragpolicy {FRAG_OLD = 0, FRAG_DROP, FRAG_NEW};

#define SEQ_TRIVIALTIME_MAX	75
#define SEQ_RI_MAX		0xD7CAB8

struct personality {
	SPLAY_ENTRY(personality) node;
	char *name;

	struct personate t_tests[7];
	struct personate seq_tests[6];

	struct personate ecn_test;
	struct personate_ie ie_test;
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

	uint16_t TCPID_Max_Increment;
	int ipid_shared_sequence; //boolean

	uint8_t valset:1,
	        unused:7;

	/* Used for constant ISNs */
	uint32_t TCP_ISN_constant_val;

	/* TCP ISN gcd */
	uint32_t TCP_ISN_gcd_min;
	uint32_t TCP_ISN_gcd_max;
	//Value chosen between min and max
	uint32_t TCP_ISN_gcd;

	/* Upper and lower bound for TCP ISN Counter Rate (ISR)*/
	uint32_t TCP_ISR_min;
	uint32_t TCP_ISR_max;
	//Value chosen between min and max
	uint32_t TCP_ISR;

	/* Upper and lower bound for TCP ISN Sequence Predictability Index (SP)*/
	uint32_t TCP_SP_min;
	uint32_t TCP_SP_max;
	//Value chosen between min and max
	uint32_t TCP_SP;

	//enum seqtype seqt;
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

void ip_personality(struct template *, uint16_t *, enum ipid_protocol proto);
struct personate * tcp_personality_test(const struct tcp_con *con, struct personality *person,
	uint8_t sndflags);
int tcp_personality(struct tcp_con *con, uint8_t *pflags, int *pwindow, int *pdf,
	    uint16_t *pid, struct tcp_options *poptions);
void tcp_personality_options(struct tcp_con *con, struct tcp_hdr *tcp, struct tcp_options *options);
int tcp_personality_match(struct tcp_con *, int);

int icmp_error_personality(struct template *, struct addr *,
    struct ip_hdr *ip, uint8_t *, uint8_t *, int *, uint8_t *);

//Helper function.
//Counts the number instances of the characters in *chars in the string *string
uint CountCharsInString(char *string, char *chars);


int parse_option(struct tcp_options *options, char *line);

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
