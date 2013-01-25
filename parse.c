/* A Bison parser, made by GNU Bison 2.5.  */

/* Bison implementation for Yacc-like parsers in C
   
      Copyright (C) 1984, 1989-1990, 2000-2011 Free Software Foundation, Inc.
   
   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.
   
   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "2.5"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 0

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1

/* Using locations.  */
#define YYLSP_NEEDED 0



/* Copy the first part of user declarations.  */

/* Line 268 of yacc.c  */
#line 32 "parse.y"

#include <sys/types.h>

#include "config.h"

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <sys/tree.h>
#include <sys/queue.h>

#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <pcap.h>
#include <dnet.h>

#include <event.h>

#include "honeyd.h"
#include "personality.h"
#include "router.h"
#include "plugins_config.h"
#include "plugins.h"
#include "template.h"
#include "condition.h"
#include "interface.h"
#include "ethernet.h"
#include "pfvar.h"
#include "dhcpclient.h"
#include "subsystem.h"
#include "util.h"
#ifdef HAVE_PYTHON
#include "pyextend.h"
#endif

int hydlex(void);
int hydparse(void);
int hyderror(char *, ...);
int hydwarn(char *, ...);
int hydprintf(char *, ...);
void *hyd_scan_string(char *);
int hyd_delete_buffer(void *);

#define yylex hydlex
#define yyparse hydparse
#define yy_scan_string hyd_scan_string
#define yy_delete_buffer hyd_delete_buffer
#define yyerror hyderror
#define yywarn hydwarn
#define yyprintf hydprintf
#define yyin hydin

extern int honeyd_verify_config;

pf_osfp_t pfctl_get_fingerprint(const char *);
struct action *honeyd_protocol(struct template *, int);
void port_action_clone(struct action *, struct action *);
static void dhcp_template(struct template *tmpl,
    char *interface, char *mac_addr);

static struct evbuffer *buffer = NULL;
int lineno;
char *filename;
int errors = 0;
int curtype = -1;	/* Lex sets it to SOCK_STREAM or _DGRAM */



/* Line 268 of yacc.c  */
#line 146 "parse.c"

/* Enabling traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* Enabling the token table.  */
#ifndef YYTOKEN_TABLE
# define YYTOKEN_TABLE 0
#endif


/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     CREATE = 258,
     ADD = 259,
     PORT = 260,
     BIND = 261,
     CLONE = 262,
     DOT = 263,
     FILTERED = 264,
     OPEN = 265,
     CLOSED = 266,
     DEFAULT = 267,
     SET = 268,
     ACTION = 269,
     PERSONALITY = 270,
     RANDOM = 271,
     ANNOTATE = 272,
     NO = 273,
     FINSCAN = 274,
     FRAGMENT = 275,
     DROP = 276,
     OLD = 277,
     NEW = 278,
     COLON = 279,
     PROXY = 280,
     UPTIME = 281,
     DROPRATE = 282,
     IN = 283,
     SYN = 284,
     UID = 285,
     GID = 286,
     ROUTE = 287,
     ENTRY = 288,
     LINK = 289,
     NET = 290,
     UNREACH = 291,
     SLASH = 292,
     LATENCY = 293,
     MS = 294,
     LOSS = 295,
     BANDWIDTH = 296,
     SUBSYSTEM = 297,
     OPTION = 298,
     TO = 299,
     SHARED = 300,
     NETWORK = 301,
     SPOOF = 302,
     FROM = 303,
     TEMPLATE = 304,
     BROADCAST = 305,
     TUNNEL = 306,
     TARPIT = 307,
     DYNAMIC = 308,
     USE = 309,
     IF = 310,
     OTHERWISE = 311,
     EQUAL = 312,
     SOURCE = 313,
     OS = 314,
     IP = 315,
     BETWEEN = 316,
     DELETE = 317,
     LIST = 318,
     ETHERNET = 319,
     DHCP = 320,
     ON = 321,
     MAXFDS = 322,
     RESTART = 323,
     DEBUG = 324,
     DASH = 325,
     TIME = 326,
     INTERNAL = 327,
     STRING = 328,
     CMDSTRING = 329,
     IPSTRING = 330,
     IP6STRING = 331,
     NUMBER = 332,
     PROTO = 333,
     FLOAT = 334
   };
#endif
/* Tokens.  */
#define CREATE 258
#define ADD 259
#define PORT 260
#define BIND 261
#define CLONE 262
#define DOT 263
#define FILTERED 264
#define OPEN 265
#define CLOSED 266
#define DEFAULT 267
#define SET 268
#define ACTION 269
#define PERSONALITY 270
#define RANDOM 271
#define ANNOTATE 272
#define NO 273
#define FINSCAN 274
#define FRAGMENT 275
#define DROP 276
#define OLD 277
#define NEW 278
#define COLON 279
#define PROXY 280
#define UPTIME 281
#define DROPRATE 282
#define IN 283
#define SYN 284
#define UID 285
#define GID 286
#define ROUTE 287
#define ENTRY 288
#define LINK 289
#define NET 290
#define UNREACH 291
#define SLASH 292
#define LATENCY 293
#define MS 294
#define LOSS 295
#define BANDWIDTH 296
#define SUBSYSTEM 297
#define OPTION 298
#define TO 299
#define SHARED 300
#define NETWORK 301
#define SPOOF 302
#define FROM 303
#define TEMPLATE 304
#define BROADCAST 305
#define TUNNEL 306
#define TARPIT 307
#define DYNAMIC 308
#define USE 309
#define IF 310
#define OTHERWISE 311
#define EQUAL 312
#define SOURCE 313
#define OS 314
#define IP 315
#define BETWEEN 316
#define DELETE 317
#define LIST 318
#define ETHERNET 319
#define DHCP 320
#define ON 321
#define MAXFDS 322
#define RESTART 323
#define DEBUG 324
#define DASH 325
#define TIME 326
#define INTERNAL 327
#define STRING 328
#define CMDSTRING 329
#define IPSTRING 330
#define IP6STRING 331
#define NUMBER 332
#define PROTO 333
#define FLOAT 334




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
{

/* Line 293 of yacc.c  */
#line 141 "parse.y"

	char *string;
	int number;
	struct link_drop drop;
	struct addr addr;
	struct action action;
	struct template *tmpl;
	struct personality *pers;
	struct addrinfo *ai;
	enum fragpolicy fragp;
	float floatp;
	struct condition condition;
	struct tm time;
	struct condition_time timecondition;



/* Line 293 of yacc.c  */
#line 358 "parse.c"
} YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
#endif


/* Copy the second part of user declarations.  */


/* Line 343 of yacc.c  */
#line 370 "parse.c"

#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#elif (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
typedef signed char yytype_int8;
#else
typedef short int yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short int yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short int yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif ! defined YYSIZE_T && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned int
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(msgid) dgettext ("bison-runtime", msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(msgid) msgid
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(e) ((void) (e))
#else
# define YYUSE(e) /* empty */
#endif

/* Identity function, used to suppress warnings about constant conditions.  */
#ifndef lint
# define YYID(n) (n)
#else
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static int
YYID (int yyi)
#else
static int
YYID (yyi)
    int yyi;
#endif
{
  return yyi;
}
#endif

#if ! defined yyoverflow || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's `empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (YYID (0))
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
	     && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
	 || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yytype_int16 yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)				\
    do									\
      {									\
	YYSIZE_T yynewbytes;						\
	YYCOPY (&yyptr->Stack_alloc, Stack, yysize);			\
	Stack = &yyptr->Stack_alloc;					\
	yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
	yyptr += yynewbytes / sizeof (*yyptr);				\
      }									\
    while (YYID (0))

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from FROM to TO.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(To, From, Count) \
      __builtin_memcpy (To, From, (Count) * sizeof (*(From)))
#  else
#   define YYCOPY(To, From, Count)		\
      do					\
	{					\
	  YYSIZE_T yyi;				\
	  for (yyi = 0; yyi < (Count); yyi++)	\
	    (To)[yyi] = (From)[yyi];		\
	}					\
      while (YYID (0))
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  2
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   201

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  80
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  32
/* YYNRULES -- Number of rules.  */
#define YYNRULES  113
/* YYNRULES -- Number of states.  */
#define YYNSTATES  212

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   334

#define YYTRANSLATE(YYX)						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    67,    68,    69,    70,    71,    72,    73,    74,
      75,    76,    77,    78,    79
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const yytype_uint16 yyprhs[] =
{
       0,     0,     3,     4,     7,    10,    13,    16,    19,    22,
      25,    28,    31,    34,    37,    40,    43,    46,    49,    55,
      62,    69,    75,    82,    86,    90,    95,   100,   105,   112,
     116,   122,   128,   136,   143,   148,   153,   158,   164,   170,
     175,   180,   187,   191,   195,   199,   205,   216,   225,   230,
     235,   237,   240,   243,   246,   249,   251,   253,   255,   257,
     261,   265,   268,   271,   275,   279,   285,   291,   297,   299,
     301,   304,   306,   308,   310,   312,   314,   316,   318,   320,
     321,   325,   326,   329,   330,   334,   337,   338,   346,   351,
     356,   361,   367,   370,   374,   378,   381,   385,   389,   393,
     394,   396,   397,   399,   400,   402,   407,   412,   417,   420,
     422,   424,   429,   434
};

/* YYRHS -- A `-1'-separated list of the rules' RHS.  */
static const yytype_int8 yyrhs[] =
{
      81,     0,    -1,    -1,    81,    82,    -1,    81,    84,    -1,
      81,    83,    -1,    81,    85,    -1,    81,    86,    -1,    81,
      87,    -1,    81,    88,    -1,    81,    89,    -1,    81,   104,
      -1,    81,   105,    -1,     3,    73,    -1,     3,    49,    -1,
       3,    12,    -1,    53,    73,    -1,    62,    97,    -1,    62,
      97,    78,     5,    77,    -1,     4,    97,    78,     5,    77,
      96,    -1,     4,    97,    54,    97,    55,   109,    -1,     4,
      97,    56,    54,    97,    -1,     4,    97,    42,    74,   106,
     107,    -1,     6,    92,    97,    -1,     6,    93,    97,    -1,
       6,   109,    92,    97,    -1,     6,    92,    44,    73,    -1,
      65,    97,    66,    73,    -1,    65,    97,    66,    73,    64,
      74,    -1,     7,    73,    97,    -1,    13,    97,    47,    48,
      92,    -1,    13,    97,    47,    44,    92,    -1,    13,    97,
      47,    48,    92,    44,    92,    -1,    13,    97,    12,    78,
      14,    96,    -1,    13,    97,    15,    98,    -1,    13,    97,
      64,    74,    -1,    13,    97,    26,    77,    -1,    13,    97,
      27,    28,    99,    -1,    13,    97,    27,    29,    99,    -1,
      13,    97,    67,    77,    -1,    13,    97,    30,    77,    -1,
      13,    97,    30,    77,    31,    77,    -1,    17,    98,    90,
      -1,    17,    98,    91,    -1,    32,    33,    92,    -1,    32,
      33,    92,    46,    94,    -1,    32,    92,     4,    35,    94,
      92,   100,   101,   102,   103,    -1,    32,    92,     4,    35,
      94,    51,    92,    92,    -1,    32,    92,    34,    94,    -1,
      32,    92,    36,    94,    -1,    19,    -1,    18,    19,    -1,
      20,    21,    -1,    20,    22,    -1,    20,    23,    -1,    75,
      -1,    74,    -1,    76,    -1,    74,    -1,    92,    37,    77,
      -1,    92,    24,    77,    -1,   108,    73,    -1,   108,    74,
      -1,   108,    72,    74,    -1,   108,    25,    95,    -1,   108,
      25,    73,    24,    77,    -1,   108,    25,    73,    24,    73,
      -1,   108,    25,    92,    24,    73,    -1,     9,    -1,    11,
      -1,   108,    10,    -1,    73,    -1,    49,    -1,    12,    -1,
      92,    -1,    74,    -1,    16,    -1,    79,    -1,    77,    -1,
      -1,    38,    77,    39,    -1,    -1,    40,    99,    -1,    -1,
      41,    77,    77,    -1,    41,    77,    -1,    -1,    21,    61,
      77,    39,    70,    77,    39,    -1,    43,    73,    73,    77,
      -1,    43,    73,    73,    79,    -1,    43,    73,    73,    73,
      -1,    43,    73,    73,    37,    73,    -1,    63,    49,    -1,
      63,    49,    74,    -1,    63,    49,    73,    -1,    63,    42,
      -1,    63,    42,    73,    -1,    63,    42,    74,    -1,    69,
      73,    77,    -1,    -1,    45,    -1,    -1,    68,    -1,    -1,
      52,    -1,    58,    59,    57,    74,    -1,    58,    60,    57,
      92,    -1,    58,    60,    57,    94,    -1,    71,   110,    -1,
      78,    -1,    56,    -1,    61,   111,    70,   111,    -1,    77,
      24,    77,    73,    -1,    74,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   158,   158,   159,   160,   161,   162,   163,   164,   165,
     166,   167,   168,   171,   177,   182,   187,   197,   202,   213,
     231,   239,   248,   265,   293,   307,   331,   359,   365,   373,
     380,   388,   396,   406,   424,   430,   450,   456,   467,   478,
     488,   499,   513,   519,   526,   532,   538,   569,   582,   595,
     610,   611,   613,   614,   615,   617,   626,   646,   656,   676,
     697,   709,   716,   726,   740,   748,   774,   790,   805,   811,
     817,   826,   833,   839,   845,   852,   860,   867,   871,   876,
     877,   882,   883,   888,   889,   893,   898,   899,   908,   919,
     930,   942,   958,   962,   970,   974,   978,   982,   988,  1009,
    1012,  1019,  1022,  1029,  1032,  1038,  1051,  1059,  1067,  1075,
    1083,  1091,  1098,  1120
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || YYTOKEN_TABLE
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "CREATE", "ADD", "PORT", "BIND", "CLONE",
  "DOT", "FILTERED", "OPEN", "CLOSED", "DEFAULT", "SET", "ACTION",
  "PERSONALITY", "RANDOM", "ANNOTATE", "NO", "FINSCAN", "FRAGMENT", "DROP",
  "OLD", "NEW", "COLON", "PROXY", "UPTIME", "DROPRATE", "IN", "SYN", "UID",
  "GID", "ROUTE", "ENTRY", "LINK", "NET", "UNREACH", "SLASH", "LATENCY",
  "MS", "LOSS", "BANDWIDTH", "SUBSYSTEM", "OPTION", "TO", "SHARED",
  "NETWORK", "SPOOF", "FROM", "TEMPLATE", "BROADCAST", "TUNNEL", "TARPIT",
  "DYNAMIC", "USE", "IF", "OTHERWISE", "EQUAL", "SOURCE", "OS", "IP",
  "BETWEEN", "DELETE", "LIST", "ETHERNET", "DHCP", "ON", "MAXFDS",
  "RESTART", "DEBUG", "DASH", "TIME", "INTERNAL", "STRING", "CMDSTRING",
  "IPSTRING", "IP6STRING", "NUMBER", "PROTO", "FLOAT", "$accept", "config",
  "creation", "delete", "addition", "subsystem", "binding", "set",
  "annotate", "route", "finscan", "fragment", "ipaddr", "ip6addr", "ipnet",
  "ipaddrplusport", "action", "template", "personality", "rate", "latency",
  "packetloss", "bandwidth", "randomearlydrop", "option", "ui", "shared",
  "restart", "flags", "condition", "timecondition", "time", 0
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[YYLEX-NUM] -- Internal token number corresponding to
   token YYLEX-NUM.  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,   302,   303,   304,
     305,   306,   307,   308,   309,   310,   311,   312,   313,   314,
     315,   316,   317,   318,   319,   320,   321,   322,   323,   324,
     325,   326,   327,   328,   329,   330,   331,   332,   333,   334
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    80,    81,    81,    81,    81,    81,    81,    81,    81,
      81,    81,    81,    82,    82,    82,    82,    83,    83,    84,
      84,    84,    85,    86,    86,    86,    86,    86,    86,    86,
      86,    86,    86,    87,    87,    87,    87,    87,    87,    87,
      87,    87,    88,    88,    89,    89,    89,    89,    89,    89,
      90,    90,    91,    91,    91,    92,    92,    93,    93,    94,
      95,    96,    96,    96,    96,    96,    96,    96,    96,    96,
      96,    97,    97,    97,    97,    98,    98,    99,    99,   100,
     100,   101,   101,   102,   102,   102,   103,   103,   104,   104,
     104,   104,   105,   105,   105,   105,   105,   105,   105,   106,
     106,   107,   107,   108,   108,   109,   109,   109,   109,   109,
     109,   110,   111,   111
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     0,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     5,     6,
       6,     5,     6,     3,     3,     4,     4,     4,     6,     3,
       5,     5,     7,     6,     4,     4,     4,     5,     5,     4,
       4,     6,     3,     3,     3,     5,    10,     8,     4,     4,
       1,     2,     2,     2,     2,     1,     1,     1,     1,     3,
       3,     2,     2,     3,     3,     5,     5,     5,     1,     1,
       2,     1,     1,     1,     1,     1,     1,     1,     1,     0,
       3,     0,     2,     0,     3,     2,     0,     7,     4,     4,
       4,     5,     2,     3,     3,     2,     3,     3,     3,     0,
       1,     0,     1,     0,     1,     4,     4,     4,     2,     1,
       1,     4,     4,     1
};

/* YYDEFACT[STATE-NAME] -- Default reduction number in state STATE-NUM.
   Performed when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       2,     0,     1,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     3,     5,     4,     6,
       7,     8,     9,    10,    11,    12,    15,    14,    13,    73,
      72,    71,    56,    55,    74,     0,   110,     0,     0,    56,
      57,   109,     0,     0,     0,     0,     0,    76,    75,     0,
       0,     0,     0,    16,    17,    95,    92,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   108,     0,    23,    24,
       0,    29,     0,     0,     0,     0,     0,     0,     0,     0,
       0,    50,     0,    42,    43,    44,     0,     0,     0,     0,
       0,    96,    97,    94,    93,     0,    98,    99,     0,     0,
       0,     0,     0,   113,     0,     0,    26,    25,     0,    34,
      36,     0,     0,    40,     0,     0,    35,    39,    51,    52,
      53,    54,     0,     0,     0,    48,    49,     0,    90,    88,
      89,     0,    27,   100,   101,     0,    21,   103,   105,   106,
     107,     0,     0,   103,    78,    77,    37,    38,     0,    31,
      30,    45,     0,     0,    91,    18,     0,   102,    22,    20,
      68,    69,   104,    19,     0,     0,   111,    33,    41,     0,
       0,    79,    59,    28,    70,     0,     0,    61,    62,   112,
      32,     0,     0,    81,     0,     0,    64,    63,    47,     0,
       0,    83,     0,     0,    80,    82,     0,    86,    66,    65,
      67,    60,    85,     0,    46,    84,     0,     0,     0,     0,
       0,    87
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     1,    16,    17,    18,    19,    20,    21,    22,    23,
      83,    84,    34,    43,   125,   186,   163,    35,    49,   146,
     183,   191,   197,   204,    24,    25,   134,   158,   164,    44,
      66,   105
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -112
static const yytype_int16 yypact[] =
{
    -112,    15,  -112,     0,    -3,    55,   -70,    -3,   -11,   -23,
     -65,   -48,    -3,   -13,    -3,   -38,  -112,  -112,  -112,  -112,
    -112,  -112,  -112,  -112,  -112,  -112,  -112,  -112,  -112,  -112,
    -112,  -112,  -112,  -112,  -112,   -16,  -112,    60,   -18,  -112,
    -112,  -112,    12,    -3,    41,    -3,    76,  -112,  -112,   116,
      41,    56,    -6,  -112,     3,    51,    54,    28,    31,    38,
      -3,    68,   100,    75,    87,    30,  -112,    72,  -112,  -112,
      -3,  -112,    70,   -11,    69,   113,    73,   -21,    77,    78,
     130,  -112,    53,  -112,  -112,   106,   118,    41,    41,    16,
     149,  -112,  -112,  -112,  -112,    83,  -112,   112,   103,    -3,
      82,    86,    41,  -112,   137,    92,  -112,  -112,   152,  -112,
    -112,   -29,   -29,   132,    41,    41,  -112,  -112,  -112,  -112,
    -112,  -112,    41,    41,   131,  -112,  -112,    94,  -112,  -112,
    -112,    95,   105,  -112,   107,    43,  -112,     5,  -112,   131,
    -112,    96,    30,     5,  -112,  -112,  -112,  -112,    97,  -112,
     127,  -112,   -44,   101,  -112,  -112,   108,  -112,  -112,  -112,
    -112,  -112,  -112,  -112,    -8,   104,  -112,  -112,  -112,    41,
      41,   141,  -112,  -112,  -112,    64,   109,  -112,  -112,  -112,
    -112,    41,   110,   140,   157,   160,  -112,  -112,  -112,   146,
     -29,   145,   -40,    23,  -112,  -112,   111,   168,  -112,  -112,
    -112,  -112,   114,   129,  -112,  -112,   115,   154,   124,   119,
     156,  -112
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int8 yypgoto[] =
{
    -112,  -112,  -112,  -112,  -112,  -112,  -112,  -112,  -112,  -112,
    -112,  -112,    -5,  -112,   -68,  -112,    57,    -1,   125,  -111,
    -112,  -112,  -112,  -112,  -112,  -112,  -112,  -112,  -112,    62,
    -112,    59
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -1
static const yytype_uint8 yytable[] =
{
      42,   147,   174,    45,    51,    47,    46,   170,    52,    29,
      50,    54,    26,    57,   160,     2,   161,   175,     3,     4,
     126,     5,     6,   114,    29,    53,    59,   115,     7,    55,
      32,    33,     8,   198,   140,    58,    56,   199,    60,    70,
      61,    68,    69,    65,    71,    85,    30,     9,   144,    27,
     145,    32,    33,   127,   151,   152,    67,   162,    10,    98,
      86,    30,    62,    48,   176,   177,   178,    89,    11,   107,
      31,    32,    33,    28,   119,   120,   121,    12,    13,   195,
      14,    90,   124,   124,    15,    31,    32,    33,    72,   128,
      87,    73,    88,   129,    95,   130,   200,   139,   136,    36,
     201,    37,    74,    75,   103,   100,    76,   104,    96,   149,
     150,    36,    97,    37,    38,    32,    33,   124,   124,    63,
      64,    41,    99,    77,    91,    92,    38,    93,    94,    39,
      33,    40,   101,    41,    80,    81,    82,   184,    32,    33,
      78,   111,   112,    79,   102,   106,   110,   171,   108,   118,
     113,   116,   122,   123,   131,   117,   132,   133,   135,   137,
     138,   141,   142,   148,   180,   181,   143,   154,   153,   156,
     185,   169,   155,   165,   168,   157,   188,   179,   172,   182,
     190,   192,   173,   187,   193,   194,   196,   189,   202,   203,
     206,   205,   207,   208,   209,   211,   210,   159,   109,     0,
     167,   166
};

#define yypact_value_is_default(yystate) \
  ((yystate) == (-112))

#define yytable_value_is_error(yytable_value) \
  YYID (0)

static const yytype_int16 yycheck[] =
{
       5,   112,    10,    73,     9,    16,     7,    51,    73,    12,
      33,    12,    12,    14,     9,     0,    11,    25,     3,     4,
      88,     6,     7,    44,    12,    73,    42,    48,    13,    42,
      74,    75,    17,    73,   102,    73,    49,    77,    54,    44,
      56,    42,    43,    61,    45,    50,    49,    32,    77,    49,
      79,    74,    75,    37,   122,   123,    44,    52,    43,    60,
       4,    49,    78,    74,    72,    73,    74,    73,    53,    70,
      73,    74,    75,    73,    21,    22,    23,    62,    63,   190,
      65,    78,    87,    88,    69,    73,    74,    75,    12,    73,
      34,    15,    36,    77,    66,    79,    73,   102,    99,    56,
      77,    58,    26,    27,    74,     5,    30,    77,    77,   114,
     115,    56,    74,    58,    71,    74,    75,   122,   123,    59,
      60,    78,    54,    47,    73,    74,    71,    73,    74,    74,
      75,    76,    57,    78,    18,    19,    20,    73,    74,    75,
      64,    28,    29,    67,    57,    73,    77,   152,    78,    19,
      77,    74,    46,    35,     5,    77,    73,    45,    55,    77,
      74,    24,    70,    31,   169,   170,    14,    73,    37,    64,
     175,    44,    77,    77,    77,    68,   181,    73,    77,    38,
      40,    24,    74,    74,    24,    39,    41,    77,    77,    21,
      61,    77,    77,    39,    70,    39,    77,   135,    73,    -1,
     143,   142
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,    81,     0,     3,     4,     6,     7,    13,    17,    32,
      43,    53,    62,    63,    65,    69,    82,    83,    84,    85,
      86,    87,    88,    89,   104,   105,    12,    49,    73,    12,
      49,    73,    74,    75,    92,    97,    56,    58,    71,    74,
      76,    78,    92,    93,   109,    73,    97,    16,    74,    98,
      33,    92,    73,    73,    97,    42,    49,    97,    73,    42,
      54,    56,    78,    59,    60,    61,   110,    44,    97,    97,
      92,    97,    12,    15,    26,    27,    30,    47,    64,    67,
      18,    19,    20,    90,    91,    92,     4,    34,    36,    73,
      78,    73,    74,    73,    74,    66,    77,    74,    97,    54,
       5,    57,    57,    74,    77,   111,    73,    97,    78,    98,
      77,    28,    29,    77,    44,    48,    74,    77,    19,    21,
      22,    23,    46,    35,    92,    94,    94,    37,    73,    77,
      79,     5,    73,    45,   106,    55,    97,    77,    74,    92,
      94,    24,    70,    14,    77,    79,    99,    99,    31,    92,
      92,    94,    94,    37,    73,    77,    64,    68,   107,   109,
       9,    11,    52,    96,   108,    77,   111,    96,    77,    44,
      51,    92,    77,    74,    10,    25,    72,    73,    74,    73,
      92,    92,    38,   100,    73,    92,    95,    74,    92,    77,
      40,   101,    24,    24,    39,    99,    41,   102,    73,    77,
      73,    77,    77,    21,   103,    77,    61,    77,    39,    70,
      77,    39
};

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		(-2)
#define YYEOF		0

#define YYACCEPT	goto yyacceptlab
#define YYABORT		goto yyabortlab
#define YYERROR		goto yyerrorlab


/* Like YYERROR except do call yyerror.  This remains here temporarily
   to ease the transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  However,
   YYFAIL appears to be in use.  Nevertheless, it is formally deprecated
   in Bison 2.4.2's NEWS entry, where a plan to phase it out is
   discussed.  */

#define YYFAIL		goto yyerrlab
#if defined YYFAIL
  /* This is here to suppress warnings from the GCC cpp's
     -Wunused-macros.  Normally we don't worry about that warning, but
     some users do, and we want to make it easy for users to remove
     YYFAIL uses, which will produce warnings from Bison 2.5.  */
#endif

#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)					\
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    {								\
      yychar = (Token);						\
      yylval = (Value);						\
      YYPOPSTACK (1);						\
      goto yybackup;						\
    }								\
  else								\
    {								\
      yyerror (YY_("syntax error: cannot back up")); \
      YYERROR;							\
    }								\
while (YYID (0))


#define YYTERROR	1
#define YYERRCODE	256


/* YYLLOC_DEFAULT -- Set CURRENT to span from RHS[1] to RHS[N].
   If N is 0, then set CURRENT to the empty location which ends
   the previous symbol: RHS[0] (always defined).  */

#define YYRHSLOC(Rhs, K) ((Rhs)[K])
#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)				\
    do									\
      if (YYID (N))                                                    \
	{								\
	  (Current).first_line   = YYRHSLOC (Rhs, 1).first_line;	\
	  (Current).first_column = YYRHSLOC (Rhs, 1).first_column;	\
	  (Current).last_line    = YYRHSLOC (Rhs, N).last_line;		\
	  (Current).last_column  = YYRHSLOC (Rhs, N).last_column;	\
	}								\
      else								\
	{								\
	  (Current).first_line   = (Current).last_line   =		\
	    YYRHSLOC (Rhs, 0).last_line;				\
	  (Current).first_column = (Current).last_column =		\
	    YYRHSLOC (Rhs, 0).last_column;				\
	}								\
    while (YYID (0))
#endif


/* This macro is provided for backward compatibility. */

#ifndef YY_LOCATION_PRINT
# define YY_LOCATION_PRINT(File, Loc) ((void) 0)
#endif


/* YYLEX -- calling `yylex' with the right arguments.  */

#ifdef YYLEX_PARAM
# define YYLEX yylex (YYLEX_PARAM)
#else
# define YYLEX yylex ()
#endif

/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)			\
do {						\
  if (yydebug)					\
    YYFPRINTF Args;				\
} while (YYID (0))

# define YY_SYMBOL_PRINT(Title, Type, Value, Location)			  \
do {									  \
  if (yydebug)								  \
    {									  \
      YYFPRINTF (stderr, "%s ", Title);					  \
      yy_symbol_print (stderr,						  \
		  Type, Value); \
      YYFPRINTF (stderr, "\n");						  \
    }									  \
} while (YYID (0))


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
#else
static void
yy_symbol_value_print (yyoutput, yytype, yyvaluep)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
#endif
{
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# else
  YYUSE (yyoutput);
# endif
  switch (yytype)
    {
      default:
	break;
    }
}


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
#else
static void
yy_symbol_print (yyoutput, yytype, yyvaluep)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
#endif
{
  if (yytype < YYNTOKENS)
    YYFPRINTF (yyoutput, "token %s (", yytname[yytype]);
  else
    YYFPRINTF (yyoutput, "nterm %s (", yytname[yytype]);

  yy_symbol_value_print (yyoutput, yytype, yyvaluep);
  YYFPRINTF (yyoutput, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_stack_print (yytype_int16 *yybottom, yytype_int16 *yytop)
#else
static void
yy_stack_print (yybottom, yytop)
    yytype_int16 *yybottom;
    yytype_int16 *yytop;
#endif
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)				\
do {								\
  if (yydebug)							\
    yy_stack_print ((Bottom), (Top));				\
} while (YYID (0))


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_reduce_print (YYSTYPE *yyvsp, int yyrule)
#else
static void
yy_reduce_print (yyvsp, yyrule)
    YYSTYPE *yyvsp;
    int yyrule;
#endif
{
  int yynrhs = yyr2[yyrule];
  int yyi;
  unsigned long int yylno = yyrline[yyrule];
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
	     yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr, yyrhs[yyprhs[yyrule] + yyi],
		       &(yyvsp[(yyi + 1) - (yynrhs)])
		       		       );
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)		\
do {					\
  if (yydebug)				\
    yy_reduce_print (yyvsp, Rule); \
} while (YYID (0))

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef	YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif


#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static YYSIZE_T
yystrlen (const char *yystr)
#else
static YYSIZE_T
yystrlen (yystr)
    const char *yystr;
#endif
{
  YYSIZE_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static char *
yystpcpy (char *yydest, const char *yysrc)
#else
static char *
yystpcpy (yydest, yysrc)
    char *yydest;
    const char *yysrc;
#endif
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYSIZE_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
	switch (*++yyp)
	  {
	  case '\'':
	  case ',':
	    goto do_not_strip_quotes;

	  case '\\':
	    if (*++yyp != '\\')
	      goto do_not_strip_quotes;
	    /* Fall through.  */
	  default:
	    if (yyres)
	      yyres[yyn] = *yyp;
	    yyn++;
	    break;

	  case '"':
	    if (yyres)
	      yyres[yyn] = '\0';
	    return yyn;
	  }
    do_not_strip_quotes: ;
    }

  if (! yyres)
    return yystrlen (yystr);

  return yystpcpy (yyres, yystr) - yyres;
}
# endif

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return 1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return 2 if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYSIZE_T *yymsg_alloc, char **yymsg,
                yytype_int16 *yyssp, int yytoken)
{
  YYSIZE_T yysize0 = yytnamerr (0, yytname[yytoken]);
  YYSIZE_T yysize = yysize0;
  YYSIZE_T yysize1;
  enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
  /* Internationalized format string. */
  const char *yyformat = 0;
  /* Arguments of yyformat. */
  char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
  /* Number of reported tokens (one for the "unexpected", one per
     "expected"). */
  int yycount = 0;

  /* There are many possibilities here to consider:
     - Assume YYFAIL is not used.  It's too flawed to consider.  See
       <http://lists.gnu.org/archive/html/bison-patches/2009-12/msg00024.html>
       for details.  YYERROR is fine as it does not invoke this
       function.
     - If this state is a consistent state with a default action, then
       the only way this function was invoked is if the default action
       is an error action.  In that case, don't check for expected
       tokens because there are none.
     - The only way there can be no lookahead present (in yychar) is if
       this state is a consistent state with a default action.  Thus,
       detecting the absence of a lookahead is sufficient to determine
       that there is no unexpected or expected token to report.  In that
       case, just report a simple "syntax error".
     - Don't assume there isn't a lookahead just because this state is a
       consistent state with a default action.  There might have been a
       previous inconsistent state, consistent state with a non-default
       action, or user semantic action that manipulated yychar.
     - Of course, the expected token list depends on states to have
       correct lookahead information, and it depends on the parser not
       to perform extra reductions after fetching a lookahead from the
       scanner and before detecting a syntax error.  Thus, state merging
       (from LALR or IELR) and default reductions corrupt the expected
       token list.  However, the list is correct for canonical LR with
       one exception: it will still contain any token that will not be
       accepted due to an error action in a later state.
  */
  if (yytoken != YYEMPTY)
    {
      int yyn = yypact[*yyssp];
      yyarg[yycount++] = yytname[yytoken];
      if (!yypact_value_is_default (yyn))
        {
          /* Start YYX at -YYN if negative to avoid negative indexes in
             YYCHECK.  In other words, skip the first -YYN actions for
             this state because they are default actions.  */
          int yyxbegin = yyn < 0 ? -yyn : 0;
          /* Stay within bounds of both yycheck and yytname.  */
          int yychecklim = YYLAST - yyn + 1;
          int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
          int yyx;

          for (yyx = yyxbegin; yyx < yyxend; ++yyx)
            if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR
                && !yytable_value_is_error (yytable[yyx + yyn]))
              {
                if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
                  {
                    yycount = 1;
                    yysize = yysize0;
                    break;
                  }
                yyarg[yycount++] = yytname[yyx];
                yysize1 = yysize + yytnamerr (0, yytname[yyx]);
                if (! (yysize <= yysize1
                       && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
                  return 2;
                yysize = yysize1;
              }
        }
    }

  switch (yycount)
    {
# define YYCASE_(N, S)                      \
      case N:                               \
        yyformat = S;                       \
      break
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
# undef YYCASE_
    }

  yysize1 = yysize + yystrlen (yyformat);
  if (! (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
    return 2;
  yysize = yysize1;

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return 1;
    }

  /* Avoid sprintf, as that infringes on the user's name space.
     Don't have undefined behavior even if the translation
     produced a string with the wrong number of "%s"s.  */
  {
    char *yyp = *yymsg;
    int yyi = 0;
    while ((*yyp = *yyformat) != '\0')
      if (*yyp == '%' && yyformat[1] == 's' && yyi < yycount)
        {
          yyp += yytnamerr (yyp, yyarg[yyi++]);
          yyformat += 2;
        }
      else
        {
          yyp++;
          yyformat++;
        }
  }
  return 0;
}
#endif /* YYERROR_VERBOSE */

/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep)
#else
static void
yydestruct (yymsg, yytype, yyvaluep)
    const char *yymsg;
    int yytype;
    YYSTYPE *yyvaluep;
#endif
{
  YYUSE (yyvaluep);

  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  switch (yytype)
    {

      default:
	break;
    }
}


/* Prevent warnings from -Wmissing-prototypes.  */
#ifdef YYPARSE_PARAM
#if defined __STDC__ || defined __cplusplus
int yyparse (void *YYPARSE_PARAM);
#else
int yyparse ();
#endif
#else /* ! YYPARSE_PARAM */
#if defined __STDC__ || defined __cplusplus
int yyparse (void);
#else
int yyparse ();
#endif
#endif /* ! YYPARSE_PARAM */


/* The lookahead symbol.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;

/* Number of syntax errors so far.  */
int yynerrs;


/*----------.
| yyparse.  |
`----------*/

#ifdef YYPARSE_PARAM
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (void *YYPARSE_PARAM)
#else
int
yyparse (YYPARSE_PARAM)
    void *YYPARSE_PARAM;
#endif
#else /* ! YYPARSE_PARAM */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (void)
#else
int
yyparse ()

#endif
#endif
{
    int yystate;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus;

    /* The stacks and their tools:
       `yyss': related to states.
       `yyvs': related to semantic values.

       Refer to the stacks thru separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* The state stack.  */
    yytype_int16 yyssa[YYINITDEPTH];
    yytype_int16 *yyss;
    yytype_int16 *yyssp;

    /* The semantic value stack.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs;
    YYSTYPE *yyvsp;

    YYSIZE_T yystacksize;

  int yyn;
  int yyresult;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;

#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  yytoken = 0;
  yyss = yyssa;
  yyvs = yyvsa;
  yystacksize = YYINITDEPTH;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY; /* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */
  yyssp = yyss;
  yyvsp = yyvs;

  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
	/* Give user a chance to reallocate the stack.  Use copies of
	   these so that the &'s don't force the real ones into
	   memory.  */
	YYSTYPE *yyvs1 = yyvs;
	yytype_int16 *yyss1 = yyss;

	/* Each stack pointer address is followed by the size of the
	   data in use in that stack, in bytes.  This used to be a
	   conditional around just the two extra args, but that might
	   be undefined if yyoverflow is a macro.  */
	yyoverflow (YY_("memory exhausted"),
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),
		    &yystacksize);

	yyss = yyss1;
	yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyexhaustedlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
	goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
	yystacksize = YYMAXDEPTH;

      {
	yytype_int16 *yyss1 = yyss;
	union yyalloc *yyptr =
	  (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
	if (! yyptr)
	  goto yyexhaustedlab;
	YYSTACK_RELOCATE (yyss_alloc, yyss);
	YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
	if (yyss1 != yyssa)
	  YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
		  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
	YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = YYLEX;
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  /* Discard the shifted token.  */
  yychar = YYEMPTY;

  yystate = yyn;
  *++yyvsp = yylval;

  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     `$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 13:

/* Line 1806 of yacc.c  */
#line 172 "parse.y"
    {
		if (template_create((yyvsp[(2) - (2)].string)) == NULL)
			yyerror("Template \"%s\" exists already", (yyvsp[(2) - (2)].string));
		free((yyvsp[(2) - (2)].string));
	}
    break;

  case 14:

/* Line 1806 of yacc.c  */
#line 178 "parse.y"
    {
		if (template_create("template") == NULL)
			yyerror("Template \"template\" exists already");
	}
    break;

  case 15:

/* Line 1806 of yacc.c  */
#line 183 "parse.y"
    {
		if (template_create("default") == NULL)
			yyerror("Template \"default\" exists already");
	}
    break;

  case 16:

/* Line 1806 of yacc.c  */
#line 188 "parse.y"
    {		
		struct template *tmpl;
		if ((tmpl = template_create((yyvsp[(2) - (2)].string))) == NULL)
			yyerror("Template \"%s\" exists already", (yyvsp[(2) - (2)].string));
		tmpl->flags |= TEMPLATE_DYNAMIC;
		free((yyvsp[(2) - (2)].string));
	}
    break;

  case 17:

/* Line 1806 of yacc.c  */
#line 198 "parse.y"
    {
		if ((yyvsp[(2) - (2)].tmpl) != NULL)
			template_free((yyvsp[(2) - (2)].tmpl));
	}
    break;

  case 18:

/* Line 1806 of yacc.c  */
#line 203 "parse.y"
    {
		struct port *port;
		if ((port = port_find((yyvsp[(2) - (5)].tmpl), (yyvsp[(3) - (5)].number), (yyvsp[(5) - (5)].number))) == NULL) {
			yyerror("Cannot find port %d in \"%s\"",
			    (yyvsp[(5) - (5)].number), (yyvsp[(2) - (5)].tmpl)->name);
		} else {
			port_free((yyvsp[(2) - (5)].tmpl), port);
		}
	}
    break;

  case 19:

/* Line 1806 of yacc.c  */
#line 214 "parse.y"
    {
		struct action *action;		
		if ((yyvsp[(2) - (6)].tmpl) == NULL) {
			yyerror("No template");
			break;
		}
		
		if ((action = honeyd_protocol((yyvsp[(2) - (6)].tmpl), (yyvsp[(3) - (6)].number))) == NULL) {
			yyerror("Bad protocol");
			break;
		}
		if ((yyvsp[(2) - (6)].tmpl) != NULL && template_add((yyvsp[(2) - (6)].tmpl), (yyvsp[(3) - (6)].number), (yyvsp[(5) - (6)].number), &(yyvsp[(6) - (6)].action)) == -1)
			yyerror("Cannot add port %d to template \"%s\"",
			    (yyvsp[(5) - (6)].number), (yyvsp[(2) - (6)].tmpl) != NULL ? (yyvsp[(2) - (6)].tmpl)->name : "<unknown>");
		if ((yyvsp[(6) - (6)].action).action)
			free((yyvsp[(6) - (6)].action).action);
	}
    break;

  case 20:

/* Line 1806 of yacc.c  */
#line 232 "parse.y"
    {	
		if ((yyvsp[(2) - (6)].tmpl) == NULL || (yyvsp[(4) - (6)].tmpl) == NULL)
			break;
		if (!((yyvsp[(2) - (6)].tmpl)->flags & TEMPLATE_DYNAMIC))
			yyerror("Cannot add templates to non-dynamic template \"%s\"", (yyvsp[(2) - (6)].tmpl)->name);
		template_insert_dynamic((yyvsp[(2) - (6)].tmpl), (yyvsp[(4) - (6)].tmpl), &(yyvsp[(6) - (6)].condition));
	}
    break;

  case 21:

/* Line 1806 of yacc.c  */
#line 240 "parse.y"
    {	
		if ((yyvsp[(2) - (5)].tmpl) == NULL || (yyvsp[(5) - (5)].tmpl) == NULL)
			break;
		if (!((yyvsp[(2) - (5)].tmpl)->flags & TEMPLATE_DYNAMIC))
			yyerror("Cannot add templates to non-dynamic template \"%s\"", (yyvsp[(2) - (5)].tmpl)->name);
		template_insert_dynamic((yyvsp[(2) - (5)].tmpl), (yyvsp[(5) - (5)].tmpl), NULL);
	}
    break;

  case 22:

/* Line 1806 of yacc.c  */
#line 249 "parse.y"
    {
		int flags = 0;

		if ((yyvsp[(5) - (6)].number))
			flags |= SUBSYSTEM_SHARED;		
		if ((yyvsp[(6) - (6)].number))
			flags |= SUBSYSTEM_RESTART;		

		(yyvsp[(4) - (6)].string)[strlen((yyvsp[(4) - (6)].string)) - 1] = '\0';
		if ((yyvsp[(2) - (6)].tmpl) != NULL &&
		    template_subsystem((yyvsp[(2) - (6)].tmpl), (yyvsp[(4) - (6)].string)+1, flags) == -1)
			yyerror("Can not add subsystem \"%s\" to template \"%s\"",
			    (yyvsp[(4) - (6)].string)+1, (yyvsp[(2) - (6)].tmpl) != NULL ? (yyvsp[(2) - (6)].tmpl)->name : "<unknown>");
		free((yyvsp[(4) - (6)].string));
	}
    break;

  case 23:

/* Line 1806 of yacc.c  */
#line 266 "parse.y"
    {
		/* Bind to an IP address and start subsystems */
		if ((yyvsp[(3) - (3)].tmpl) == NULL) {
			yyerror("Unknown template");
			break;
		}

		if ((yyvsp[(3) - (3)].tmpl)->ethernet_addr != NULL) {
			struct interface *inter;
			inter = interface_find_responsible(&(yyvsp[(2) - (3)].addr));
			if (inter == NULL ||
			    inter->if_ent.intf_link_addr.addr_type != ADDR_TYPE_ETH) {
				yyerror("Template \"%s\" is configured with "
				    "ethernet address but there is no "
				    "interface that can reach %s",
				    (yyvsp[(3) - (3)].tmpl)->name, addr_ntoa(&(yyvsp[(2) - (3)].addr)));
				break;
			} else {
				(yyvsp[(3) - (3)].tmpl)->addrbits = inter->if_addrbits;
			}
		}

		if (template_clone(addr_ntoa(&(yyvsp[(2) - (3)].addr)), (yyvsp[(3) - (3)].tmpl), NULL, 1) == NULL) {
			yyerror("Binding to %s failed", addr_ntoa(&(yyvsp[(2) - (3)].addr)));
			break;
		}
	}
    break;

  case 24:

/* Line 1806 of yacc.c  */
#line 294 "parse.y"
    {
		/* Bind to an IP address and start subsystems */
		if ((yyvsp[(3) - (3)].tmpl) == NULL) {
			yyerror("Unknown template");
			break;
		}

		if (template_clone(addr_ntoa(&(yyvsp[(2) - (3)].addr)), (yyvsp[(3) - (3)].tmpl), NULL, 1) == NULL) {
			yyerror("Binding to %s failed", addr_ntoa(&(yyvsp[(2) - (3)].addr)));
			break;
		}
	}
    break;

  case 25:

/* Line 1806 of yacc.c  */
#line 308 "parse.y"
    {
		struct template *tmpl;

		/* Special magic */
		if ((tmpl = template_find(addr_ntoa(&(yyvsp[(3) - (4)].addr)))) != NULL) {
			if (!(tmpl->flags & TEMPLATE_DYNAMIC)) {
				yyerror("Template \"%s\" already specified as "
				    "non-dynamic template", addr_ntoa(&(yyvsp[(3) - (4)].addr)));
				break;
			}
		} else if ((tmpl = template_create(addr_ntoa(&(yyvsp[(3) - (4)].addr)))) == NULL) {
			yyerror("Could not create template \"%s\"",
			    addr_ntoa(&(yyvsp[(3) - (4)].addr)));
			break;
		}
		tmpl->flags |= TEMPLATE_DYNAMIC;

		/* 
		 * Add this point we do have the right template.
		 * We just need to add the proper condition.
		 */
		template_insert_dynamic(tmpl, (yyvsp[(4) - (4)].tmpl), &(yyvsp[(2) - (4)].condition));
	}
    break;

  case 26:

/* Line 1806 of yacc.c  */
#line 332 "parse.y"
    {
		struct interface *inter;
		struct template *tmpl;

		/* Bind an IP address to an external interface */
		if ((inter = interface_find((yyvsp[(4) - (4)].string))) == NULL) {
			yyerror("Interface \"%s\" does not exist.", (yyvsp[(4) - (4)].string));
			free((yyvsp[(4) - (4)].string));
			break;
		}
		if (inter->if_ent.intf_link_addr.addr_type != ADDR_TYPE_ETH) {
			yyerror("Interface \"%s\" does not support ARP.", (yyvsp[(4) - (4)].string));
			free((yyvsp[(4) - (4)].string));
			break;
		}

		if ((tmpl = template_create(addr_ntoa(&(yyvsp[(2) - (4)].addr)))) == NULL) {
			yyerror("Template \"%s\" exists already",
			    addr_ntoa(&(yyvsp[(2) - (4)].addr)));
			break;
		}

		/* Make this template external. */
		tmpl->flags |= TEMPLATE_EXTERNAL;
		tmpl->inter = inter;
		free((yyvsp[(4) - (4)].string));
	}
    break;

  case 27:

/* Line 1806 of yacc.c  */
#line 360 "parse.y"
    {		
		/* Automagically assign DHCP address */
		dhcp_template((yyvsp[(2) - (4)].tmpl), (yyvsp[(4) - (4)].string), NULL);
		free((yyvsp[(4) - (4)].string));
	}
    break;

  case 28:

/* Line 1806 of yacc.c  */
#line 366 "parse.y"
    {		
		/* Automagically assign DHCP address with MAC address */
		(yyvsp[(6) - (6)].string)[strlen((yyvsp[(6) - (6)].string)) - 1] = '\0';
		dhcp_template((yyvsp[(2) - (6)].tmpl), (yyvsp[(4) - (6)].string), (yyvsp[(6) - (6)].string) + 1);
		free((yyvsp[(4) - (6)].string));
		free((yyvsp[(6) - (6)].string));
	}
    break;

  case 29:

/* Line 1806 of yacc.c  */
#line 374 "parse.y"
    {
		/* Just clone.  This is not the final destination yet */
		if ((yyvsp[(3) - (3)].tmpl) == NULL || template_clone((yyvsp[(2) - (3)].string), (yyvsp[(3) - (3)].tmpl), NULL, 0) == NULL)
			yyerror("Cloning to %s failed", (yyvsp[(2) - (3)].string));
		free((yyvsp[(2) - (3)].string));
	}
    break;

  case 30:

/* Line 1806 of yacc.c  */
#line 381 "parse.y"
    {
		if ((yyvsp[(2) - (5)].tmpl) == NULL) {
			yyerror("No template");
			break;
		}
		(yyvsp[(2) - (5)].tmpl)->spoof.new_src = (yyvsp[(5) - (5)].addr);
	}
    break;

  case 31:

/* Line 1806 of yacc.c  */
#line 389 "parse.y"
    {
		if ((yyvsp[(2) - (5)].tmpl) == NULL) {
			yyerror("No template");
			break;
		}
		(yyvsp[(2) - (5)].tmpl)->spoof.new_dst = (yyvsp[(5) - (5)].addr);
	}
    break;

  case 32:

/* Line 1806 of yacc.c  */
#line 397 "parse.y"
    {
		if ((yyvsp[(2) - (7)].tmpl) == NULL) {
			yyerror("No template");
			break;
		}
		(yyvsp[(2) - (7)].tmpl)->spoof.new_src = (yyvsp[(5) - (7)].addr);
		(yyvsp[(2) - (7)].tmpl)->spoof.new_dst = (yyvsp[(7) - (7)].addr);
	}
    break;

  case 33:

/* Line 1806 of yacc.c  */
#line 407 "parse.y"
    {
		struct action *action;

		if ((yyvsp[(2) - (6)].tmpl) == NULL) {
			yyerror("No template");
			break;
		}
		
		if ((action = honeyd_protocol((yyvsp[(2) - (6)].tmpl), (yyvsp[(4) - (6)].number))) == NULL) {
			yyerror("Bad protocol");
			break;
		}

		port_action_clone(action, &(yyvsp[(6) - (6)].action));
		if ((yyvsp[(6) - (6)].action).action != NULL)
			free((yyvsp[(6) - (6)].action).action);
	}
    break;

  case 34:

/* Line 1806 of yacc.c  */
#line 425 "parse.y"
    {
		if ((yyvsp[(2) - (4)].tmpl) == NULL || (yyvsp[(4) - (4)].pers) == NULL)
			break;
		(yyvsp[(2) - (4)].tmpl)->person = personality_clone((yyvsp[(4) - (4)].pers));
	}
    break;

  case 35:

/* Line 1806 of yacc.c  */
#line 431 "parse.y"
    {
		extern int need_arp;
		if ((yyvsp[(2) - (4)].tmpl) == NULL || (yyvsp[(4) - (4)].string) == NULL)
			break;
		(yyvsp[(4) - (4)].string)[strlen((yyvsp[(4) - (4)].string)) - 1] = '\0';
		(yyvsp[(2) - (4)].tmpl)->ethernet_addr = ethernetcode_make_address((yyvsp[(4) - (4)].string) + 1);
		if ((yyvsp[(2) - (4)].tmpl)->ethernet_addr == NULL) {
			yyerror("Unknown ethernet vendor \"%s\"", (yyvsp[(4) - (4)].string) + 1);
		}
		/*** small patch to make sure the ethernet adress is used ***/
		/*** even if none were set in the default template ***/
		struct addr addr;
		if(addr_aton((yyvsp[(2) - (4)].tmpl)->name, &addr) != -1)
			template_post_arp((yyvsp[(2) - (4)].tmpl), &addr);
		/*** end patch ***/
		free ((yyvsp[(4) - (4)].string));

		need_arp = 1;
	}
    break;

  case 36:

/* Line 1806 of yacc.c  */
#line 451 "parse.y"
    {
		if ((yyvsp[(2) - (4)].tmpl) == NULL || (yyvsp[(4) - (4)].number) == 0)
			break;
		(yyvsp[(2) - (4)].tmpl)->timestamp = (yyvsp[(4) - (4)].number) * 2;
	}
    break;

  case 37:

/* Line 1806 of yacc.c  */
#line 457 "parse.y"
    {
		if ((yyvsp[(2) - (5)].tmpl) == NULL)
			break;
		if ((yyvsp[(5) - (5)].floatp) > 100) {
			yyerror("Droprate too high: %f", (yyvsp[(5) - (5)].floatp));
			break;
		}

		(yyvsp[(2) - (5)].tmpl)->drop_inrate = (yyvsp[(5) - (5)].floatp) * 100;
	}
    break;

  case 38:

/* Line 1806 of yacc.c  */
#line 468 "parse.y"
    {
		if ((yyvsp[(2) - (5)].tmpl) == NULL)
			break;
		if ((yyvsp[(5) - (5)].floatp) > 100) {
			yyerror("Droprate too high: %f", (yyvsp[(5) - (5)].floatp));
			break;
		}

		(yyvsp[(2) - (5)].tmpl)->drop_synrate = (yyvsp[(5) - (5)].floatp) * 100;
	}
    break;

  case 39:

/* Line 1806 of yacc.c  */
#line 479 "parse.y"
    {
		if ((yyvsp[(2) - (4)].tmpl) == NULL)
			break;
		if ((yyvsp[(4) - (4)].number) <= 3) {
			yyerror("Bad number of max file descriptors %d", (yyvsp[(4) - (4)].number));
			break;
		}
		(yyvsp[(2) - (4)].tmpl)->max_nofiles = (yyvsp[(4) - (4)].number);
	}
    break;

  case 40:

/* Line 1806 of yacc.c  */
#line 489 "parse.y"
    {
		if ((yyvsp[(2) - (4)].tmpl) == NULL)
			break;
		if (!(yyvsp[(4) - (4)].number)) {
			yyerror("Bad uid %d", (yyvsp[(4) - (4)].number));
			break;
		}
		(yyvsp[(2) - (4)].tmpl)->uid = (yyvsp[(4) - (4)].number);
		honeyd_use_uid((yyvsp[(4) - (4)].number));
	}
    break;

  case 41:

/* Line 1806 of yacc.c  */
#line 500 "parse.y"
    {
		if ((yyvsp[(2) - (6)].tmpl) == NULL)
			break;
		if (!(yyvsp[(4) - (6)].number) || !(yyvsp[(6) - (6)].number)) {
			yyerror("Bad uid %d, gid %d", (yyvsp[(4) - (6)].number), (yyvsp[(6) - (6)].number));
			break;
		}
		(yyvsp[(2) - (6)].tmpl)->uid = (yyvsp[(4) - (6)].number);
		(yyvsp[(2) - (6)].tmpl)->gid = (yyvsp[(6) - (6)].number);
		honeyd_use_uid((yyvsp[(4) - (6)].number));
		honeyd_use_gid((yyvsp[(6) - (6)].number));
	}
    break;

  case 42:

/* Line 1806 of yacc.c  */
#line 514 "parse.y"
    {
		if ((yyvsp[(2) - (3)].pers) == NULL)
			break;
		(yyvsp[(2) - (3)].pers)->disallow_finscan = !(yyvsp[(3) - (3)].number);
	}
    break;

  case 43:

/* Line 1806 of yacc.c  */
#line 520 "parse.y"
    {
		if ((yyvsp[(2) - (3)].pers) == NULL)
			break;
		(yyvsp[(2) - (3)].pers)->fragp = (yyvsp[(3) - (3)].fragp);
	}
    break;

  case 44:

/* Line 1806 of yacc.c  */
#line 527 "parse.y"
    {
		if (router_start(&(yyvsp[(3) - (3)].addr), NULL) == -1)
			yyerror("Defining entry point failed: %s",
			    addr_ntoa(&(yyvsp[(3) - (3)].addr)));
	}
    break;

  case 45:

/* Line 1806 of yacc.c  */
#line 533 "parse.y"
    {
		if (router_start(&(yyvsp[(3) - (5)].addr), &(yyvsp[(5) - (5)].addr)) == -1)
			yyerror("Defining entry point failed: %s",
			    addr_ntoa(&(yyvsp[(3) - (5)].addr)));
	}
    break;

  case 46:

/* Line 1806 of yacc.c  */
#line 539 "parse.y"
    {
		struct router *r, *newr;
		struct addr defroute;

		if ((r = router_find(&(yyvsp[(2) - (10)].addr))) == NULL &&
		    (r = router_new(&(yyvsp[(2) - (10)].addr))) == NULL) {
			yyerror("Cannot make forward reference for router %s",
			    addr_ntoa(&(yyvsp[(2) - (10)].addr)));
			break;
		}
		if ((newr = router_find(&(yyvsp[(6) - (10)].addr))) == NULL)
			newr = router_new(&(yyvsp[(6) - (10)].addr));
		if (router_add_net(r, &(yyvsp[(5) - (10)].addr), newr, (yyvsp[(7) - (10)].number), (yyvsp[(8) - (10)].number), (yyvsp[(9) - (10)].number), &(yyvsp[(10) - (10)].drop)) == -1)
			yyerror("Could not add route to %s", addr_ntoa(&(yyvsp[(5) - (10)].addr)));

		if ((yyvsp[(9) - (10)].number) == 0 && (yyvsp[(10) - (10)].drop).high != 0)
			yywarn("Ignoring drop between statement without "
			       "specified bandwidth.");

		addr_pton("0.0.0.0/0", &defroute);
		defroute.addr_bits = 0; /* work around libdnet bug */

		/* Only insert a reverse route, if the current route is
		 * not the default route.
		 */
		if (addr_cmp(&defroute, &(yyvsp[(5) - (10)].addr)) != 0 &&
		    router_add_net(newr, &defroute, r, (yyvsp[(7) - (10)].number), (yyvsp[(8) - (10)].number), (yyvsp[(9) - (10)].number), &(yyvsp[(10) - (10)].drop)) == -1)
			yyerror("Could not add default route to %s",
			    addr_ntoa(&(yyvsp[(5) - (10)].addr)));
	}
    break;

  case 47:

/* Line 1806 of yacc.c  */
#line 570 "parse.y"
    {
		struct router *r;

		if ((r = router_find(&(yyvsp[(2) - (8)].addr))) == NULL &&
		    (r = router_new(&(yyvsp[(2) - (8)].addr))) == NULL) {
			yyerror("Cannot make forward reference for router %s",
			    addr_ntoa(&(yyvsp[(2) - (8)].addr)));
			break;
		}
		if (router_add_tunnel(r, &(yyvsp[(5) - (8)].addr), &(yyvsp[(7) - (8)].addr), &(yyvsp[(8) - (8)].addr)) == -1)
			yyerror("Could not add tunnel to %s", addr_ntoa(&(yyvsp[(8) - (8)].addr)));
	}
    break;

  case 48:

/* Line 1806 of yacc.c  */
#line 583 "parse.y"
    {
		struct router *r;

		if ((r = router_find(&(yyvsp[(2) - (4)].addr))) == NULL &&
		    (r = router_new(&(yyvsp[(2) - (4)].addr))) == NULL) {
			yyerror("Cannot make forward reference for router %s",
			    addr_ntoa(&(yyvsp[(2) - (4)].addr)));
			break;
		}
		if (router_add_link(r, &(yyvsp[(4) - (4)].addr)) == -1)
			yyerror("Could not add link %s", addr_ntoa(&(yyvsp[(4) - (4)].addr)));
	}
    break;

  case 49:

/* Line 1806 of yacc.c  */
#line 596 "parse.y"
    {
		struct router *r;

		if ((r = router_find(&(yyvsp[(2) - (4)].addr))) == NULL &&
		    (r = router_new(&(yyvsp[(2) - (4)].addr))) == NULL) {
			yyerror("Cannot make forward reference for router %s",
			    addr_ntoa(&(yyvsp[(2) - (4)].addr)));
			break;
		}
		if (router_add_unreach(r, &(yyvsp[(4) - (4)].addr)) == -1)
			yyerror("Could not add unreachable net %s",
			    addr_ntoa(&(yyvsp[(4) - (4)].addr)));
	}
    break;

  case 50:

/* Line 1806 of yacc.c  */
#line 610 "parse.y"
    { (yyval.number) = 1; }
    break;

  case 51:

/* Line 1806 of yacc.c  */
#line 611 "parse.y"
    { (yyval.number) = 0; }
    break;

  case 52:

/* Line 1806 of yacc.c  */
#line 613 "parse.y"
    { (yyval.fragp) = FRAG_DROP; }
    break;

  case 53:

/* Line 1806 of yacc.c  */
#line 614 "parse.y"
    { (yyval.fragp) = FRAG_OLD; }
    break;

  case 54:

/* Line 1806 of yacc.c  */
#line 615 "parse.y"
    { (yyval.fragp) = FRAG_NEW; }
    break;

  case 55:

/* Line 1806 of yacc.c  */
#line 618 "parse.y"
    {
		if (addr_pton((yyvsp[(1) - (1)].string), &(yyval.addr)) < 0)
			yyerror("Illegal IP address %s", (yyvsp[(1) - (1)].string));
		else
			yywarn("Parsed valid IP %s", (yyvsp[(1) - (1)].string));
			
		free((yyvsp[(1) - (1)].string));
	}
    break;

  case 56:

/* Line 1806 of yacc.c  */
#line 627 "parse.y"
    {
		struct addrinfo ai, *aitop;

		memset(&ai, 0, sizeof (ai));
		ai.ai_family = AF_INET;
		ai.ai_socktype = 0;
		ai.ai_flags = 0;

		/* Remove quotation marks */
		(yyvsp[(1) - (1)].string)[strlen((yyvsp[(1) - (1)].string)) - 1] = '\0';
		if (getaddrinfo((yyvsp[(1) - (1)].string)+1, NULL, &ai, &aitop) != 0) {
			yyerror("getaddrinfo failed: %s", (yyvsp[(1) - (1)].string)+1);
			break;
		}
		addr_ston(aitop->ai_addr, &(yyval.addr));
		freeaddrinfo(aitop);
		free((yyvsp[(1) - (1)].string));
	}
    break;

  case 57:

/* Line 1806 of yacc.c  */
#line 647 "parse.y"
    {
		if (addr_pton((yyvsp[(1) - (1)].string), &(yyval.addr)) < 0) {
			yyerror("Illegal IP address %s", (yyvsp[(1) - (1)].string));
		} else {
			yywarn("Parsed valid IP %s", (yyvsp[(1) - (1)].string));
		}
		
		free((yyvsp[(1) - (1)].string));
	}
    break;

  case 58:

/* Line 1806 of yacc.c  */
#line 657 "parse.y"
    {
		struct addrinfo ai, *aitop;

		memset(&ai, 0, sizeof (ai));
		ai.ai_family = AF_INET;
		ai.ai_socktype = 0;
		ai.ai_flags = 0;

		/* Remove quotation marks */
		(yyvsp[(1) - (1)].string)[strlen((yyvsp[(1) - (1)].string)) - 1] = '\0';
		if (getaddrinfo((yyvsp[(1) - (1)].string)+1, NULL, &ai, &aitop) != 0) {
			yyerror("getaddrinfo failed: %s", (yyvsp[(1) - (1)].string)+1);
			break;
		}
		addr_ston(aitop->ai_addr, &(yyval.addr));
		freeaddrinfo(aitop);
		free((yyvsp[(1) - (1)].string));
	}
    break;

  case 59:

/* Line 1806 of yacc.c  */
#line 677 "parse.y"
    {
		char src[25];
		struct addr b;
		snprintf(src, sizeof(src), "%s/%d",
		    addr_ntoa(&(yyvsp[(1) - (3)].addr)), (yyvsp[(3) - (3)].number));
		if (addr_pton(src, &(yyval.addr)) < 0)
			yyerror("Illegal IP network %s", src);
		/* Fix libdnet error */
		if ((yyvsp[(3) - (3)].number) == 0)
			(yyval.addr).addr_bits = 0;

		/* Test if this is a legal network */
		addr_net(&(yyval.addr), &b);
		b.addr_bits = (yyval.addr).addr_bits;
		if (memcmp(&(yyval.addr).addr_ip, &b.addr_ip, IP_ADDR_LEN)) {
			(yyval.addr) = b;
			yywarn("Bad network mask in %s", src);
		}
	}
    break;

  case 60:

/* Line 1806 of yacc.c  */
#line 698 "parse.y"
    {
		if (curtype == -1) {
			yyerror("Bad port type");
			break;
		}
		(yyval.ai) = cmd_proxy_getinfo(addr_ntoa(&(yyvsp[(1) - (3)].addr)), curtype, (yyvsp[(3) - (3)].number));
		curtype = -1;
		if ((yyval.ai) == NULL)
			yyerror("Illegal IP address port pair");
	}
    break;

  case 61:

/* Line 1806 of yacc.c  */
#line 710 "parse.y"
    {
		memset(&(yyval.action), 0, sizeof((yyval.action)));
		(yyval.action).action = (yyvsp[(2) - (2)].string);
		(yyval.action).flags = (yyvsp[(1) - (2)].number);
		(yyval.action).status = PORT_OPEN;
	}
    break;

  case 62:

/* Line 1806 of yacc.c  */
#line 717 "parse.y"
    {
		memset(&(yyval.action), 0, sizeof((yyval.action)));
		(yyvsp[(2) - (2)].string)[strlen((yyvsp[(2) - (2)].string)) - 1] = '\0';
		if (((yyval.action).action = strdup((yyvsp[(2) - (2)].string) + 1)) == NULL)
			yyerror("Out of memory");
		(yyval.action).status = PORT_OPEN;
		(yyval.action).flags = (yyvsp[(1) - (2)].number);
		free((yyvsp[(2) - (2)].string));
	}
    break;

  case 63:

/* Line 1806 of yacc.c  */
#line 727 "parse.y"
    {
#ifdef HAVE_PYTHON
		memset(&(yyval.action), 0, sizeof((yyval.action)));
		(yyvsp[(3) - (3)].string)[strlen((yyvsp[(3) - (3)].string)) - 1] = '\0';
		if (((yyval.action).action_extend = pyextend_load_module((yyvsp[(3) - (3)].string)+1)) == NULL)
			yyerror("Bad python module: \"%s\"", (yyvsp[(3) - (3)].string)+1);
		(yyval.action).status = PORT_PYTHON;
		(yyval.action).flags = (yyvsp[(1) - (3)].number);
		free((yyvsp[(3) - (3)].string));
#else
		yyerror("Python support is not available.");
#endif
	}
    break;

  case 64:

/* Line 1806 of yacc.c  */
#line 741 "parse.y"
    {
		memset(&(yyval.action), 0, sizeof((yyval.action)));
		(yyval.action).status = PORT_PROXY;
		(yyval.action).action = NULL;
		(yyval.action).aitop = (yyvsp[(3) - (3)].ai);
		(yyval.action).flags = (yyvsp[(1) - (3)].number);
	}
    break;

  case 65:

/* Line 1806 of yacc.c  */
#line 749 "parse.y"
    {
		memset(&(yyval.action), 0, sizeof((yyval.action)));
		(yyval.action).status = PORT_PROXY;
		(yyval.action).action = NULL;
		(yyval.action).aitop = NULL;
		(yyval.action).flags = (yyvsp[(1) - (5)].number);
		if ((yyvsp[(3) - (5)].string)[0] != '$') {
			if (curtype == -1) {
				yyerror("Bad port type");
				break;
			}
			(yyval.action).aitop = cmd_proxy_getinfo((yyvsp[(3) - (5)].string), curtype, (yyvsp[(5) - (5)].number));
			curtype = -1;
			if ((yyval.action).aitop == NULL)
				yyerror("Illegal host name in proxy");
		} else {
			char proxy[1024];

			snprintf(proxy, sizeof(proxy), "%s:%d", (yyvsp[(3) - (5)].string), (yyvsp[(5) - (5)].number));
			(yyval.action).action = strdup(proxy);
			if ((yyval.action).action == NULL)
				yyerror("Out of memory");
		}
		free((yyvsp[(3) - (5)].string));
	}
    break;

  case 66:

/* Line 1806 of yacc.c  */
#line 775 "parse.y"
    {
		char proxy[1024];
		memset(&(yyval.action), 0, sizeof((yyval.action)));
		(yyval.action).status = PORT_PROXY;
		(yyval.action).action = NULL;
		(yyval.action).aitop = NULL;
		(yyval.action).flags = (yyvsp[(1) - (5)].number);

		snprintf(proxy, sizeof(proxy), "%s:%s", (yyvsp[(3) - (5)].string), (yyvsp[(5) - (5)].string));
		(yyval.action).action = strdup(proxy);
		if ((yyval.action).action == NULL)
				yyerror("Out of memory");
		free((yyvsp[(3) - (5)].string));
		free((yyvsp[(5) - (5)].string));
	}
    break;

  case 67:

/* Line 1806 of yacc.c  */
#line 791 "parse.y"
    {
		char proxy[1024];
		memset(&(yyval.action), 0, sizeof((yyval.action)));
		(yyval.action).status = PORT_PROXY;
		(yyval.action).action = NULL;
		(yyval.action).aitop = NULL;
		(yyval.action).flags = (yyvsp[(1) - (5)].number);

		snprintf(proxy, sizeof(proxy), "%s:%s", addr_ntoa(&(yyvsp[(3) - (5)].addr)), (yyvsp[(5) - (5)].string));
		(yyval.action).action = strdup(proxy);
		if ((yyval.action).action == NULL)
				yyerror("Out of memory");
		free((yyvsp[(5) - (5)].string));
	}
    break;

  case 68:

/* Line 1806 of yacc.c  */
#line 806 "parse.y"
    {
		memset(&(yyval.action), 0, sizeof((yyval.action)));
		(yyval.action).status = PORT_FILTERED;
		(yyval.action).action = NULL;
	}
    break;

  case 69:

/* Line 1806 of yacc.c  */
#line 812 "parse.y"
    {
		memset(&(yyval.action), 0, sizeof((yyval.action)));
		(yyval.action).status = PORT_CLOSED;
		(yyval.action).action = NULL;
	}
    break;

  case 70:

/* Line 1806 of yacc.c  */
#line 818 "parse.y"
    {
		memset(&(yyval.action), 0, sizeof((yyval.action)));
		(yyval.action).status = PORT_OPEN;
		(yyval.action).action = NULL;
		(yyval.action).flags = (yyvsp[(1) - (2)].number);
	}
    break;

  case 71:

/* Line 1806 of yacc.c  */
#line 827 "parse.y"
    {
		(yyval.tmpl) = template_find((yyvsp[(1) - (1)].string));
		if ((yyval.tmpl) == NULL)
			yyerror("Unknown template \"%s\"", (yyvsp[(1) - (1)].string));
		free((yyvsp[(1) - (1)].string));
	}
    break;

  case 72:

/* Line 1806 of yacc.c  */
#line 834 "parse.y"
    {
		(yyval.tmpl) = template_find("template");
		if ((yyval.tmpl) == NULL)
			yyerror("Unknown template \"%s\"", "template");
	}
    break;

  case 73:

/* Line 1806 of yacc.c  */
#line 840 "parse.y"
    {
		(yyval.tmpl) = template_find("default");
		if ((yyval.tmpl) == NULL)
			yyerror("Unknown template \"%s\"", "default");
	}
    break;

  case 74:

/* Line 1806 of yacc.c  */
#line 846 "parse.y"
    {
		(yyval.tmpl) = template_find(addr_ntoa(&(yyvsp[(1) - (1)].addr)));
		if ((yyval.tmpl) == NULL)
			yyerror("Unknown template \"%s\"", addr_ntoa(&(yyvsp[(1) - (1)].addr)));
	}
    break;

  case 75:

/* Line 1806 of yacc.c  */
#line 853 "parse.y"
    {
		(yyvsp[(1) - (1)].string)[strlen((yyvsp[(1) - (1)].string)) - 1] = '\0';
		(yyval.pers) = personality_find((yyvsp[(1) - (1)].string)+1);
		if ((yyval.pers) == NULL)
			yyerror("Unknown personality \"%s\"", (yyvsp[(1) - (1)].string)+1);
		free((yyvsp[(1) - (1)].string));
	}
    break;

  case 76:

/* Line 1806 of yacc.c  */
#line 861 "parse.y"
    {
		(yyval.pers) = personality_random();
		if ((yyval.pers) == NULL)
			yyerror("Random personality failed");
	}
    break;

  case 77:

/* Line 1806 of yacc.c  */
#line 868 "parse.y"
    {
		(yyval.floatp) = (yyvsp[(1) - (1)].floatp);
	}
    break;

  case 78:

/* Line 1806 of yacc.c  */
#line 872 "parse.y"
    {
		(yyval.floatp) = (yyvsp[(1) - (1)].number);
	}
    break;

  case 79:

/* Line 1806 of yacc.c  */
#line 876 "parse.y"
    { (yyval.number) = 0; }
    break;

  case 80:

/* Line 1806 of yacc.c  */
#line 878 "parse.y"
    {
		(yyval.number) = (yyvsp[(2) - (3)].number);
	}
    break;

  case 81:

/* Line 1806 of yacc.c  */
#line 882 "parse.y"
    { (yyval.number) = 0; }
    break;

  case 82:

/* Line 1806 of yacc.c  */
#line 884 "parse.y"
    {
		(yyval.number) = (yyvsp[(2) - (2)].floatp) * 100;
	}
    break;

  case 83:

/* Line 1806 of yacc.c  */
#line 888 "parse.y"
    { (yyval.number) = 0; }
    break;

  case 84:

/* Line 1806 of yacc.c  */
#line 890 "parse.y"
    {
		(yyval.number) = (yyvsp[(2) - (3)].number) * (yyvsp[(3) - (3)].number);
	}
    break;

  case 85:

/* Line 1806 of yacc.c  */
#line 894 "parse.y"
    {
		(yyval.number) = (yyvsp[(2) - (2)].number);
	}
    break;

  case 86:

/* Line 1806 of yacc.c  */
#line 898 "parse.y"
    { memset(&(yyval.drop), 0, sizeof((yyval.drop))); }
    break;

  case 87:

/* Line 1806 of yacc.c  */
#line 900 "parse.y"
    {
		if ((yyvsp[(6) - (7)].number) <= (yyvsp[(3) - (7)].number))
			yyerror("Incorrect thresholds. First number needs to "
				"be smaller than second number.");
		(yyval.drop).low = (yyvsp[(3) - (7)].number);
		(yyval.drop).high = (yyvsp[(6) - (7)].number);
	}
    break;

  case 88:

/* Line 1806 of yacc.c  */
#line 909 "parse.y"
    {
		struct honeyd_plugin_cfg cfg;

		memset(&cfg, 0, sizeof(struct honeyd_plugin_cfg));
		cfg.cfg_int = (yyvsp[(4) - (4)].number);
		cfg.cfg_type = HD_CONFIG_INT;
		plugins_config_item_add((yyvsp[(2) - (4)].string), (yyvsp[(3) - (4)].string), &cfg);
		
		free((yyvsp[(2) - (4)].string)); free((yyvsp[(3) - (4)].string));
	}
    break;

  case 89:

/* Line 1806 of yacc.c  */
#line 920 "parse.y"
    {
		struct honeyd_plugin_cfg cfg;

		memset(&cfg, 0, sizeof(struct honeyd_plugin_cfg));
		cfg.cfg_flt = (yyvsp[(4) - (4)].floatp);
		cfg.cfg_type = HD_CONFIG_FLT;
		plugins_config_item_add((yyvsp[(2) - (4)].string), (yyvsp[(3) - (4)].string), &cfg);

		free((yyvsp[(2) - (4)].string)); free((yyvsp[(3) - (4)].string));
        }
    break;

  case 90:

/* Line 1806 of yacc.c  */
#line 931 "parse.y"
    {
		struct honeyd_plugin_cfg cfg;

		memset(&cfg, 0, sizeof(struct honeyd_plugin_cfg));
		cfg.cfg_str = (yyvsp[(4) - (4)].string);
		cfg.cfg_type = HD_CONFIG_STR;
		plugins_config_item_add((yyvsp[(2) - (4)].string), (yyvsp[(3) - (4)].string), &cfg);

		free((yyvsp[(2) - (4)].string)); free((yyvsp[(3) - (4)].string)); free((yyvsp[(4) - (4)].string));
        }
    break;

  case 91:

/* Line 1806 of yacc.c  */
#line 943 "parse.y"
    {
		struct honeyd_plugin_cfg cfg;
		char path[MAXPATHLEN];

		snprintf(path, sizeof(path), "/%s", (yyvsp[(5) - (5)].string));

		memset(&cfg, 0, sizeof(struct honeyd_plugin_cfg));
		cfg.cfg_str = path;
		cfg.cfg_type = HD_CONFIG_STR;
		plugins_config_item_add((yyvsp[(2) - (5)].string), (yyvsp[(3) - (5)].string), &cfg);

		free((yyvsp[(2) - (5)].string)); free((yyvsp[(3) - (5)].string)); free((yyvsp[(5) - (5)].string));
        }
    break;

  case 92:

/* Line 1806 of yacc.c  */
#line 959 "parse.y"
    {
	template_list_glob(buffer, "*");
}
    break;

  case 93:

/* Line 1806 of yacc.c  */
#line 963 "parse.y"
    {
	(yyvsp[(3) - (3)].string)[strlen((yyvsp[(3) - (3)].string))-1] = '\0';

	template_list_glob(buffer, (yyvsp[(3) - (3)].string)+1);

	free ((yyvsp[(3) - (3)].string));
}
    break;

  case 94:

/* Line 1806 of yacc.c  */
#line 971 "parse.y"
    {
	template_list_glob(buffer, (yyvsp[(3) - (3)].string));
}
    break;

  case 95:

/* Line 1806 of yacc.c  */
#line 975 "parse.y"
    {
	template_subsystem_list_glob(buffer, "*");
}
    break;

  case 96:

/* Line 1806 of yacc.c  */
#line 979 "parse.y"
    {
	template_subsystem_list_glob(buffer, (yyvsp[(3) - (3)].string));
}
    break;

  case 97:

/* Line 1806 of yacc.c  */
#line 983 "parse.y"
    {
	(yyvsp[(3) - (3)].string)[strlen((yyvsp[(3) - (3)].string))-1] = '\0';
	template_subsystem_list_glob(buffer, (yyvsp[(3) - (3)].string)+1);
	free((yyvsp[(3) - (3)].string));
}
    break;

  case 98:

/* Line 1806 of yacc.c  */
#line 989 "parse.y"
    {
	if (strcasecmp((yyvsp[(2) - (3)].string), "fd") == 0) {
		yyprintf("%d: %d\n", (yyvsp[(3) - (3)].number), fdshare_inspect((yyvsp[(3) - (3)].number)));
	} else if (strcasecmp((yyvsp[(2) - (3)].string), "trace") == 0) {
		struct evbuffer *evbuf = evbuffer_new();
		if (evbuf == NULL)
			err(1, "%s: malloc");

		trace_inspect((yyvsp[(3) - (3)].number), evbuf);

		yyprintf("%s", EVBUFFER_DATA(evbuf));

		evbuffer_free(evbuf);
	} else {
		yyerror("Unsupported debug command: \"%s\"\n", (yyvsp[(2) - (3)].string));
	}
	free((yyvsp[(2) - (3)].string));
}
    break;

  case 99:

/* Line 1806 of yacc.c  */
#line 1009 "parse.y"
    {
	(yyval.number) = 0;
}
    break;

  case 100:

/* Line 1806 of yacc.c  */
#line 1013 "parse.y"
    {
	(yyval.number) = 1;
}
    break;

  case 101:

/* Line 1806 of yacc.c  */
#line 1019 "parse.y"
    {
	(yyval.number) = 0;
}
    break;

  case 102:

/* Line 1806 of yacc.c  */
#line 1023 "parse.y"
    {
	(yyval.number) = 1;
}
    break;

  case 103:

/* Line 1806 of yacc.c  */
#line 1029 "parse.y"
    {
	(yyval.number) = 0;
}
    break;

  case 104:

/* Line 1806 of yacc.c  */
#line 1033 "parse.y"
    {
	(yyval.number) = PORT_TARPIT;
}
    break;

  case 105:

/* Line 1806 of yacc.c  */
#line 1039 "parse.y"
    {
		pf_osfp_t fp;
		(yyvsp[(4) - (4)].string)[strlen((yyvsp[(4) - (4)].string)) - 1] = '\0';
		if ((fp = pfctl_get_fingerprint((yyvsp[(4) - (4)].string)+1)) == PF_OSFP_NOMATCH)
			yyerror("Unknown fingerprint \"%s\"", (yyvsp[(4) - (4)].string)+1);
		if (((yyval.condition).match_arg = malloc(sizeof(fp))) == NULL)
			yyerror("Out of memory");
		memcpy((yyval.condition).match_arg, &fp, sizeof(fp));
		(yyval.condition).match = condition_match_osfp;
		(yyval.condition).match_arglen = sizeof(fp);
		free ((yyvsp[(4) - (4)].string));
	}
    break;

  case 106:

/* Line 1806 of yacc.c  */
#line 1052 "parse.y"
    {
		if (((yyval.condition).match_arg = malloc(sizeof(struct addr))) == NULL)
			yyerror("Out of memory");
		memcpy((yyval.condition).match_arg, &(yyvsp[(4) - (4)].addr), sizeof(struct addr));
		(yyval.condition).match = condition_match_addr;
		(yyval.condition).match_arglen = sizeof(struct addr);
	}
    break;

  case 107:

/* Line 1806 of yacc.c  */
#line 1060 "parse.y"
    {
		if (((yyval.condition).match_arg = malloc(sizeof(struct addr))) == NULL)
			yyerror("Out of memory");
		memcpy((yyval.condition).match_arg, &(yyvsp[(4) - (4)].addr), sizeof(struct addr));
		(yyval.condition).match = condition_match_addr;
		(yyval.condition).match_arglen = sizeof(struct addr);
	}
    break;

  case 108:

/* Line 1806 of yacc.c  */
#line 1068 "parse.y"
    {
		if (((yyval.condition).match_arg = malloc(sizeof(struct condition_time))) == NULL)
			yyerror("Out of memory");
		memcpy((yyval.condition).match_arg, &(yyvsp[(2) - (2)].timecondition), sizeof(struct condition_time));
		(yyval.condition).match = condition_match_time;
		(yyval.condition).match_arglen = sizeof(struct condition_time);
	}
    break;

  case 109:

/* Line 1806 of yacc.c  */
#line 1076 "parse.y"
    {
		if (((yyval.condition).match_arg = malloc(sizeof(struct addr))) == NULL)
			yyerror("Out of memory");
		memcpy((yyval.condition).match_arg, &(yyvsp[(1) - (1)].number), sizeof(int));
		(yyval.condition).match = condition_match_proto;
		(yyval.condition).match_arglen = sizeof(int);
	}
    break;

  case 110:

/* Line 1806 of yacc.c  */
#line 1084 "parse.y"
    {
		(yyval.condition).match_arg = 0;
		(yyval.condition).match = condition_match_otherwise;
		(yyval.condition).match_arglen = 0;
	}
    break;

  case 111:

/* Line 1806 of yacc.c  */
#line 1092 "parse.y"
    {
		(yyval.timecondition).tm_start = (yyvsp[(2) - (4)].time);
		(yyval.timecondition).tm_end = (yyvsp[(4) - (4)].time);
	}
    break;

  case 112:

/* Line 1806 of yacc.c  */
#line 1099 "parse.y"
    {
		int ispm = -1;
		int hour, minute;

		if (strcmp((yyvsp[(4) - (4)].string), "am") == 0) {
			ispm = 0;
		} else if (strcmp((yyvsp[(4) - (4)].string), "pm") == 0) {
			ispm = 1;
		} else {
			yyerror("Bad time specifier, use 'am' or 'pm': %s", (yyvsp[(4) - (4)].string));
			break;
		}
		free ((yyvsp[(4) - (4)].string));

		hour = (yyvsp[(1) - (4)].number) + (ispm ? 12 : 0);
		minute = (yyvsp[(3) - (4)].number);

		memset(&(yyval.time), 0, sizeof((yyval.time)));
		(yyval.time).tm_hour = hour;
		(yyval.time).tm_min = minute;
	}
    break;

  case 113:

/* Line 1806 of yacc.c  */
#line 1121 "parse.y"
    {
		char *time = (yyvsp[(1) - (1)].string) + 1;
		time[strlen(time)-1] = '\0';

		if (strptime(time, "%T", &(yyval.time)) != NULL) {
			; /* done */
		} else if (strptime(time, "%r", &(yyval.time)) != NULL) {
			; /* done */
		} else {
			yyerror("Bad time specification; use \"hh:mm:ss\"");
		}

		free((yyvsp[(1) - (1)].string));
	}
    break;



/* Line 1806 of yacc.c  */
#line 3243 "parse.c"
      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;

  /* Now `shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*------------------------------------.
| yyerrlab -- here on detecting error |
`------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYEMPTY : YYTRANSLATE (yychar);

  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (YY_("syntax error"));
#else
# define YYSYNTAX_ERROR yysyntax_error (&yymsg_alloc, &yymsg, \
                                        yyssp, yytoken)
      {
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = YYSYNTAX_ERROR;
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == 1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = (char *) YYSTACK_ALLOC (yymsg_alloc);
            if (!yymsg)
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = 2;
              }
            else
              {
                yysyntax_error_status = YYSYNTAX_ERROR;
                yymsgp = yymsg;
              }
          }
        yyerror (yymsgp);
        if (yysyntax_error_status == 2)
          goto yyexhaustedlab;
      }
# undef YYSYNTAX_ERROR
#endif
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
	 error, discard it.  */

      if (yychar <= YYEOF)
	{
	  /* Return failure if at end of input.  */
	  if (yychar == YYEOF)
	    YYABORT;
	}
      else
	{
	  yydestruct ("Error: discarding",
		      yytoken, &yylval);
	  yychar = YYEMPTY;
	}
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:

  /* Pacify compilers like GCC when the user code never invokes
     YYERROR and the label yyerrorlab therefore never appears in user
     code.  */
  if (/*CONSTCOND*/ 0)
     goto yyerrorlab;

  /* Do not reclaim the symbols of the rule which action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;	/* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
	{
	  yyn += YYTERROR;
	  if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
	    {
	      yyn = yytable[yyn];
	      if (0 < yyn)
		break;
	    }
	}

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
	YYABORT;


      yydestruct ("Error: popping",
		  yystos[yystate], yyvsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  *++yyvsp = yylval;


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

#if !defined(yyoverflow) || YYERROR_VERBOSE
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval);
    }
  /* Do not reclaim the symbols of the rule which action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
		  yystos[*yyssp], yyvsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  /* Make sure YYID is used.  */
  return YYID (yyresult);
}



/* Line 2067 of yacc.c  */
#line 1136 "parse.y"


static void
dhcp_template(struct template *tmpl, char *interface, char *mac_addr)
{
	struct interface *inter;
	struct template *newtmpl;
	struct addr addr;
	extern int need_dhcp;
	extern int need_arp;

	if (mac_addr == NULL && tmpl->ethernet_addr == NULL) {
		yyerror("Need an ethernet address for DHCP.");
		return;
	}

	/* Find the right interface */
	if ((inter = interface_find(interface)) == NULL) {
		yyerror("Interface \"%s\" does not exist.", interface);
		return;
	}
	if (inter->if_ent.intf_link_addr.addr_type != ADDR_TYPE_ETH) {
		yyerror("Interface \"%s\" does not support ARP.", interface);
		return;
	}

	/* Need to find a temporary IP address */
	if (template_get_dhcp_address(&addr) == -1) {
		yyerror("Failed to obtain temporary IP address.");
		return;
	}

	newtmpl = template_clone(addr_ntoa(&addr), tmpl, inter, 1);
	if (newtmpl == NULL) {
		yyerror("Binding to %s failed", addr_ntoa(&addr));
		return;
	}
	
	newtmpl->addrbits = inter->if_addrbits;

	if (mac_addr != NULL) {
		/*
		 * This is more complicated than it should be.
		 * 1. Remove existing ARP table entries.
		 * 2. Set new ethernet MAC address
		 * 3. Assign interface to template
		 * 4. Post new ARP table entry.
		 */
		template_remove_arp(newtmpl);

		newtmpl->ethernet_addr = ethernetcode_make_address(mac_addr);
		if (newtmpl->ethernet_addr == NULL) {
			yyerror("Unknown ethernet vendor \"%s\"", mac_addr);
		}

		newtmpl->inter = inter;

		/* We need to update the ARP binding */
		template_post_arp(newtmpl, &addr);
	}

	/* We can ignore the rest if we just verify the configuration */
	if (honeyd_verify_config)
		return;

	/* Wow - now we can assign the DHCP object to it */
	queue_dhcp_discover(newtmpl);

	need_arp = need_dhcp = 1;
}

int
yyerror(char *fmt, ...)
{
	va_list ap;
	errors = 1;

	va_start(ap, fmt);
	if (buffer == NULL) {
		fprintf(stderr, "%s:%d: ", filename, lineno);
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
	} else {
		char *data;
		if (vasprintf(&data, fmt, ap) == -1)
			err(1, "%s: vasprintf", __func__);
		evbuffer_add_printf(buffer, "%s: %s\n", filename, data);
		free(data);
	}
	va_end(ap);
	return (0);
}

int
yywarn(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (buffer == NULL) {
		fprintf(stderr, "%s:%d: ", filename, lineno);
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
	} else {
		char *data;
		if (vasprintf(&data, fmt, ap) == -1)
			err(1, "%s: vasprintf", __func__);
		evbuffer_add_printf(buffer, "%s: %s\n", filename, data);
		free(data);
	}
	va_end(ap);
	return (0);
}

int
yyprintf(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (buffer == NULL) {
		vfprintf(stdout, fmt, ap);
	} else {
		char *data;
		if (vasprintf(&data, fmt, ap) == -1)
			err(1, "%s: vasprintf", __func__);
		evbuffer_add_printf(buffer, "%s", data);
		free(data);
	}
	va_end(ap);
	return (0);
}

int
parse_configuration(FILE *input, char *name)
{
	extern FILE *yyin;

	buffer = NULL;
	errors = 0;
	lineno = 1;
	filename = name;
	yyin = input;
	yyparse();
	return (errors ? -1 : 0);
}

/*
 * Parse from memory.  Error output is buffered
 */

int
parse_line(struct evbuffer *output, char *line)
{
	void *yybuf;

	buffer = output;
	errors = 0;
	lineno = 1;
	filename = "<stdin>";
	yybuf = yy_scan_string(line);
	yyparse();
	yy_delete_buffer(yybuf);
	return (errors ? -1 : 0);
}

