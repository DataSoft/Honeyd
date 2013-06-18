/* A Bison parser, made by GNU Bison 2.5.  */

/* Bison interface for Yacc-like parsers in C
   
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


/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     CREATE = 258,
     ADD = 259,
     BCAST = 260,
     PORT = 261,
     SRCPORT = 262,
     DSTPORT = 263,
     BIND = 264,
     CLONE = 265,
     DOT = 266,
     FILTERED = 267,
     OPEN = 268,
     CLOSED = 269,
     DEFAULT = 270,
     SET = 271,
     ACTION = 272,
     PERSONALITY = 273,
     RANDOM = 274,
     ANNOTATE = 275,
     NO = 276,
     FINSCAN = 277,
     FRAGMENT = 278,
     DROP = 279,
     OLD = 280,
     NEW = 281,
     COLON = 282,
     PROXY = 283,
     UPTIME = 284,
     DROPRATE = 285,
     IN = 286,
     SYN = 287,
     UID = 288,
     GID = 289,
     ROUTE = 290,
     ENTRY = 291,
     LINK = 292,
     NET = 293,
     UNREACH = 294,
     SLASH = 295,
     LATENCY = 296,
     MS = 297,
     LOSS = 298,
     BANDWIDTH = 299,
     SUBSYSTEM = 300,
     OPTION = 301,
     TO = 302,
     SHARED = 303,
     NETWORK = 304,
     SPOOF = 305,
     FROM = 306,
     TEMPLATE = 307,
     BROADCAST = 308,
     TUNNEL = 309,
     TARPIT = 310,
     DYNAMIC = 311,
     USE = 312,
     IF = 313,
     OTHERWISE = 314,
     EQUAL = 315,
     SOURCE = 316,
     OS = 317,
     IP = 318,
     BETWEEN = 319,
     DELETE = 320,
     LIST = 321,
     ETHERNET = 322,
     DHCP = 323,
     ON = 324,
     MAXFDS = 325,
     RESTART = 326,
     DEBUG = 327,
     DASH = 328,
     TIME = 329,
     INTERNAL = 330,
     STRING = 331,
     CMDSTRING = 332,
     IPSTRING = 333,
     NUMBER = 334,
     PROTO = 335,
     FLOAT = 336
   };
#endif
/* Tokens.  */
#define CREATE 258
#define ADD 259
#define BCAST 260
#define PORT 261
#define SRCPORT 262
#define DSTPORT 263
#define BIND 264
#define CLONE 265
#define DOT 266
#define FILTERED 267
#define OPEN 268
#define CLOSED 269
#define DEFAULT 270
#define SET 271
#define ACTION 272
#define PERSONALITY 273
#define RANDOM 274
#define ANNOTATE 275
#define NO 276
#define FINSCAN 277
#define FRAGMENT 278
#define DROP 279
#define OLD 280
#define NEW 281
#define COLON 282
#define PROXY 283
#define UPTIME 284
#define DROPRATE 285
#define IN 286
#define SYN 287
#define UID 288
#define GID 289
#define ROUTE 290
#define ENTRY 291
#define LINK 292
#define NET 293
#define UNREACH 294
#define SLASH 295
#define LATENCY 296
#define MS 297
#define LOSS 298
#define BANDWIDTH 299
#define SUBSYSTEM 300
#define OPTION 301
#define TO 302
#define SHARED 303
#define NETWORK 304
#define SPOOF 305
#define FROM 306
#define TEMPLATE 307
#define BROADCAST 308
#define TUNNEL 309
#define TARPIT 310
#define DYNAMIC 311
#define USE 312
#define IF 313
#define OTHERWISE 314
#define EQUAL 315
#define SOURCE 316
#define OS 317
#define IP 318
#define BETWEEN 319
#define DELETE 320
#define LIST 321
#define ETHERNET 322
#define DHCP 323
#define ON 324
#define MAXFDS 325
#define RESTART 326
#define DEBUG 327
#define DASH 328
#define TIME 329
#define INTERNAL 330
#define STRING 331
#define CMDSTRING 332
#define IPSTRING 333
#define NUMBER 334
#define PROTO 335
#define FLOAT 336




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
{

/* Line 2068 of yacc.c  */
#line 139 "parse.y"

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



/* Line 2068 of yacc.c  */
#line 230 "parse.h"
} YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
#endif

extern YYSTYPE yylval;


