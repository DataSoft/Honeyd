
/* A Bison parser, made by GNU Bison 2.4.1.  */

/* Skeleton interface for Bison's Yacc-like parsers in C
   
      Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005, 2006
   Free Software Foundation, Inc.
   
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
     PORT = 260,
     BIND = 261,
     CLONE = 262,
     DOT = 263,
     BLOCK = 264,
     OPEN = 265,
     RESET = 266,
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
     TUNNEL = 305,
     TARPIT = 306,
     DYNAMIC = 307,
     USE = 308,
     IF = 309,
     OTHERWISE = 310,
     EQUAL = 311,
     SOURCE = 312,
     OS = 313,
     IP = 314,
     BETWEEN = 315,
     DELETE = 316,
     LIST = 317,
     ETHERNET = 318,
     DHCP = 319,
     ON = 320,
     MAXFDS = 321,
     RESTART = 322,
     DEBUG = 323,
     DASH = 324,
     TIME = 325,
     INTERNAL = 326,
     STRING = 327,
     CMDSTRING = 328,
     IPSTRING = 329,
     NUMBER = 330,
     PROTO = 331,
     FLOAT = 332
   };
#endif
/* Tokens.  */
#define CREATE 258
#define ADD 259
#define PORT 260
#define BIND 261
#define CLONE 262
#define DOT 263
#define BLOCK 264
#define OPEN 265
#define RESET 266
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
#define TUNNEL 305
#define TARPIT 306
#define DYNAMIC 307
#define USE 308
#define IF 309
#define OTHERWISE 310
#define EQUAL 311
#define SOURCE 312
#define OS 313
#define IP 314
#define BETWEEN 315
#define DELETE 316
#define LIST 317
#define ETHERNET 318
#define DHCP 319
#define ON 320
#define MAXFDS 321
#define RESTART 322
#define DEBUG 323
#define DASH 324
#define TIME 325
#define INTERNAL 326
#define STRING 327
#define CMDSTRING 328
#define IPSTRING 329
#define NUMBER 330
#define PROTO 331
#define FLOAT 332




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
{

/* Line 1676 of yacc.c  */
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



/* Line 1676 of yacc.c  */
#line 224 "parse.h"
} YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
#endif

extern YYSTYPE yylval;


