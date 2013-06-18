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
     BIND = 262,
     CLONE = 263,
     DOT = 264,
     FILTERED = 265,
     OPEN = 266,
     CLOSED = 267,
     DEFAULT = 268,
     SET = 269,
     ACTION = 270,
     PERSONALITY = 271,
     RANDOM = 272,
     ANNOTATE = 273,
     NO = 274,
     FINSCAN = 275,
     FRAGMENT = 276,
     DROP = 277,
     OLD = 278,
     NEW = 279,
     COLON = 280,
     PROXY = 281,
     UPTIME = 282,
     DROPRATE = 283,
     IN = 284,
     SYN = 285,
     UID = 286,
     GID = 287,
     ROUTE = 288,
     ENTRY = 289,
     LINK = 290,
     NET = 291,
     UNREACH = 292,
     SLASH = 293,
     LATENCY = 294,
     MS = 295,
     LOSS = 296,
     BANDWIDTH = 297,
     SUBSYSTEM = 298,
     OPTION = 299,
     TO = 300,
     SHARED = 301,
     NETWORK = 302,
     SPOOF = 303,
     FROM = 304,
     TEMPLATE = 305,
     BROADCAST = 306,
     TUNNEL = 307,
     TARPIT = 308,
     DYNAMIC = 309,
     USE = 310,
     IF = 311,
     OTHERWISE = 312,
     EQUAL = 313,
     SOURCE = 314,
     OS = 315,
     IP = 316,
     BETWEEN = 317,
     DELETE = 318,
     LIST = 319,
     ETHERNET = 320,
     DHCP = 321,
     ON = 322,
     MAXFDS = 323,
     RESTART = 324,
     DEBUG = 325,
     DASH = 326,
     TIME = 327,
     INTERNAL = 328,
     STRING = 329,
     CMDSTRING = 330,
     IPSTRING = 331,
     NUMBER = 332,
     PROTO = 333,
     FLOAT = 334
   };
#endif
/* Tokens.  */
#define CREATE 258
#define ADD 259
#define BCAST 260
#define PORT 261
#define BIND 262
#define CLONE 263
#define DOT 264
#define FILTERED 265
#define OPEN 266
#define CLOSED 267
#define DEFAULT 268
#define SET 269
#define ACTION 270
#define PERSONALITY 271
#define RANDOM 272
#define ANNOTATE 273
#define NO 274
#define FINSCAN 275
#define FRAGMENT 276
#define DROP 277
#define OLD 278
#define NEW 279
#define COLON 280
#define PROXY 281
#define UPTIME 282
#define DROPRATE 283
#define IN 284
#define SYN 285
#define UID 286
#define GID 287
#define ROUTE 288
#define ENTRY 289
#define LINK 290
#define NET 291
#define UNREACH 292
#define SLASH 293
#define LATENCY 294
#define MS 295
#define LOSS 296
#define BANDWIDTH 297
#define SUBSYSTEM 298
#define OPTION 299
#define TO 300
#define SHARED 301
#define NETWORK 302
#define SPOOF 303
#define FROM 304
#define TEMPLATE 305
#define BROADCAST 306
#define TUNNEL 307
#define TARPIT 308
#define DYNAMIC 309
#define USE 310
#define IF 311
#define OTHERWISE 312
#define EQUAL 313
#define SOURCE 314
#define OS 315
#define IP 316
#define BETWEEN 317
#define DELETE 318
#define LIST 319
#define ETHERNET 320
#define DHCP 321
#define ON 322
#define MAXFDS 323
#define RESTART 324
#define DEBUG 325
#define DASH 326
#define TIME 327
#define INTERNAL 328
#define STRING 329
#define CMDSTRING 330
#define IPSTRING 331
#define NUMBER 332
#define PROTO 333
#define FLOAT 334




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
#line 226 "parse.h"
} YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
#endif

extern YYSTYPE yylval;


