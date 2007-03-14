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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef _DEBUG_H_
#define _DEBUG_H_

#ifdef HONEYD_DEBUG

/**
 * D - prints debugging output
 * @x: debugging information.
 *
 * Use this macro to output debugging information. @x is
 * the content as you would pass it to printf(), including
 * braces to make the arguments appear as one argument to
 * the macro. The macro is automatically deleted if -DDEBUG
 * is not passed at build time.
 */
#define D(x)                  do { printf("%s/%i: ", __FILE__, __LINE__); printf x ; } while (0)

/**
 * D_ASSERT - debugging assertion.
 * @exp: expression to evaluate.
 * @msg: message to output if @exp fails.
 *
 * The macro outputs @msg if the expression @exp evaluates
 * to %FALSE.
 */
#define D_ASSERT(exp, msg)    if (! exp) { printf("%s/%i: %s\n", __FILE__, __LINE__, msg); }

/**
 * D_ASSERT_PTR - pointer existence assertion.
 * @ptr: pointer to check.
 *
 * The macro asserts the existence (i.e. non-NULL-ness) of
 * the given pointer, and outpus a message if it is %NULL.
 */
#define D_ASSERT_PTR(ptr)     D_ASSERT(ptr, "pointer is NULL.")

#else
#define D(x)                  
#define D_ASSERT(exp, msg)    
#define D_ASSERT_PTR(ptr)     
#endif

#endif 

