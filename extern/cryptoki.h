#ifndef _CRYPTOKI_H_
#define _CRYPTOKI_H_ 1

/* MIT License */

/* Copyright (c) 2019 Eric Devolder */

/* Permission is hereby granted, free of charge, to any person obtaining  */
/* a copy of this software and associated documentation files (the        */
/* "Software"), to deal in the Software without restriction, including    */
/* without limitation the rights to use, copy, modify, merge, publish,    */
/* distribute, sublicense, and/or sell copies of the Software, and to     */
/* permit persons to whom the Software is furnished to do so, subject to  */
/* the following conditions:                                              */

/* The above copyright notice and this permission notice shall be         */
/* included in all copies or substantial portions of the Software.        */

/* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,        */
/* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF     */
/* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND                  */
/* NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE */
/* LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION */
/* OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION  */
/* WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.        */


#ifdef __cplusplus
extern "C" {
#endif

#if defined(__CYGWIN64__)
#pragma warning "Cygwin 64 bits build will only work with Cygwin64-compiled PKCS#11 modules"
#endif

/* Use the public domain PKCS#11 v3.2 header from the Kryoptic project.
 * The original OASIS multi-file headers (pkcs11.h / pkcs11t.h / pkcs11f.h)
 * are retained for reference only; this wrapper now includes pkcs11_v32.h
 * which is fully self-contained and placed in the Public Domain. */
#include "pkcs11_v32.h"

/* python-pkcs11 extension: sentinel value for non-logged-in sessions.
 * Not part of the PKCS#11 spec — used internally to distinguish
 * "no login" from CKU_SO / CKU_USER / CKU_CONTEXT_SPECIFIC. */
#define CKU_USER_NOBODY         999UL

#ifdef __cplusplus
}
#endif

#endif /* _CRYPTOKI_H_ */

