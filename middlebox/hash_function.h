#ifndef HASH_FUNCTION_H
#define HASH_FUNCTION_H

/* hash function from http://www.azillionmonkeys.com/qed/hash.html */

#include "stdint.h"		/* Replace with <stdint.h> if appropriate */

#undef get16bits
#if (defined(__GNUC__) && defined(__i386__)) || defined(__WATCOMC__) \
	  || defined(_MSC_VER) || defined (__BORLANDC__) || defined (__TURBOC__)
#define get16bits(d) (*((const uint16_t *) (d)))
#endif

#if !defined (get16bits)
#define get16bits(d) ((((const uint8_t *)(d))[1] << UINT32_C(8))\
		                      +((const uint8_t *)(d))[0])
#endif

uint32_t __hash(const char *data, int len);

#endif
