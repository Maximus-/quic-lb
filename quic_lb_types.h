/*
 * Copyright (c) 2020 F5 Networks Inc.
 * This source code is subject to the terms of the Apache License,
 * version 2.0 (https://www.apache.org/licenses/LICENSE-2.0)
 */

#ifndef _QUIC_LB_TYPES
#define _QUIC_LB_TYPES

#define malloc(size) umalloc(size, M_FILTER, UM_ZERO);
#define free(arg) ufree(arg)
#define assert(arg)

#define RAND_bytes(ptr,len) rndset(ptr, RND_PSEUDO, len)

#define rnd8_range(arg) rnd8_range(RND_PSEUDO, arg)
#define rnd16_range(arg) rnd16_range(RND_PSEUDO, arg)
#endif // _QUIC_LB_TYPES
