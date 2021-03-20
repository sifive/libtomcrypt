/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "tomcrypt.h"

/**
  @file sm3.c
  LTC_SM3 code by Tom St Denis
*/


#ifdef LTC_SM3

/* forward declare */
void sm3_compress_blocks(ulong32 digest[8],
    const unsigned char *data, size_t blocks);
void sm3_compress(ulong32 digest[8], const unsigned char block[64]);


const struct ltc_hash_descriptor sm3_desc =
{
    "sm3",              /* name */
    NID_HASH_SM3,       /* ID */
    SM3_DIGEST_LENGTH,  /* hashsize */
    SM3_BLOCK_SIZE,     /* blocksize */

    /* OID */
    { 1, 2, 156, 10197, 1, 401, },
    6,      /* OIDlen */

    &sm3_init,
    &sm3_process,
    &sm3_done,
    &sm3_test,
    NULL
};


/**
   Initialize the hash state
   @param md   The hash state you wish to initialize
   @return CRYPT_OK if successful
*/
int sm3_init(hash_state * md)
{
    sm3_ctx_t *ctx = &(md->sm3);

    memset(ctx, 0, sizeof(*ctx));
    ctx->digest[0] = 0x7380166F;
    ctx->digest[1] = 0x4914B2B9;
    ctx->digest[2] = 0x172442D7;
    ctx->digest[3] = 0xDA8A0600;
    ctx->digest[4] = 0xA96F30BC;
    ctx->digest[5] = 0x163138AA;
    ctx->digest[6] = 0xE38DEE4D;
    ctx->digest[7] = 0xB0FB0E4E;

   return CRYPT_OK;
}

/**
   Process a block of memory though the hash
   @param md        The hash state
   @param data      The data to hash
   @param data_len  The length of the data (octets)
   @return CRYPT_OK if successful
*/
int sm3_process(hash_state * md, const unsigned char *data, unsigned long data_len)
{
    sm3_ctx_t *ctx = &(md->sm3);
    size_t blocks;

    if (ctx->num) {
        unsigned int left = SM3_BLOCK_SIZE - ctx->num;
        if (data_len < left) {
            memcpy(ctx->block + ctx->num, data, data_len);
            ctx->num += data_len;
            return CRYPT_OK;
        } else {
            memcpy(ctx->block + ctx->num, data, left);
            sm3_compress_blocks(ctx->digest, ctx->block, 1);
            ctx->nblocks++;
            data += left;
            data_len -= left;
        }
    }

    blocks = data_len / SM3_BLOCK_SIZE;
    sm3_compress_blocks(ctx->digest, data, blocks);
    ctx->nblocks += blocks;
    data += SM3_BLOCK_SIZE * blocks;
    data_len -= SM3_BLOCK_SIZE * blocks;

    ctx->num = data_len;
    if (data_len) {
        memcpy(ctx->block, data, data_len);
    }

    return CRYPT_OK;
}

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param digest [out] The destination of the hash (20 bytes)
   @return CRYPT_OK if successful
*/
int sm3_done(hash_state * md, unsigned char *digest)
{
    sm3_ctx_t *ctx = &(md->sm3);
    int i;

    ctx->block[ctx->num] = 0x80;

    if (ctx->num + 9 <= SM3_BLOCK_SIZE) {
        memset(ctx->block + ctx->num + 1, 0, SM3_BLOCK_SIZE - ctx->num - 9);
    } else {
        memset(ctx->block + ctx->num + 1, 0, SM3_BLOCK_SIZE - ctx->num - 1);
        sm3_compress(ctx->digest, ctx->block);
        memset(ctx->block, 0, SM3_BLOCK_SIZE - 8);
    }
    PUTU32(ctx->block + 56, ctx->nblocks >> 23);
    PUTU32(ctx->block + 60, (ctx->nblocks << 9) + (ctx->num << 3));

    sm3_compress(ctx->digest, ctx->block);
    for (i = 0; i < 8; i++) {
        PUTU32(digest + i*4, ctx->digest[i]);
    }

    return CRYPT_OK;
}

/**
  Self-test the hash
  @return CRYPT_OK if successful, CRYPT_NOP if self-tests have been disabled
*/
int  sm3_test(void)
{
#ifndef LTC_TEST
    return CRYPT_NOP;
#else
    static const struct {
        const char *msg;
        unsigned char hash[SM3_DIGEST_LENGTH];
    } tests[] = {
        { "abc",
            { 0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9,
              0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
              0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2,
              0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0,
            }
        },
        { "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
            { 0xde, 0xbe, 0x9f, 0xf9, 0x22, 0x75, 0xb8, 0xa1,
              0x38, 0x60, 0x48, 0x89, 0xc1, 0x8e, 0x5a, 0x4d,
              0x6f, 0xdb, 0x70, 0xe5, 0x38, 0x7e, 0x57, 0x65,
              0x29, 0x3d, 0xcb, 0xa3, 0x9c, 0x0c, 0x57, 0x32,
            }
        },
    };
    static const struct {
        unsigned char msg[2 + 16 + 32 * 6];
        unsigned char hash[SM3_DIGEST_LENGTH];
    } za_tests[] = {
        {   /* data from GM/T 0003.5-2012 appendix A. ZA=H256(INTLA||IDA||A||B||xG||yG||xA||yA) */
            { /* INTLA */0x00, 0x80,
              /* IDA */
              0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
              /* A */
              0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
              0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
              /* B */
              0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34, 0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
              0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92, 0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93,
              /* xG */
              0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19, 0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
              0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1, 0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7,
              /* yG */
              0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C, 0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
              0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40, 0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0,
              /* xA */
              0x09, 0xF9, 0xDF, 0x31, 0x1E, 0x54, 0x21, 0xA1, 0x50, 0xDD, 0x7D, 0x16, 0x1E, 0x4B, 0xC5, 0xC6,
              0x72, 0x17, 0x9F, 0xAD, 0x18, 0x33, 0xFC, 0x07, 0x6B, 0xB0, 0x8F, 0xF3, 0x56, 0xF3, 0x50, 0x20,
              /* yA */
              0xCC, 0xEA, 0x49, 0x0C, 0xE2, 0x67, 0x75, 0xA5, 0x2D, 0xC6, 0xEA, 0x71, 0x8C, 0xC1, 0xAA, 0x60,
              0x0A, 0xED, 0x05, 0xFB, 0xF3, 0x5E, 0x08, 0x4A, 0x66, 0x32, 0xF6, 0x07, 0x2D, 0xA9, 0xAD, 0x13,
            },
            {
              0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B, 0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26,
              0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9, 0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3,
            },
        },
    };

    int i;
    unsigned char tmp[SM3_DIGEST_LENGTH];
    hash_state md;

    for (i = 0; i < (int)(sizeof(tests) / sizeof(tests[0]));  i++) {
        sm3_init(&md);
        sm3_process(&md, (unsigned char*)tests[i].msg, (unsigned long)strlen(tests[i].msg));
        sm3_done(&md, tmp);
        if (compare_testvector(tmp, sizeof(tmp), tests[i].hash, sizeof(tests[i].hash), "SM3", i)) {
            return CRYPT_FAIL_TESTVECTOR;
        }
    }

    for (i = 0; i < (int)(sizeof(za_tests) / sizeof(za_tests[0]));  i++) {
        sm3_init(&md);
        sm3_process(&md, (unsigned char*)za_tests[i].msg, 2 + 16 + 32 * 6);
        sm3_done(&md, tmp);
        if (compare_testvector(tmp, sizeof(tmp), za_tests[i].hash, sizeof(za_tests[i].hash), "SM3", i)) {
            return CRYPT_FAIL_TESTVECTOR;
        }
    }
    return CRYPT_OK;
#endif
}

#define ROL32   ROL

#define ROTL(x,n)  (((x)<<(n)) | ((x)>>(32-(n))))
#define P0(x) ((x) ^ ROL32((x), 9) ^ ROL32((x),17))
#define P1(x) ((x) ^ ROL32((x),15) ^ ROL32((x),23))

#define FF00(x,y,z)  ((x) ^ (y) ^ (z))
#define FF16(x,y,z)  (((x)&(y)) | ((x)&(z)) | ((y)&(z)))
#define GG00(x,y,z)  ((x) ^ (y) ^ (z))
#define GG16(x,y,z)  ((((y)^(z)) & (x)) ^ (z))

#define R(A, B, C, D, E, F, G, H, xx)				\
    SS1 = ROL32((ROL32(A, 12) + E + K[j]), 7);		\
    SS2 = SS1 ^ ROL32(A, 12);				\
    TT1 = FF##xx(A, B, C) + D + SS2 + (W[j] ^ W[j + 4]);	\
    TT2 = GG##xx(E, F, G) + H + SS1 + W[j];			\
    B = ROL32(B, 9);					\
    H = TT1;						\
    F = ROL32(F, 19);					\
    D = P0(TT2);						\
    j++

#define R8(A, B, C, D, E, F, G, H, xx)				\
    R(A, B, C, D, E, F, G, H, xx);				\
    R(H, A, B, C, D, E, F, G, xx);				\
    R(G, H, A, B, C, D, E, F, xx);				\
    R(F, G, H, A, B, C, D, E, xx);				\
    R(E, F, G, H, A, B, C, D, xx);				\
    R(D, E, F, G, H, A, B, C, xx);				\
    R(C, D, E, F, G, H, A, B, xx);				\
    R(B, C, D, E, F, G, H, A, xx)



#define T00 0x79cc4519U
#define T16 0x7a879d8aU

#define K0	0x79cc4519U
#define K1	0xf3988a32U
#define K2	0xe7311465U
#define K3	0xce6228cbU
#define K4	0x9cc45197U
#define K5	0x3988a32fU
#define K6	0x7311465eU
#define K7	0xe6228cbcU
#define K8	0xcc451979U
#define K9	0x988a32f3U
#define K10	0x311465e7U
#define K11	0x6228cbceU
#define K12	0xc451979cU
#define K13	0x88a32f39U
#define K14	0x11465e73U
#define K15	0x228cbce6U
#define K16	0x9d8a7a87U
#define K17	0x3b14f50fU
#define K18	0x7629ea1eU
#define K19	0xec53d43cU
#define K20	0xd8a7a879U
#define K21	0xb14f50f3U
#define K22	0x629ea1e7U
#define K23	0xc53d43ceU
#define K24	0x8a7a879dU
#define K25	0x14f50f3bU
#define K26	0x29ea1e76U
#define K27	0x53d43cecU
#define K28	0xa7a879d8U
#define K29	0x4f50f3b1U
#define K30	0x9ea1e762U
#define K31	0x3d43cec5U
#define K32	0x7a879d8aU
#define K33	0xf50f3b14U
#define K34	0xea1e7629U
#define K35	0xd43cec53U
#define K36	0xa879d8a7U
#define K37	0x50f3b14fU
#define K38	0xa1e7629eU
#define K39	0x43cec53dU
#define K40	0x879d8a7aU
#define K41	0x0f3b14f5U
#define K42	0x1e7629eaU
#define K43	0x3cec53d4U
#define K44	0x79d8a7a8U
#define K45	0xf3b14f50U
#define K46	0xe7629ea1U
#define K47	0xcec53d43U
#define K48	0x9d8a7a87U
#define K49	0x3b14f50fU
#define K50	0x7629ea1eU
#define K51	0xec53d43cU
#define K52	0xd8a7a879U
#define K53	0xb14f50f3U
#define K54	0x629ea1e7U
#define K55	0xc53d43ceU
#define K56	0x8a7a879dU
#define K57	0x14f50f3bU
#define K58	0x29ea1e76U
#define K59	0x53d43cecU
#define K60	0xa7a879d8U
#define K61	0x4f50f3b1U
#define K62	0x9ea1e762U
#define K63	0x3d43cec5U

ulong32 K[64] = {
    K0,  K1,  K2,  K3,  K4,  K5,  K6,  K7,
    K8,  K9,  K10, K11, K12, K13, K14, K15,
    K16, K17, K18, K19, K20, K21, K22, K23,
    K24, K25, K26, K27, K28, K29, K30, K31,
    K32, K33, K34, K35, K36, K37, K38, K39,
    K40, K41, K42, K43, K44, K45, K46, K47,
    K48, K49, K50, K51, K52, K53, K54, K55,
    K56, K57, K58, K59, K60, K61, K62, K63,
    /*
    0x79cc4519U, 0xf3988a32U, 0xe7311465U, 0xce6228cbU,
    0x9cc45197U, 0x3988a32fU, 0x7311465eU, 0xe6228cbcU,
    0xcc451979U, 0x988a32f3U, 0x311465e7U, 0x6228cbceU,
    0xc451979cU, 0x88a32f39U, 0x11465e73U, 0x228cbce6U,
    0x9d8a7a87U, 0x3b14f50fU, 0x7629ea1eU, 0xec53d43cU,
    0xd8a7a879U, 0xb14f50f3U, 0x629ea1e7U, 0xc53d43ceU,
    0x8a7a879dU, 0x14f50f3bU, 0x29ea1e76U, 0x53d43cecU,
    0xa7a879d8U, 0x4f50f3b1U, 0x9ea1e762U, 0x3d43cec5U,
    0x7a879d8aU, 0xf50f3b14U, 0xea1e7629U, 0xd43cec53U,
    0xa879d8a7U, 0x50f3b14fU, 0xa1e7629eU, 0x43cec53dU,
    0x879d8a7aU, 0x0f3b14f5U, 0x1e7629eaU, 0x3cec53d4U,
    0x79d8a7a8U, 0xf3b14f50U, 0xe7629ea1U, 0xcec53d43U,
    0x9d8a7a87U, 0x3b14f50fU, 0x7629ea1eU, 0xec53d43cU,
    0xd8a7a879U, 0xb14f50f3U, 0x629ea1e7U, 0xc53d43ceU,
    0x8a7a879dU, 0x14f50f3bU, 0x29ea1e76U, 0x53d43cecU,
    0xa7a879d8U, 0x4f50f3b1U, 0x9ea1e762U, 0x3d43cec5U,
    */
};

void sm3_compress_blocks(ulong32 digest[8],
    const unsigned char *data, size_t blocks)
{
    ulong32 A;
    ulong32 B;
    ulong32 C;
    ulong32 D;
    ulong32 E;
    ulong32 F;
    ulong32 G;
    ulong32 H;
    ulong32 W[68];
    ulong32 SS1, SS2, TT1, TT2;
    int j;

#ifdef SM3_SSE3
    __m128i X, T, R;
    __m128i M = _mm_setr_epi32(0, 0, 0, 0xffffffff);
    __m128i V = _mm_setr_epi8(3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12);
#endif

    while (blocks--) {

        A = digest[0];
        B = digest[1];
        C = digest[2];
        D = digest[3];
        E = digest[4];
        F = digest[5];
        G = digest[6];
        H = digest[7];


#ifdef SM3_SSE3

        for (j = 0; j < 16; j += 4) {
            X = _mm_loadu_si128((__m128i *)(data + j * 4));
            X = _mm_shuffle_epi8(X, V);
            _mm_storeu_si128((__m128i *)(W + j), X);
        }

        for (j = 16; j < 68; j += 4) {
            /* X = (W[j - 3], W[j - 2], W[j - 1], 0) */
            X = _mm_loadu_si128((__m128i *)(W + j - 3));
            X = _mm_andnot_si128(M, X);

            X = _mm_rotl_epi32(X, 15);
            T = _mm_loadu_si128((__m128i *)(W + j - 9));
            X = _mm_xor_si128(X, T);
            T = _mm_loadu_si128((__m128i *)(W + j - 16));
            X = _mm_xor_si128(X, T);

            /* P1() */
            T = _mm_rotl_epi32(X, (23 - 15));
            T = _mm_xor_si128(T, X);
            T = _mm_rotl_epi32(T, 15);
            X = _mm_xor_si128(X, T);

            T = _mm_loadu_si128((__m128i *)(W + j - 13));
            T = _mm_rotl_epi32(T, 7);
            X = _mm_xor_si128(X, T);
            T = _mm_loadu_si128((__m128i *)(W + j - 6));
            X = _mm_xor_si128(X, T);

            /* W[j + 3] ^= P1(ROL32(W[j + 1], 15)) */
            R = _mm_shuffle_epi32(X, 0);
            R = _mm_and_si128(R, M);
            T = _mm_rotl_epi32(R, 15);
            T = _mm_xor_si128(T, R);
            T = _mm_rotl_epi32(T, 9);
            R = _mm_xor_si128(R, T);
            R = _mm_rotl_epi32(R, 6);
            X = _mm_xor_si128(X, R);

            _mm_storeu_si128((__m128i *)(W + j), X);
        }
#else
        for (j = 0; j < 16; j++)
            W[j] = GETU32(data + j*4);

        for (; j < 68; j++)
            W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROL32(W[j - 3], 15))
                ^ ROL32(W[j - 13], 7) ^ W[j - 6];
#endif


        j = 0;

#define FULL_UNROLL
#ifdef FULL_UNROLL
        R8(A, B, C, D, E, F, G, H, 00);
        R8(A, B, C, D, E, F, G, H, 00);
        R8(A, B, C, D, E, F, G, H, 16);
        R8(A, B, C, D, E, F, G, H, 16);
        R8(A, B, C, D, E, F, G, H, 16);
        R8(A, B, C, D, E, F, G, H, 16);
        R8(A, B, C, D, E, F, G, H, 16);
        R8(A, B, C, D, E, F, G, H, 16);
#else
        for (; j < 16; j++) {
            SS1 = ROL32((ROL32(A, 12) + E + K(j)), 7);
            SS2 = SS1 ^ ROL32(A, 12);
            TT1 = FF00(A, B, C) + D + SS2 + (W[j] ^ W[j + 4]);
            TT2 = GG00(E, F, G) + H + SS1 + W[j];
            D = C;
            C = ROL32(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = ROL32(F, 19);
            F = E;
            E = P0(TT2);
        }

        for (; j < 64; j++) {
            SS1 = ROL32((ROL32(A, 12) + E + K(j)), 7);
            SS2 = SS1 ^ ROL32(A, 12);
            TT1 = FF16(A, B, C) + D + SS2 + (W[j] ^ W[j + 4]);
            TT2 = GG16(E, F, G) + H + SS1 + W[j];
            D = C;
            C = ROL32(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = ROL32(F, 19);
            F = E;
            E = P0(TT2);
        }
#endif

        digest[0] ^= A;
        digest[1] ^= B;
        digest[2] ^= C;
        digest[3] ^= D;
        digest[4] ^= E;
        digest[5] ^= F;
        digest[6] ^= G;
        digest[7] ^= H;

        data += 64;
    }
}

void sm3_compress(ulong32 digest[8], const unsigned char block[64])
{
    return sm3_compress_blocks(digest, block, 1);
}


#endif


/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
