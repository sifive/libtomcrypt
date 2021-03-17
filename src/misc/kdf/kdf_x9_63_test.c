/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include "tomcrypt_private.h"

#ifdef LTC_X963_KDF

/**
  ANSI X9.63 KDF self-test
  @return CRYPT_OK if successful, CRYPT_NOP if tests have been disabled.
*/
int x963_kdf_test(void)
{
#ifndef LTC_TEST
    return CRYPT_NOP;
#else
    unsigned char OKM[82];
    int i;

    static const struct x963_kdf_test_case {
        int num;
        const char* Hash;

        unsigned char IKM[80];
        unsigned long IKM_l;
        unsigned char OKM[82];
        unsigned long OKM_l;
    } cases[] = {
#ifdef LTC_SM3

           {1, "sm3",
            {0x33, 0x5E, 0x18, 0xD7, 0x51, 0xE5, 0x1F, 0x04,
             0x0E, 0x27, 0xD4, 0x68, 0x13, 0x8b, 0x7A, 0xB1,
             0xDC, 0x86, 0xAD, 0x7F, 0x98, 0x1D, 0x7D, 0x41,
             0x62, 0x22, 0xFD, 0x6A, 0xB3, 0xED, 0x23, 0x0D,
             0xAB, 0x74, 0x3E, 0xBC, 0xFB, 0x22, 0xD6, 0x4F,
             0x7B, 0x6A, 0xB7, 0x91, 0xF7, 0x06, 0x58, 0xF2,
             0x5B, 0x48, 0xFA, 0x93, 0xE5, 0x40, 0x64, 0xFD,
             0xBF, 0xBE, 0xD3, 0xF0, 0xBD, 0x84, 0x7A, 0xC9},
             64,
            {0x44, 0xE6, 0x0F, 0xDB, 0xF0, 0xBA, 0xE8, 0x14,
             0x37, 0x66, 0x53, 0x74, 0xBE, 0xF2, 0x67, 0x49,
             0x04, 0x6C, 0x9E},
             19},
#endif /* LTC_SM3 */
    };

    int err;
    int tested=0,failed=0;
    for (i = 0; i < (int)(sizeof(cases) / sizeof(cases[0])); i++) {
        int hash = find_hash(cases[i].Hash);
        if (hash == -1) continue;
        ++tested;
        if ((err = x963_kdf(hash, cases[i].IKM, cases[i].IKM_l,
                        OKM, cases[i].OKM_l)) != CRYPT_OK) {
#if defined(LTC_TEST_DBG) && (LTC_TEST_DBG > 1)
            printf("ANSI X9.63 KDF-%s test #%d, %s\n", cases[i].Hash, i, error_to_string(err));
#endif
            return err;
        }

        if(compare_testvector(OKM, cases[i].OKM_l, cases[i].OKM, (size_t)cases[i].OKM_l, "ANSI X9.63 KDF", cases[i].num)) {
            failed++;
        }
    }

    if (failed != 0) {
        return CRYPT_FAIL_TESTVECTOR;
    }
    if (tested == 0) {
        return CRYPT_NOP;
    }
    return CRYPT_OK;
 #endif
}

#endif  /* LTC_X963_KDF */
