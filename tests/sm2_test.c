/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
#include <tomcrypt_test.h>

#ifdef LTC_TEST_SM2

int sm2_id_test(void) {
    int err;
    struct ltc_idtest {
        const char* k;
        const char* id;
        unsigned char za[SM3_DIGEST_LENGTH];
    } id_tests[] = {
      {
        "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8",
        "1234567812345678",
        {
          0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B, 0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26,
          0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9, 0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3,
        },
      },
    };

    ecc_key usera;
    unsigned char out[SM3_DIGEST_LENGTH];
    unsigned long outlen = sizeof(out);
    const struct ltc_hash_descriptor *hash_desc;
    ulong32 i;

    hash_desc = &hash_descriptor[find_hash("sm3")];

    for (i = 0; i < sizeof(id_tests) / sizeof(id_tests[0]); i++) {
        DO(sm2_make_key_test(id_tests[i].k, &usera));

        if ((err = sm2_compute_id_digest(hash_desc, id_tests[i].id, strlen(id_tests[i].id), out, &outlen, &usera)) != CRYPT_OK) {
            return err;
        };

        if (compare_testvector(out, SM3_DIGEST_LENGTH, id_tests[i].za, SM3_DIGEST_LENGTH, "SM2 id digest", i)) {
            return 1;
        }
    }

    return 0;
}

int sm2_msg_digest_test(void) {
    int err;
    struct ltc_idtest {
        const char* k;
        const char* id;
        const char* msg;
        unsigned char e[SM3_DIGEST_LENGTH];
    } id_tests[] = {
      {
        "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8",
        "1234567812345678",
        "message digest",
        {
          0xF0, 0xB4, 0x3E, 0x94, 0xBA, 0x45, 0xAC, 0xCA, 0xAC, 0xE6, 0x92, 0xED, 0x53, 0x43, 0x82, 0xEB,
          0x17, 0xE6, 0xAB, 0x5A, 0x19, 0xCE, 0x7B, 0x31, 0xF4, 0x48, 0x6F, 0xDF, 0xC0, 0xD2, 0x86, 0x40,
        },
      },
    };

    ecc_key usera;
    unsigned char out[SM3_DIGEST_LENGTH];
    unsigned long outlen = sizeof(out);
    ulong32 i;

    for (i = 0; i < sizeof(id_tests) / sizeof(id_tests[0]); i++) {
        DO(sm2_make_key_test(id_tests[i].k, &usera));

        if ((err = sm2_compute_message_digest((const unsigned char *)id_tests[i].msg, strlen(id_tests[i].msg),
                id_tests[i].id, strlen(id_tests[i].id), out, &outlen, &usera)) != CRYPT_OK) {
            return err;
        };

        if (compare_testvector(out, SM3_DIGEST_LENGTH, id_tests[i].e, SM3_DIGEST_LENGTH, "SM2 msg digest", i)) {
            return 1;
        }
    }

    return 0;
}

int sm2_sign_test(void) {
    int err;
    struct ltc_signtest {
        const char* k;
        const char* ik;
        unsigned char e[SM3_DIGEST_LENGTH];
        unsigned char rs[64];
    } sign_tests[] = {
      {
        "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8",
        "59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21",
        {
          0xF0, 0xB4, 0x3E, 0x94, 0xBA, 0x45, 0xAC, 0xCA, 0xAC, 0xE6, 0x92, 0xED, 0x53, 0x43, 0x82, 0xEB,
          0x17, 0xE6, 0xAB, 0x5A, 0x19, 0xCE, 0x7B, 0x31, 0xF4, 0x48, 0x6F, 0xDF, 0xC0, 0xD2, 0x86, 0x40,
        },
        {
          0xF5, 0xA0, 0x3B, 0x06, 0x48, 0xD2, 0xC4, 0x63, 0x0E, 0xEA, 0xC5, 0x13, 0xE1, 0xBB, 0x81, 0xA1,
          0x59, 0x44, 0xDA, 0x38, 0x27, 0xD5, 0xB7, 0x41, 0x43, 0xAC, 0x7E, 0xAC, 0xEE, 0xE7, 0x20, 0xB3,
          0xB1, 0xB6, 0xAA, 0x29, 0xDF, 0x21, 0x2F, 0xD8, 0x76, 0x31, 0x82, 0xBC, 0x0D, 0x42, 0x1C, 0xA1,
          0xBB, 0x90, 0x38, 0xFD, 0x1F, 0x7F, 0x42, 0xD4, 0x84, 0x0B, 0x69, 0xC4, 0x85, 0xBB, 0xC1, 0xAA,
        }
      },
    };

    ecc_key usera;
    struct sm2_sign_st sig_out;
    unsigned char out[64];
    ulong32 i, rlen;
    void *ik;

    mp_init(&ik);

    for (i = 0; i < sizeof(sign_tests) / sizeof(sign_tests[0]); i++) {
        DO(sm2_make_key_test(sign_tests[i].k, &usera));
        mp_init_multi(&sig_out.r, &sig_out.s, NULL);
        if ((err = sm2_sign_ex(sign_tests[i].e, sizeof(sign_tests[i].e), &sig_out, &usera, sign_tests[i].ik)) != CRYPT_OK) {
            return err;
        };

        rlen = mp_unsigned_bin_size(sig_out.r);

        if ((err = mp_to_unsigned_bin(sig_out.r, out)) != CRYPT_OK) {
            return err;
        }
        if ((err = mp_to_unsigned_bin(sig_out.s, out + rlen)) != CRYPT_OK) {
            return err;
        }

        if (compare_testvector(out, 64, sign_tests[i].rs, 64, "SM2 sign", i)) {
            return 1;
        }

        mp_clear_multi(sig_out.r, sig_out.s, NULL);
    }

    mp_clear(ik);

    return 0;
}

int sm2_verify_test(void) {
    int err;
    struct ltc_signtest {
        const char* k;
        unsigned char e[SM3_DIGEST_LENGTH];
        unsigned char r[32];
        unsigned char s[32];
    } sign_tests[] = {
      {
        "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8",
        {
          0xF0, 0xB4, 0x3E, 0x94, 0xBA, 0x45, 0xAC, 0xCA, 0xAC, 0xE6, 0x92, 0xED, 0x53, 0x43, 0x82, 0xEB,
          0x17, 0xE6, 0xAB, 0x5A, 0x19, 0xCE, 0x7B, 0x31, 0xF4, 0x48, 0x6F, 0xDF, 0xC0, 0xD2, 0x86, 0x40,
        },
        {
          0xF5, 0xA0, 0x3B, 0x06, 0x48, 0xD2, 0xC4, 0x63, 0x0E, 0xEA, 0xC5, 0x13, 0xE1, 0xBB, 0x81, 0xA1,
          0x59, 0x44, 0xDA, 0x38, 0x27, 0xD5, 0xB7, 0x41, 0x43, 0xAC, 0x7E, 0xAC, 0xEE, 0xE7, 0x20, 0xB3,
        },
        {
          0xB1, 0xB6, 0xAA, 0x29, 0xDF, 0x21, 0x2F, 0xD8, 0x76, 0x31, 0x82, 0xBC, 0x0D, 0x42, 0x1C, 0xA1,
          0xBB, 0x90, 0x38, 0xFD, 0x1F, 0x7F, 0x42, 0xD4, 0x84, 0x0B, 0x69, 0xC4, 0x85, 0xBB, 0xC1, 0xAA,
        }
      },
    };

    ecc_key usera;
    struct sm2_sign_st sig;
    int stat;
    ulong32 i;

    for (i = 0; i < sizeof(sign_tests) / sizeof(sign_tests[0]); i++) {
        DO(sm2_make_key_test(sign_tests[i].k, &usera));
        mp_init_multi(&sig.r, &sig.s, NULL);
        mp_read_unsigned_bin(sig.r, sign_tests[i].r, sizeof(sign_tests[i].r));
        mp_read_unsigned_bin(sig.s, sign_tests[i].s, sizeof(sign_tests[i].s));

        if ((err = sm2_verify(&sig, sign_tests[i].e, sizeof(sign_tests[i].e), &stat, &usera)) != CRYPT_OK) {
            return err;
        };

        if (stat == 0)
            return 1;

        mp_clear_multi(sig.r, sig.s, NULL);
    }

    return 0;
}

int sm2_tests(void)
{
    int err;
    unsigned long i;
    ecc_key usera;
    unsigned char priv_key_hex[512];
    unsigned char buf_x[ECC_BUF_SIZE];
    unsigned char buf_y[ECC_BUF_SIZE];
    int size;

    struct ltc_testkey {
        const char* k;
        unsigned char pubkey_x[32];
        unsigned char pubkey_y[32];
    } testkeys[] = {
        {
            "81EB26E941BB5AF16DF116495F90695272AE2CD63D6C4AE1678418BE48230029",
            {
              0x16, 0x0E, 0x12, 0x89, 0x7D, 0xF4, 0xED, 0xB6, 0x1D, 0xD8, 0x12, 0xFE, 0xB9, 0x67, 0x48, 0xFB,
              0xD3, 0xCC, 0xF4, 0xFF, 0xE2, 0x6A, 0xA6, 0xF6, 0xDB, 0x95, 0x40, 0xAF, 0x49, 0xC9, 0x42, 0x32,
            },
            {
              0x4A, 0x7D, 0xAD, 0x08, 0xBB, 0x9A, 0x45, 0x95, 0x31, 0x69, 0x4B, 0xEB, 0x20, 0xAA, 0x48, 0x9D,
              0x66, 0x49, 0x97, 0x5E, 0x1B, 0xFC, 0xF8, 0xC4, 0x74, 0x1B, 0x78, 0xB4, 0xB2, 0x23, 0x00, 0x7F,
            }
        },
        {
            "3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8",
            {
              0x09, 0xF9, 0xDF, 0x31, 0x1E, 0x54, 0x21, 0xA1, 0x50, 0xDD, 0x7D, 0x16, 0x1E, 0x4B, 0xC5, 0xC6,
              0x72, 0x17, 0x9F, 0xAD, 0x18, 0x33, 0xFC, 0x07, 0x6B, 0xB0, 0x8F, 0xF3, 0x56, 0xF3, 0x50, 0x20,
            },
            {
              0xCC, 0xEA, 0x49, 0x0C, 0xE2, 0x67, 0x75, 0xA5, 0x2D, 0xC6, 0xEA, 0x71, 0x8C, 0xC1, 0xAA, 0x60,
              0x0A, 0xED, 0x05, 0xFB, 0xF3, 0x5E, 0x08, 0x4A, 0x66, 0x32, 0xF6, 0x07, 0x2D, 0xA9, 0xAD, 0x13,
            },
        },
        {
            "59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21",
            {
              0x04, 0xEB, 0xFC, 0x71, 0x8E, 0x8D, 0x17, 0x98, 0x62, 0x04, 0x32, 0x26, 0x8E, 0x77, 0xFE, 0xB6,
              0x41, 0x5E, 0x2E, 0xDE, 0x0E, 0x07, 0x3C, 0x0F, 0x4F, 0x64, 0x0E, 0xCD, 0x2E, 0x14, 0x9A, 0x73,
            },
            {
              0xE8, 0x58, 0xF9, 0xD8, 0x1E, 0x54, 0x30, 0xA5, 0x7B, 0x36, 0xDA, 0xAB, 0x8F, 0x95, 0x0A, 0x3C,
              0x64, 0xE6, 0xEE, 0x6A, 0x63, 0x09, 0x4D, 0x99, 0x28, 0x3A, 0xFF, 0x76, 0x7E, 0x12, 0x4D, 0xF0,
            },
        }
    };

    for (i = 0; i < sizeof(testkeys) / sizeof(struct ltc_testkey); i++) {
        DO(sm2_make_key_test(testkeys[i].k, &usera));

        mp_tohex(usera.k, (char*)priv_key_hex);
        size = mp_unsigned_bin_size(usera.pubkey.x);
        zeromem(buf_x, sizeof(buf_x));
        if ((err = mp_to_unsigned_bin(usera.pubkey.x, buf_x) != CRYPT_OK)) return err;

        zeromem(buf_y, sizeof(buf_y));
        if ((err = mp_to_unsigned_bin(usera.pubkey.y, buf_y) != CRYPT_OK)) return err;

        if (compare_testvector(priv_key_hex, 64, testkeys[i].k, 64, "SM2 private key", i)) {
            return 1;
        }

        if (compare_testvector(buf_x, size, testkeys[i].pubkey_x, 32, "SM2 public key x", i)) {
            return 1;
        }

        if (compare_testvector(buf_y, size, testkeys[i].pubkey_y, 32, "SM2 public key y", i)) {
            return 1;
        }
    }

    if ((err = sm2_id_test()) != CRYPT_OK) {
        return err;
    }

    if ((err = sm2_msg_digest_test()) != CRYPT_OK) {
        return err;
    }

    if ((err = sm2_sign_test()) != CRYPT_OK) {
        return err;
    }

    if ((err = sm2_verify_test()) != CRYPT_OK) {
        return err;
    }

    return err;
}

#else

int sm2_tests(void)
{
    return CRYPT_NOP;
}

#endif
