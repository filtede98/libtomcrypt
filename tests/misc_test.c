/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
#include  <tomcrypt_test.h>

#if (ARGTYPE == 4)
static int s_null_guard_test(void)
{
   symmetric_key skey;
   unsigned char dummy[32] = { 0 };
   int val = 0;
   unsigned int sz = 0;

#ifdef LTC_BLOWFISH
   SHOULD_FAIL_WITH(blowfish_setup(NULL, 16, 0, &skey), CRYPT_INVALID_ARG);
   SHOULD_FAIL_WITH(blowfish_setup(dummy, 16, 0, NULL), CRYPT_INVALID_ARG);
   SHOULD_FAIL_WITH(blowfish_setup_with_data(NULL, 16, NULL, 0, &skey), CRYPT_INVALID_ARG);
   SHOULD_FAIL_WITH(blowfish_setup_with_data(dummy, 16, NULL, 0, NULL), CRYPT_INVALID_ARG);
   blowfish_done(NULL);
#endif

#ifdef LTC_CAMELLIA
   SHOULD_FAIL_WITH(camellia_ecb_encrypt(NULL, dummy, &skey), CRYPT_INVALID_ARG);
   SHOULD_FAIL_WITH(camellia_ecb_encrypt(dummy, NULL, &skey), CRYPT_INVALID_ARG);
   SHOULD_FAIL_WITH(camellia_ecb_encrypt(dummy, dummy, NULL), CRYPT_INVALID_ARG);
   SHOULD_FAIL_WITH(camellia_ecb_decrypt(NULL, dummy, &skey), CRYPT_INVALID_ARG);
   SHOULD_FAIL_WITH(camellia_ecb_decrypt(dummy, NULL, &skey), CRYPT_INVALID_ARG);
   SHOULD_FAIL_WITH(camellia_ecb_decrypt(dummy, dummy, NULL), CRYPT_INVALID_ARG);
   SHOULD_FAIL_WITH(camellia_keysize(NULL), CRYPT_INVALID_ARG);
   camellia_done(NULL);
#endif

#ifdef LTC_KSEED
   SHOULD_FAIL_WITH(kseed_setup(NULL, 16, 0, &skey), CRYPT_INVALID_ARG);
   SHOULD_FAIL_WITH(kseed_setup(dummy, 16, 0, NULL), CRYPT_INVALID_ARG);
   SHOULD_FAIL_WITH(kseed_ecb_encrypt(NULL, dummy, &skey), CRYPT_INVALID_ARG);
   SHOULD_FAIL_WITH(kseed_ecb_encrypt(dummy, NULL, &skey), CRYPT_INVALID_ARG);
   SHOULD_FAIL_WITH(kseed_ecb_encrypt(dummy, dummy, NULL), CRYPT_INVALID_ARG);
   SHOULD_FAIL_WITH(kseed_ecb_decrypt(NULL, dummy, &skey), CRYPT_INVALID_ARG);
   SHOULD_FAIL_WITH(kseed_ecb_decrypt(dummy, NULL, &skey), CRYPT_INVALID_ARG);
   SHOULD_FAIL_WITH(kseed_ecb_decrypt(dummy, dummy, NULL), CRYPT_INVALID_ARG);
   kseed_done(NULL);
#endif

#ifdef LTC_IDEA
   SHOULD_FAIL_WITH(idea_ecb_encrypt(NULL, dummy, &skey), CRYPT_INVALID_ARG);
   SHOULD_FAIL_WITH(idea_ecb_encrypt(dummy, NULL, &skey), CRYPT_INVALID_ARG);
   SHOULD_FAIL_WITH(idea_ecb_encrypt(dummy, dummy, NULL), CRYPT_INVALID_ARG);
   SHOULD_FAIL_WITH(idea_ecb_decrypt(NULL, dummy, &skey), CRYPT_INVALID_ARG);
   SHOULD_FAIL_WITH(idea_ecb_decrypt(dummy, NULL, &skey), CRYPT_INVALID_ARG);
   SHOULD_FAIL_WITH(idea_ecb_decrypt(dummy, dummy, NULL), CRYPT_INVALID_ARG);
   idea_done(NULL);
#endif

#ifdef LTC_DES
   SHOULD_FAIL_WITH(desx_setup(NULL, 24, 0, &skey), CRYPT_INVALID_ARG);
   SHOULD_FAIL_WITH(desx_setup(dummy, 24, 0, NULL), CRYPT_INVALID_ARG);
   des_done(NULL);
   desx_done(NULL);
   des3_done(NULL);
#endif

#ifdef LTC_RC2
   SHOULD_FAIL_WITH(rc2_setup(NULL, 16, 0, &skey), CRYPT_INVALID_ARG);
   SHOULD_FAIL_WITH(rc2_setup(dummy, 16, 0, NULL), CRYPT_INVALID_ARG);
   rc2_done(NULL);
#endif

#ifdef LTC_CHACHA20POLY1305_MODE
   {
      chacha20poly1305_state cp_st;
      SHOULD_FAIL_WITH(chacha20poly1305_init(NULL, dummy, 32), CRYPT_INVALID_ARG);
      SHOULD_FAIL_WITH(chacha20poly1305_init(&cp_st, NULL, 32), CRYPT_INVALID_ARG);
   }
#endif

   SHOULD_FAIL_WITH(crypt_get_constant(NULL, &val), CRYPT_INVALID_ARG);
   SHOULD_FAIL_WITH(crypt_get_constant("CRYPT_OK", NULL), CRYPT_INVALID_ARG);
   SHOULD_FAIL_WITH(crypt_list_all_constants(NULL, NULL), CRYPT_INVALID_ARG);

   SHOULD_FAIL_WITH(crypt_get_size(NULL, &sz), CRYPT_INVALID_ARG);
   SHOULD_FAIL_WITH(crypt_get_size("symmetric_key", NULL), CRYPT_INVALID_ARG);
   SHOULD_FAIL_WITH(crypt_list_all_sizes(NULL, NULL), CRYPT_INVALID_ARG);

   return 0;
}
#endif

int misc_test(void)
{
#ifdef LTC_ARGON2
   DO(argon2_test());
#endif
#ifdef LTC_BCRYPT
   DO(bcrypt_test());
#endif
#ifdef LTC_SCRYPT
   DO(scrypt_test());
#endif
#ifdef LTC_HKDF
   DO(hkdf_test());
#endif
#ifdef LTC_PKCS_5
   DO(pkcs_5_test());
#endif
#ifdef LTC_PADDING
   DO(padding_test());
#endif
#ifdef LTC_BASE64
   DO(base64_test());
#endif
#ifdef LTC_BASE32
   DO(base32_test());
#endif
#ifdef LTC_BASE16
   DO(base16_test());
#endif
#ifdef LTC_ADLER32
   DO(adler32_test());
#endif
#ifdef LTC_CRC32
   DO(crc32_test());
#endif
#ifdef LTC_SSH
   ssh_test();
#endif
   pk_oid_test();
   no_null_termination_check_test();
#if (ARGTYPE == 4)
   DO(s_null_guard_test());
#endif
   return 0;
}
