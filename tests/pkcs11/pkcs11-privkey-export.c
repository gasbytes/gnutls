/*
 * Copyright (C) 2016 Red Hat, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * GnuTLS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuTLS is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GnuTLS.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>

#include "../utils.h"
#include "softhsm.h"

/* This checks whether the public parts of RSA private and public keys
 * can be properly extracted from a PKCS#11 module. */

#define PIN "1234"
#define CONFIG_NAME "softhsm-privkey-export-test"
#define CONFIG CONFIG_NAME ".config"

/* Tests whether signing with PKCS#11 and RSA would generate valid signatures */

#include "../cert-common.h"

static void tls_log_func(int level, const char *str)
{
    fprintf(stderr, "|<%d>| %s", level, str);
}

static int pin_func(void *userdata, int attempt, const char *url,
        const char *label, unsigned flags, char *pin,
        size_t pin_max)
{
    if (attempt == 0) {
        strcpy(pin, PIN);
        return 0;
    }
    return -1;
}

void doit(void)
{
    int ret;
    char buf[256];
    const char *lib, *bin;
    gnutls_privkey_t key;
    gnutls_pubkey_t pub;
    gnutls_datum_t m1, e1;
    gnutls_datum_t m2, e2;
    gnutls_x509_crt_t crt;
    gnutls_x509_privkey_t x509_key;

    if (gnutls_fips140_mode_enabled())
        exit(77);

    bin = softhsm_bin();
    lib = softhsm_lib();

    ret = global_init();
    if (ret != 0) {
        fail("%d: %s\n", ret, gnutls_strerror(ret));
        exit(1);
    }

    gnutls_pkcs11_set_pin_function(pin_func, NULL);
    gnutls_global_set_log_function(tls_log_func);
    if (debug)
        gnutls_global_set_log_level(4711);

    set_softhsm_conf(CONFIG);
    assert(snprintf(buf, sizeof(buf),
                "%s --init-token --slot 0 --label test --so-pin " PIN
                " --pin " PIN,
                bin) < (int)sizeof(buf));
    system(buf);

    ret = gnutls_pkcs11_add_provider(lib, NULL);
    if (ret < 0) {
        fail("gnutls_pkcs11_add_provider: %s\n", gnutls_strerror(ret));
        exit(1);
    }

    /* Initialize certificate and key */
    ret = gnutls_x509_crt_init(&crt);
    if (ret < 0) {
        fail("gnutls_x509_crt_init: %s\n", gnutls_strerror(ret));
        exit(1);
    }

    ret = gnutls_x509_crt_import(crt, &server_cert, GNUTLS_X509_FMT_PEM);
    if (ret < 0) {
        fail("gnutls_x509_crt_import: %s\n", gnutls_strerror(ret));
        exit(1);
    }

    ret = gnutls_x509_privkey_init(&x509_key);
    if (ret < 0) {
        fail("gnutls_x509_privkey_init: %s\n", gnutls_strerror(ret));
        exit(1);
    }

    ret = gnutls_x509_privkey_import(x509_key, &server_key, GNUTLS_X509_FMT_PEM);
    if (ret < 0) {
        fail("gnutls_x509_privkey_import: %s\n", gnutls_strerror(ret));
        exit(1);
    }

    /* Initialize softhsm token */
    ret = gnutls_pkcs11_token_init(SOFTHSM_URL, PIN, "test");
    if (ret < 0) {
        fail("gnutls_pkcs11_token_init: %s\n", gnutls_strerror(ret));
        exit(1);
    }

    ret = gnutls_pkcs11_token_set_pin(SOFTHSM_URL, NULL, PIN, GNUTLS_PIN_USER);
    if (ret < 0) {
        fail("gnutls_pkcs11_token_set_pin: %s\n", gnutls_strerror(ret));
        exit(1);
    }

    /* Copy certificate and private key to the token */
    ret = gnutls_pkcs11_copy_x509_crt(SOFTHSM_URL, crt, "test",
            GNUTLS_PKCS11_OBJ_FLAG_MARK_PRIVATE |
            GNUTLS_PKCS11_OBJ_FLAG_LOGIN);
    if (ret < 0) {
        fail("gnutls_pkcs11_copy_x509_crt: %s\n", gnutls_strerror(ret));
        exit(1);
    }

    ret = gnutls_pkcs11_copy_x509_privkey(
            SOFTHSM_URL, x509_key, "test",
            GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT,
            GNUTLS_PKCS11_OBJ_FLAG_MARK_PRIVATE |
            GNUTLS_PKCS11_OBJ_FLAG_MARK_SENSITIVE |
            GNUTLS_PKCS11_OBJ_FLAG_LOGIN);
    if (ret < 0) {
        fail("gnutls_pkcs11_copy_x509_privkey: %s\n", gnutls_strerror(ret));
        exit(1);
    }

    /* Write pubkey to the token too */
    assert(gnutls_pubkey_init(&pub) >= 0);
    assert(gnutls_pubkey_import_x509(pub, crt, 0) >= 0);

    ret = gnutls_pkcs11_copy_pubkey(
            SOFTHSM_URL, pub, "test", NULL,
            GNUTLS_KEY_DIGITAL_SIGNATURE | GNUTLS_KEY_KEY_ENCIPHERMENT, 0);
    if (ret < 0) {
        fail("gnutls_pkcs11_copy_pubkey: %s\n", gnutls_strerror(ret));
        exit(1);
    }

    gnutls_x509_crt_deinit(crt);
    gnutls_x509_privkey_deinit(x509_key);
    gnutls_pubkey_deinit(pub);
    gnutls_pkcs11_set_pin_function(NULL, NULL);

    /* Test extraction of public key from private key in token */
    ret = gnutls_privkey_init(&key);
    assert(ret >= 0);

    ret = gnutls_pubkey_init(&pub);
    assert(ret >= 0);

    gnutls_privkey_set_pin_function(key, pin_func, NULL);

    /* Import the private key from the token */
    assert(snprintf(buf, sizeof(buf), 
                "%s;object=test;object-type=private?pin-value=%s", 
                SOFTHSM_URL, PIN) < (int)sizeof(buf));

    ret = gnutls_privkey_import_url(key, buf, 0);
    if (ret < 0) {
        fail("%d: %s\n", ret, gnutls_strerror(ret));
        exit(1);
    }

    /* Extract the public key from the private key */
    ret = gnutls_pubkey_import_privkey(pub, key, 0, 0);
    if (ret < 0) {
        fail("%d: %s\n", ret, gnutls_strerror(ret));
        exit(1);
    }

    /* Export the raw RSA parameters */
    ret = gnutls_pubkey_export_rsa_raw(pub, &m1, &e1);
    if (ret < 0) {
        fail("%d: %s\n", ret, gnutls_strerror(ret));
        exit(1);
    }

    gnutls_pubkey_deinit(pub);
    gnutls_privkey_deinit(key);

    /* Try again using gnutls_pubkey_import_url */
    ret = gnutls_pubkey_init(&pub);
    assert(ret >= 0);

    assert(snprintf(buf, sizeof(buf), 
                "%s;object=test;type=public", 
                SOFTHSM_URL) < (int)sizeof(buf));

    ret = gnutls_pubkey_import_url(pub, buf, 0);
    if (ret < 0) {
        fail("%d: %s\n", ret, gnutls_strerror(ret));
        exit(1);
    }

    ret = gnutls_pubkey_export_rsa_raw(pub, &m2, &e2);
    if (ret < 0) {
        fail("%d: %s\n", ret, gnutls_strerror(ret));
        exit(1);
    }

    /* Compare the two exports to ensure they match */
    assert(m1.size == m2.size);
    assert(e1.size == e2.size);
    assert(memcmp(e1.data, e2.data, e2.size) == 0);
    assert(memcmp(m1.data, m2.data, m2.size) == 0);

    /* Clean up */
    gnutls_pubkey_deinit(pub);
    gnutls_free(m1.data);
    gnutls_free(e1.data);
    gnutls_free(m2.data);
    gnutls_free(e2.data);
    gnutls_pkcs11_deinit();
    gnutls_global_deinit();

    remove(CONFIG);
}
