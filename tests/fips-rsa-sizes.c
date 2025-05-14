/*
 * Copyright (C) 2022 Red Hat, Inc.
 *
 * Author: Alexander Sosedkin
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

#include <assert.h>
#include <stdio.h>
#include "utils.h"
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>

void generate_successfully(gnutls_privkey_t *privkey, gnutls_pubkey_t *pubkey,
			   unsigned int size);
void generate_unsuccessfully(gnutls_privkey_t *privkey, gnutls_pubkey_t *pubkey,
			     unsigned int size);
void sign_verify_successfully(gnutls_privkey_t privkey, gnutls_pubkey_t pubkey);
void sign_verify_unsuccessfully(gnutls_privkey_t privkey,
				gnutls_pubkey_t pubkey);
void nosign_verify(gnutls_privkey_t privkey, gnutls_pubkey_t pubkey);

void generate_successfully(gnutls_privkey_t *privkey, gnutls_pubkey_t *pubkey,
			   unsigned int size)
{
	int ret;
	gnutls_x509_privkey_t xprivkey;

	fprintf(stderr, "%d-bit\n", size);

	/* x509 generation as well just because why not */
	
	assert(gnutls_x509_privkey_init(&xprivkey) == 0);
	ret = gnutls_x509_privkey_generate(xprivkey, GNUTLS_PK_RSA, size, 0);
	if (ret != GNUTLS_E_SUCCESS)
		fail("%d-bit x509_privkey_init (%d)\n", size, ret);
	gnutls_x509_privkey_deinit(xprivkey);

	
	assert(gnutls_privkey_init(privkey) == 0);
	ret = gnutls_privkey_generate(*privkey, GNUTLS_PK_RSA, size, 0);
	if (ret != GNUTLS_E_SUCCESS)
		fail("%d-bit privkey_init (%d)\n", size, ret);

	assert(gnutls_pubkey_init(pubkey) == 0);
	
	ret = gnutls_pubkey_import_privkey(*pubkey, *privkey,
					   GNUTLS_KEY_DIGITAL_SIGNATURE, 0);
	if (ret != GNUTLS_E_SUCCESS)
		fail("%d-bit pubkey_import_privkey (%d)\n", size, ret);

}

void generate_unsuccessfully(gnutls_privkey_t *privkey, gnutls_pubkey_t *pubkey,
			     unsigned int size)
{
	int ret;
	gnutls_x509_privkey_t xprivkey;

	fprintf(stderr, "%d-bit\n", size);

	/* short x509 generation: ERROR, blocked */
	
	assert(gnutls_x509_privkey_init(&xprivkey) == 0);
	ret = gnutls_x509_privkey_generate(xprivkey, GNUTLS_PK_RSA, size, 0);
	if (ret != GNUTLS_E_PK_GENERATION_ERROR)
		fail("%d-bit x509_privkey_init (%d)\n", size, ret);
	gnutls_x509_privkey_deinit(xprivkey);

	/* short key generation: ERROR, blocked */
	
	assert(gnutls_privkey_init(privkey) == 0);
	ret = gnutls_privkey_generate(*privkey, GNUTLS_PK_RSA, size, 0);
	if (ret != GNUTLS_E_PK_GENERATION_ERROR)
		fail("%d-bit privkey_init (%d)\n", size, ret);
	gnutls_privkey_deinit(*privkey);

	/* Disable FIPS to generate them anyway */
	gnutls_fips140_set_mode(GNUTLS_FIPS140_LAX, 0);
	assert(gnutls_fips140_mode_enabled() == GNUTLS_FIPS140_LAX);

	assert(gnutls_x509_privkey_init(&xprivkey) == 0);
	ret = gnutls_x509_privkey_generate(xprivkey, GNUTLS_PK_RSA, size, 0);
	if (ret != GNUTLS_E_SUCCESS)
		fail("%d-bit x509_privkey_init (%d)\n", size, ret);
	gnutls_x509_privkey_deinit(xprivkey);

	assert(gnutls_privkey_init(privkey) == 0);
	ret = gnutls_privkey_generate(*privkey, GNUTLS_PK_RSA, size, 0);
	if (ret != GNUTLS_E_SUCCESS)
		fail("%d-bit privkey_init (%d)\n", size, ret);

	assert(gnutls_pubkey_init(pubkey) == 0);
	ret = gnutls_pubkey_import_privkey(*pubkey, *privkey,
					   GNUTLS_KEY_DIGITAL_SIGNATURE, 0);
	if (ret != GNUTLS_E_SUCCESS)
		fail("%d-bit pubkey_import_privkey (%d)\n", size, ret);

	gnutls_fips140_set_mode(GNUTLS_FIPS140_STRICT, 0);
	assert(gnutls_fips140_mode_enabled());

}

void sign_verify_successfully(gnutls_privkey_t privkey, gnutls_pubkey_t pubkey)
{
	int ret;

	gnutls_datum_t signature;
	gnutls_datum_t plaintext = {
		.data = (unsigned char *const)"Hello world!", .size = 12
	};

	/* RSA sign: approved */
	
	ret = gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0,
				       &plaintext, &signature);
	if (ret < 0)
		fail("gnutls_privkey_sign_data failed\n");

	/* RSA verify: approved */
	
	ret = gnutls_pubkey_verify_data2(pubkey, GNUTLS_SIGN_RSA_SHA256, 0,
					 &plaintext, &signature);
	if (ret < 0)
		fail("gnutls_pubkey_verify_data2 failed\n");

	gnutls_free(signature.data);
}

void sign_verify_unsuccessfully(gnutls_privkey_t privkey,
				gnutls_pubkey_t pubkey)
{
	int ret;

	gnutls_datum_t signature;
	gnutls_datum_t plaintext = {
		.data = (unsigned char *const)"Hello world!", .size = 12
	};

	/* small key RSA sign: not approved */
	
	ret = gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0,
				       &plaintext, &signature);
	if (ret < 0)
		fail("gnutls_privkey_sign_data failed\n");

	/* small key RSA verify: not approved */
	
	ret = gnutls_pubkey_verify_data2(pubkey, GNUTLS_SIGN_RSA_SHA256, 0,
					 &plaintext, &signature);
	if (ret < 0)
		fail("gnutls_pubkey_verify_data2 failed\n");

	gnutls_pubkey_deinit(pubkey);
	gnutls_privkey_deinit(privkey);
}

void nosign_verify(gnutls_privkey_t privkey, gnutls_pubkey_t pubkey)
{
	int ret;

	gnutls_datum_t signature;
	gnutls_datum_t plaintext = {
		.data = (unsigned char *const)"Hello world!", .size = 12
	};

	/* 1024, 1280, 1536, 1792 key RSA sign: not approved */
	
	ret = gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0,
				       &plaintext, &signature);
	if (ret < 0)
		fail("gnutls_privkey_sign_data failed\n");

	/* Disable FIPS to sign them anyway */
	gnutls_fips140_set_mode(GNUTLS_FIPS140_LAX, 0);
	assert(gnutls_fips140_mode_enabled() == GNUTLS_FIPS140_LAX);

	ret = gnutls_privkey_sign_data(privkey, GNUTLS_DIG_SHA256, 0,
				       &plaintext, &signature);
	if (ret < 0)
		fail("gnutls_privkey_sign_data failed\n");

	gnutls_fips140_set_mode(GNUTLS_FIPS140_STRICT, 0);
	assert(gnutls_fips140_mode_enabled());

	/* 1024, 1280, 1536, 1792 key RSA verify: approved (exception) */
	
	ret = gnutls_pubkey_verify_data2(pubkey, GNUTLS_SIGN_RSA_SHA256, 0,
					 &plaintext, &signature);
	if (ret < 0)
		fail("gnutls_pubkey_verify_data2 failed\n");

	gnutls_free(signature.data);
	gnutls_pubkey_deinit(pubkey);
	gnutls_privkey_deinit(privkey);
}

void doit(void)
{
	gnutls_privkey_t privkey;
	gnutls_pubkey_t pubkey;

	if (gnutls_fips140_mode_enabled() == 0) {
		success("We are not in FIPS140 mode\n");
		exit(77); /* SKIP */
	}

	generate_unsuccessfully(&privkey, &pubkey, 512);
	sign_verify_unsuccessfully(privkey, pubkey);
	generate_unsuccessfully(&privkey, &pubkey, 512);
	sign_verify_unsuccessfully(privkey, pubkey);
	generate_unsuccessfully(&privkey, &pubkey, 600);
	sign_verify_unsuccessfully(privkey, pubkey);
	generate_unsuccessfully(&privkey, &pubkey, 768);
	sign_verify_unsuccessfully(privkey, pubkey);
	generate_unsuccessfully(&privkey, &pubkey, 1280);
	sign_verify_unsuccessfully(privkey, pubkey);
	generate_unsuccessfully(&privkey, &pubkey, 1500);
	sign_verify_unsuccessfully(privkey, pubkey);
	generate_unsuccessfully(&privkey, &pubkey, 1536);
	sign_verify_unsuccessfully(privkey, pubkey);
	generate_unsuccessfully(&privkey, &pubkey, 1792);
	sign_verify_unsuccessfully(privkey, pubkey);
	generate_unsuccessfully(&privkey, &pubkey, 2000);
	sign_verify_unsuccessfully(privkey, pubkey);
	generate_unsuccessfully(&privkey, &pubkey, 2432);
	sign_verify_unsuccessfully(privkey, pubkey);

	/* 1024-bit RSA: generate, sign, verify */
    generate_successfully(&privkey, &pubkey, 1024);
	sign_verify_successfully(privkey, pubkey);
	/* 2048-bit RSA: generate, sign, verify */
	generate_successfully(&privkey, &pubkey, 2048);
	sign_verify_successfully(privkey, pubkey);
	/* 3072-bit RSA: generate, sign, verify */
	generate_successfully(&privkey, &pubkey, 3072);
	sign_verify_successfully(privkey, pubkey);

}
