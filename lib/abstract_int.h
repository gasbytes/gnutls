/*
 * Copyright (C) 2010-2012 Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 *
 */

#ifndef GNUTLS_LIB_ABSTRACT_INT_H
#define GNUTLS_LIB_ABSTRACT_INT_H

#include <gnutls/abstract.h>

typedef int (*gnutls_privkey_pk_params_func)(gnutls_privkey_t key,
					     void *userdata,
					     gnutls_pk_params_st *params);

struct gnutls_privkey_st {
    gnutls_pk_get_bits_func get_bits;
    gnutls_pk_get_spki_func get_spki;
    gnutls_pk_set_spki_func set_spki;
    gnutls_pk_generate_func generate_backend;
    gnutls_pk_import_privkey_x509_func import_privkey_x509_backend;
    gnutls_pk_import_privkey_url_func import_privkey_url_backend;
    gnutls_pk_privkey_decrypt_func privkey_decrypt_backend;
    gnutls_pk_derive_shared_secret_func derive_shared_secret_backend;
    gnutls_pk_sign_func sign_backend;
    gnutls_pk_sign_hash_func sign_hash_backend;
    gnutls_pk_deinit_func deinit_backend;
    void *pk_ctx;
	gnutls_privkey_type_t type;
	gnutls_pk_algorithm_t pk_algorithm;

	union {
		gnutls_x509_privkey_t x509;
#ifdef ENABLE_PKCS11
		gnutls_pkcs11_privkey_t pkcs11;
#endif
		struct {
			gnutls_privkey_sign_func sign_func; /* raw like TLS 1.x */
			gnutls_privkey_sign_data_func sign_data_func;
			gnutls_privkey_sign_hash_func sign_hash_func;
			gnutls_privkey_decrypt_func decrypt_func;
			gnutls_privkey_decrypt_func2 decrypt_func2;
			gnutls_privkey_deinit_func deinit_func;
			gnutls_privkey_info_func info_func;
			gnutls_privkey_pk_params_func pk_params_func;
			void *userdata;
			unsigned bits;
		} ext;
	} key;

	unsigned int flags;
	struct pin_info_st pin;
};

struct gnutls_pubkey_st {
    gnutls_pk_generate_func generate_backend;
    gnutls_pk_import_pubkey_func import_pubkey_backend;
    gnutls_pk_export_pubkey_func export_pubkey_backend;
    gnutls_pk_import_pubkey_url_func import_pubkey_url_backend;
    gnutls_pk_import_pubkey_x509_func import_pubkey_x509_backend;
    gnutls_pk_pubkey_encrypt_func pubkey_encrypt_backend;
    gnutls_pk_derive_shared_secret_func derive_shared_secret_backend;
    gnutls_pk_verify_func verify_backend;
    gnutls_pk_verify_hash_func verify_hash_backend;
    gnutls_pk_deinit_func deinit_backend;
    void *pk_ctx;
	gnutls_privkey_type_t type;
	gnutls_pk_algorithm_t pk_algorithm;
	unsigned int bits; /* an indication of the security parameter */

	/* the size of params depends on the public
	 * key algorithm
	 * RSA: [0] is modulus
	 *      [1] is public exponent
	 * DSA: [0] is p
	 *      [1] is q
	 *      [2] is g
	 *      [3] is public key
	 */
	gnutls_pk_params_st params;

	unsigned int key_usage; /* bits from GNUTLS_KEY_* */

	struct pin_info_st pin;
};

int _gnutls_privkey_get_public_mpis(gnutls_privkey_t key,
				    gnutls_pk_params_st *);

int _gnutls_privkey_get_spki_params(gnutls_privkey_t key,
				    gnutls_x509_spki_st *params);
int _gnutls_privkey_update_spki_params(gnutls_privkey_t key,
				       gnutls_pk_algorithm_t pk,
				       gnutls_digest_algorithm_t dig,
				       unsigned flags,
				       gnutls_x509_spki_st *params);

unsigned _gnutls_privkey_compatible_with_sig(gnutls_privkey_t key,
					     gnutls_sign_algorithm_t sig);

void _gnutls_privkey_cleanup(gnutls_privkey_t key);

int privkey_sign_and_hash_data(gnutls_privkey_t signer,
			       const gnutls_sign_entry_st *se,
			       const gnutls_datum_t *data,
			       gnutls_datum_t *signature,
			       gnutls_x509_spki_st *params);
int privkey_sign_raw_data(gnutls_privkey_t key, const gnutls_sign_entry_st *se,
			  const gnutls_datum_t *data, gnutls_datum_t *signature,
			  gnutls_x509_spki_st *params);

unsigned pubkey_to_bits(const gnutls_pk_params_st *params);
int _gnutls_pubkey_compatible_with_sig(gnutls_session_t, gnutls_pubkey_t pubkey,
				       const version_entry_st *ver,
				       gnutls_sign_algorithm_t sign);
int _gnutls_pubkey_get_mpis(gnutls_pubkey_t key, gnutls_pk_params_st *params);

int pubkey_verify_data(const gnutls_sign_entry_st *se, const mac_entry_st *me,
		       const gnutls_datum_t *data,
		       const gnutls_datum_t *signature,
		       gnutls_pk_params_st *params,
		       gnutls_x509_spki_st *sign_params, unsigned vflags);

const mac_entry_st *_gnutls_dsa_q_to_hash(const gnutls_pk_params_st *params,
					  unsigned int *hash_len);

int _gnutls_privkey_get_mpis(gnutls_privkey_t key, gnutls_pk_params_st *params);

#endif /* GNUTLS_LIB_ABSTRACT_INT_H */
