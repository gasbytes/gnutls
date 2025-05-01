/*
 * Copyright (C) 2017 Red Hat, Inc.
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

/* TLS 1.3 secret key derivation handling.
 */

#include "config.h"
#include "crypto-api.h"
#include "fips.h"
#include "gnutls_int.h"
#include "secrets.h"

/* HKDF-Extract(0,0) or HKDF-Extract(0, PSK) */
int _tls13_init_secret(gnutls_session_t session, const uint8_t *psk,
		       size_t psk_size)
{
	session->key.proto.tls13.temp_secret_size =
		session->security_parameters.prf->output_size;

	return _gnutls_tls13_hkdf_ops.init(session->security_parameters.prf->id,
				psk, psk_size,
				session->key.proto.tls13.temp_secret,
				session->security_parameters.prf->output_size);
}

int _tls13_init_secret2(gnutls_mac_algorithm_t mac, const uint8_t *psk,
			size_t psk_size, void *out, size_t output_size)
{
	char buf[128];

	/* when no PSK, use the zero-value */
	if (psk == NULL) {
		psk_size = output_size;
		if (unlikely(psk_size >= sizeof(buf)))
			return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

		memset(buf, 0, psk_size);
		psk = (uint8_t *)buf;
	}

	return gnutls_hmac_fast(mac, "", 0, psk, psk_size, out);
}

/* HKDF-Extract(Prev-Secret, key) */
int _tls13_update_secret(gnutls_session_t session, const uint8_t *key,
			 size_t key_size)
{
	return _gnutls_tls13_hkdf_ops.update(
				session->security_parameters.prf->id,
				key, key_size,
				session->key.proto.tls13.temp_secret,
				session->key.proto.tls13.temp_secret_size,
				session->key.proto.tls13.temp_secret);
}

int _tls13_update_secret2(gnutls_mac_algorithm_t mac, const uint8_t *key,
			  size_t key_size, const uint8_t *salt,
			  size_t salt_size, uint8_t *secret)
{
	gnutls_datum_t _key;
	gnutls_datum_t _salt;
	int ret;

	_key.data = (void *)key;
	_key.size = key_size;
	_salt.data = (void*)salt;
	_salt.size = salt_size;

	ret = _gnutls_hkdf_extract(mac, &_key, &_salt, secret);
	if (ret < 0)
		_gnutls_switch_fips_state(GNUTLS_FIPS140_OP_ERROR);
	else
		_gnutls_switch_fips_state(GNUTLS_FIPS140_OP_APPROVED);

	return ret;
}

/* Derive-Secret(Secret, Label, Messages) */
int _tls13_derive_secret2(gnutls_mac_algorithm_t mac, const char *label,
			  unsigned label_size, const uint8_t *tbh,
			  size_t tbh_size, const uint8_t secret[MAX_HASH_SIZE],
			  void *out, size_t output_size)
{
	uint8_t digest[MAX_HASH_SIZE];
	int ret;

	if (unlikely(label_size >= sizeof(digest)))
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	ret = gnutls_hash_fast((gnutls_digest_algorithm_t)mac, tbh, tbh_size,
			       digest);
	if (ret < 0)
		return gnutls_assert_val(ret);

	return _gnutls_tls13_hkdf_ops.expand(mac, label, label_size, digest,
					     output_size, secret, output_size,
					     out);
}

/* Derive-Secret(Secret, Label, Messages) */
int _tls13_derive_secret(gnutls_session_t session, const char *label,
			 unsigned label_size, const uint8_t *tbh,
			 size_t tbh_size, const uint8_t secret[MAX_HASH_SIZE],
			 void *out)
{
	if (unlikely(session->security_parameters.prf == NULL))
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	return _gnutls_tls13_hkdf_ops.derive(
				session->security_parameters.prf->id,
				label, label_size, tbh, tbh_size,
				secret, out,
				session->security_parameters.prf->output_size);
}

/* HKDF-Expand-Label(Secret, Label, HashValue, Length) */
int _tls13_expand_secret2(gnutls_mac_algorithm_t mac, const char *label,
			  unsigned label_size, const uint8_t *msg,
			  size_t msg_size, const uint8_t secret[MAX_HASH_SIZE],
			  unsigned out_size, void *out)
{
	uint8_t tmp[256] = "tls13 ";
	gnutls_buffer_st str;
	gnutls_datum_t key;
	gnutls_datum_t info;
	int ret;

	if (unlikely(label_size >= sizeof(tmp) - 6))
		return gnutls_assert_val(GNUTLS_E_INVALID_REQUEST);

	_gnutls_buffer_init(&str);

	ret = _gnutls_buffer_append_prefix(&str, 16, out_size);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	memcpy(&tmp[6], label, label_size);
	ret = _gnutls_buffer_append_data_prefix(&str, 8, tmp, label_size + 6);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	ret = _gnutls_buffer_append_data_prefix(&str, 8, msg, msg_size);
	if (ret < 0) {
		gnutls_assert();
		goto cleanup;
	}

	key.data = (void *)secret;
	key.size = _gnutls_mac_get_algo_len(mac_to_entry(mac));
	info.data = str.data;
	info.size = str.length;

	ret = _gnutls_hkdf_expand(mac, &key, &info, out, out_size);
	if (ret < 0) {
		_gnutls_switch_fips_state(GNUTLS_FIPS140_OP_ERROR);
		gnutls_assert();
		goto cleanup;
	} else {
		_gnutls_switch_fips_state(GNUTLS_FIPS140_OP_APPROVED);
	}

#if 0
	_gnutls_hard_log("INT: hkdf label: %d,%s\n",
			 out_size,
			 _gnutls_bin2hex(str.data, str.length,
					 (char *)tmp, sizeof(tmp), NULL));
	_gnutls_hard_log("INT: secret expanded for '%.*s': %d,%s\n",
			 (int)label_size, label, out_size,
			 _gnutls_bin2hex(out, out_size,
					 (char *)tmp, sizeof(tmp), NULL));
#endif

	ret = 0;
cleanup:
	_gnutls_buffer_clear(&str);
	return ret;
}

int _tls13_expand_secret(gnutls_session_t session, const char *label,
			 unsigned label_size, const uint8_t *msg,
			 size_t msg_size, const uint8_t secret[MAX_HASH_SIZE],
			 unsigned out_size, void *out)
{
	if (unlikely(session->security_parameters.prf == NULL))
		return gnutls_assert_val(GNUTLS_E_INTERNAL_ERROR);

	return _gnutls_tls13_hkdf_ops.expand(
					session->security_parameters.prf->id,
					label, label_size, msg, msg_size,
					secret, out_size, out);
}

/** Function pointer for the TLS PRF implementation. */
gnutls_crypto_tls13_hkdf_st _gnutls_tls13_hkdf_ops = {
	.init = _tls13_init_secret2,
	.update = _tls13_update_secret2,
	.derive = _tls13_derive_secret2,
	.expand = _tls13_expand_secret2
};
