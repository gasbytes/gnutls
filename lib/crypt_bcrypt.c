/*
 *      Copyright (C) 2000,2001 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

/*
 * This is a modified version of the blowfish algorithm.
 * It is an implementation of the bcrypt algorithm as described
 * in a usenix paper by Niels Provos and David Mazieres.
 * This is the encoding algorithm used in OpenBSD for passwords.
 * (includes a modified version of b64.c)
 */

#include "defines.h"
#include "gnutls_int.h"
#include "crypt_bcrypt.h"
#include "gnutls_random.h"
#include "cert_b64.h"
#include "gnutls_srp.h"
#include <gnutls_errors.h>

#define rotl(x,n)   (((x) << ((uint32)(n))) | ((x) >> (32 - (uint32)(n))))
#define rotr(x,n)   (((x) >> ((uint32)(n))) | ((x) << (32 - (uint32)(n))))
#define byteswap(x)	((rotl(x, 8) & 0x00ff00ff) | (rotr(x, 8) & 0xff00ff00))

typedef struct {
	uint32 S[4][256], P[18];
} blf_ctx;

#define BF_N       16

#define F(bc, x) ( ((bc->S[0][(x >> 24) & 0xff] + bc->S[1][(x >> 16) & 0xff]) ^ bc->S[2][(x >>  8) & 0xff]) + bc->S[3][x & 0xff] )

/* x should be a 64 bit integer */
static void _blf_encrypt(blf_ctx * c, uint8 * x)
{
	uint32 Xl;
	uint32 Xr, temp;
	short i;

	Xl = x[0] << 24 | x[1] << 16 | x[2] << 8 | x[3];
	Xr = x[4] << 24 | x[5] << 16 | x[6] << 8 | x[7];

	for (i = 0; i < BF_N; ++i) {
		Xl ^= c->P[i];
		Xr ^= F(c, Xl);

		temp = Xl;
		Xl = Xr;
		Xr = temp;
	}

	temp = Xl;
	Xl = Xr;
	Xr = temp;

	Xr ^= c->P[BF_N];
	Xl ^= c->P[BF_N + 1];

	x[0] = (Xl >> 24) & 0xff;
	x[1] = (Xl >> 16) & 0xff;
	x[2] = (Xl >> 8) & 0xff;
	x[3] = (Xl) & 0xff;
	x[4] = (Xr >> 24) & 0xff;
	x[5] = (Xr >> 16) & 0xff;
	x[6] = (Xr >> 8) & 0xff;
	x[7] = (Xr) & 0xff;
}

/* x should be a 64 bit integer */
static void enblf_noswap(blf_ctx * c, uint32 * x)
{				/* Used internally */
	uint32 Xl;
	uint32 Xr, temp;
	short i;

	Xl = x[0];
	Xr = x[1];

	for (i = 0; i < BF_N; ++i) {
		Xl ^= c->P[i];
		Xr ^= F(c, Xl);

		temp = Xl;
		Xl = Xr;
		Xr = temp;
	}

	temp = Xl;
	Xl = Xr;
	Xr = temp;

	Xr ^= c->P[BF_N];
	Xl ^= c->P[BF_N + 1];

	x[0] = Xl;
	x[1] = Xr;
}


/* salt is an 128 bit integer */
static short initialize_blowfish(blf_ctx * c)
{
	short i;

	uint32 ks0[] = {
		0xd1310ba6UL, 0x98dfb5acUL, 0x2ffd72dbUL, 0xd01adfb7UL,
		0xb8e1afedUL, 0x6a267e96UL,
		0xba7c9045UL, 0xf12c7f99UL, 0x24a19947UL, 0xb3916cf7UL,
		0x0801f2e2UL, 0x858efc16UL,
		0x636920d8UL, 0x71574e69UL, 0xa458fea3UL, 0xf4933d7eUL,
		0x0d95748fUL, 0x728eb658UL,
		0x718bcd58UL, 0x82154aeeUL, 0x7b54a41dUL, 0xc25a59b5UL,
		0x9c30d539UL, 0x2af26013UL,
		0xc5d1b023UL, 0x286085f0UL, 0xca417918UL, 0xb8db38efUL,
		0x8e79dcb0UL, 0x603a180eUL,
		0x6c9e0e8bUL, 0xb01e8a3eUL, 0xd71577c1UL, 0xbd314b27UL,
		0x78af2fdaUL, 0x55605c60UL,
		0xe65525f3UL, 0xaa55ab94UL, 0x57489862UL, 0x63e81440UL,
		0x55ca396aUL, 0x2aab10b6UL,
		0xb4cc5c34UL, 0x1141e8ceUL, 0xa15486afUL, 0x7c72e993UL,
		0xb3ee1411UL, 0x636fbc2aUL,
		0x2ba9c55dUL, 0x741831f6UL, 0xce5c3e16UL, 0x9b87931eUL,
		0xafd6ba33UL, 0x6c24cf5cUL,
		0x7a325381UL, 0x28958677UL, 0x3b8f4898UL, 0x6b4bb9afUL,
		0xc4bfe81bUL, 0x66282193UL,
		0x61d809ccUL, 0xfb21a991UL, 0x487cac60UL, 0x5dec8032UL,
		0xef845d5dUL, 0xe98575b1UL,
		0xdc262302UL, 0xeb651b88UL, 0x23893e81UL, 0xd396acc5UL,
		0x0f6d6ff3UL, 0x83f44239UL,
		0x2e0b4482UL, 0xa4842004UL, 0x69c8f04aUL, 0x9e1f9b5eUL,
		0x21c66842UL, 0xf6e96c9aUL,
		0x670c9c61UL, 0xabd388f0UL, 0x6a51a0d2UL, 0xd8542f68UL,
		0x960fa728UL, 0xab5133a3UL,
		0x6eef0b6cUL, 0x137a3be4UL, 0xba3bf050UL, 0x7efb2a98UL,
		0xa1f1651dUL, 0x39af0176UL,
		0x66ca593eUL, 0x82430e88UL, 0x8cee8619UL, 0x456f9fb4UL,
		0x7d84a5c3UL, 0x3b8b5ebeUL,
		0xe06f75d8UL, 0x85c12073UL, 0x401a449fUL, 0x56c16aa6UL,
		0x4ed3aa62UL, 0x363f7706UL,
		0x1bfedf72UL, 0x429b023dUL, 0x37d0d724UL, 0xd00a1248UL,
		0xdb0fead3UL, 0x49f1c09bUL,
		0x075372c9UL, 0x80991b7bUL, 0x25d479d8UL, 0xf6e8def7UL,
		0xe3fe501aUL, 0xb6794c3bUL,
		0x976ce0bdUL, 0x04c006baUL, 0xc1a94fb6UL, 0x409f60c4UL,
		0x5e5c9ec2UL, 0x196a2463UL,
		0x68fb6fafUL, 0x3e6c53b5UL, 0x1339b2ebUL, 0x3b52ec6fUL,
		0x6dfc511fUL, 0x9b30952cUL,
		0xcc814544UL, 0xaf5ebd09UL, 0xbee3d004UL, 0xde334afdUL,
		0x660f2807UL, 0x192e4bb3UL,
		0xc0cba857UL, 0x45c8740fUL, 0xd20b5f39UL, 0xb9d3fbdbUL,
		0x5579c0bdUL, 0x1a60320aUL,
		0xd6a100c6UL, 0x402c7279UL, 0x679f25feUL, 0xfb1fa3ccUL,
		0x8ea5e9f8UL, 0xdb3222f8UL,
		0x3c7516dfUL, 0xfd616b15UL, 0x2f501ec8UL, 0xad0552abUL,
		0x323db5faUL, 0xfd238760UL,
		0x53317b48UL, 0x3e00df82UL, 0x9e5c57bbUL, 0xca6f8ca0UL,
		0x1a87562eUL, 0xdf1769dbUL,
		0xd542a8f6UL, 0x287effc3UL, 0xac6732c6UL, 0x8c4f5573UL,
		0x695b27b0UL, 0xbbca58c8UL,
		0xe1ffa35dUL, 0xb8f011a0UL, 0x10fa3d98UL, 0xfd2183b8UL,
		0x4afcb56cUL, 0x2dd1d35bUL,
		0x9a53e479UL, 0xb6f84565UL, 0xd28e49bcUL, 0x4bfb9790UL,
		0xe1ddf2daUL, 0xa4cb7e33UL,
		0x62fb1341UL, 0xcee4c6e8UL, 0xef20cadaUL, 0x36774c01UL,
		0xd07e9efeUL, 0x2bf11fb4UL,
		0x95dbda4dUL, 0xae909198UL, 0xeaad8e71UL, 0x6b93d5a0UL,
		0xd08ed1d0UL, 0xafc725e0UL,
		0x8e3c5b2fUL, 0x8e7594b7UL, 0x8ff6e2fbUL, 0xf2122b64UL,
		0x8888b812UL, 0x900df01cUL,
		0x4fad5ea0UL, 0x688fc31cUL, 0xd1cff191UL, 0xb3a8c1adUL,
		0x2f2f2218UL, 0xbe0e1777UL,
		0xea752dfeUL, 0x8b021fa1UL, 0xe5a0cc0fUL, 0xb56f74e8UL,
		0x18acf3d6UL, 0xce89e299UL,
		0xb4a84fe0UL, 0xfd13e0b7UL, 0x7cc43b81UL, 0xd2ada8d9UL,
		0x165fa266UL, 0x80957705UL,
		0x93cc7314UL, 0x211a1477UL, 0xe6ad2065UL, 0x77b5fa86UL,
		0xc75442f5UL, 0xfb9d35cfUL,
		0xebcdaf0cUL, 0x7b3e89a0UL, 0xd6411bd3UL, 0xae1e7e49UL,
		0x00250e2dUL, 0x2071b35eUL,
		0x226800bbUL, 0x57b8e0afUL, 0x2464369bUL, 0xf009b91eUL,
		0x5563911dUL, 0x59dfa6aaUL,
		0x78c14389UL, 0xd95a537fUL, 0x207d5ba2UL, 0x02e5b9c5UL,
		0x83260376UL, 0x6295cfa9UL,
		0x11c81968UL, 0x4e734a41UL, 0xb3472dcaUL, 0x7b14a94aUL,
		0x1b510052UL, 0x9a532915UL,
		0xd60f573fUL, 0xbc9bc6e4UL, 0x2b60a476UL, 0x81e67400UL,
		0x08ba6fb5UL, 0x571be91fUL,
		0xf296ec6bUL, 0x2a0dd915UL, 0xb6636521UL, 0xe7b9f9b6UL,
		0xff34052eUL, 0xc5855664UL,
		0x53b02d5dUL, 0xa99f8fa1UL, 0x08ba4799UL, 0x6e85076aUL
	};

	uint32 ks1[] = {
		0x4b7a70e9UL, 0xb5b32944UL, 0xdb75092eUL, 0xc4192623UL,
		0xad6ea6b0UL, 0x49a7df7dUL,
		0x9cee60b8UL, 0x8fedb266UL, 0xecaa8c71UL, 0x699a17ffUL,
		0x5664526cUL, 0xc2b19ee1UL,
		0x193602a5UL, 0x75094c29UL, 0xa0591340UL, 0xe4183a3eUL,
		0x3f54989aUL, 0x5b429d65UL,
		0x6b8fe4d6UL, 0x99f73fd6UL, 0xa1d29c07UL, 0xefe830f5UL,
		0x4d2d38e6UL, 0xf0255dc1UL,
		0x4cdd2086UL, 0x8470eb26UL, 0x6382e9c6UL, 0x021ecc5eUL,
		0x09686b3fUL, 0x3ebaefc9UL,
		0x3c971814UL, 0x6b6a70a1UL, 0x687f3584UL, 0x52a0e286UL,
		0xb79c5305UL, 0xaa500737UL,
		0x3e07841cUL, 0x7fdeae5cUL, 0x8e7d44ecUL, 0x5716f2b8UL,
		0xb03ada37UL, 0xf0500c0dUL,
		0xf01c1f04UL, 0x0200b3ffUL, 0xae0cf51aUL, 0x3cb574b2UL,
		0x25837a58UL, 0xdc0921bdUL,
		0xd19113f9UL, 0x7ca92ff6UL, 0x94324773UL, 0x22f54701UL,
		0x3ae5e581UL, 0x37c2dadcUL,
		0xc8b57634UL, 0x9af3dda7UL, 0xa9446146UL, 0x0fd0030eUL,
		0xecc8c73eUL, 0xa4751e41UL,
		0xe238cd99UL, 0x3bea0e2fUL, 0x3280bba1UL, 0x183eb331UL,
		0x4e548b38UL, 0x4f6db908UL,
		0x6f420d03UL, 0xf60a04bfUL, 0x2cb81290UL, 0x24977c79UL,
		0x5679b072UL, 0xbcaf89afUL,
		0xde9a771fUL, 0xd9930810UL, 0xb38bae12UL, 0xdccf3f2eUL,
		0x5512721fUL, 0x2e6b7124UL,
		0x501adde6UL, 0x9f84cd87UL, 0x7a584718UL, 0x7408da17UL,
		0xbc9f9abcUL, 0xe94b7d8cUL,
		0xec7aec3aUL, 0xdb851dfaUL, 0x63094366UL, 0xc464c3d2UL,
		0xef1c1847UL, 0x3215d908UL,
		0xdd433b37UL, 0x24c2ba16UL, 0x12a14d43UL, 0x2a65c451UL,
		0x50940002UL, 0x133ae4ddUL,
		0x71dff89eUL, 0x10314e55UL, 0x81ac77d6UL, 0x5f11199bUL,
		0x043556f1UL, 0xd7a3c76bUL,
		0x3c11183bUL, 0x5924a509UL, 0xf28fe6edUL, 0x97f1fbfaUL,
		0x9ebabf2cUL, 0x1e153c6eUL,
		0x86e34570UL, 0xeae96fb1UL, 0x860e5e0aUL, 0x5a3e2ab3UL,
		0x771fe71cUL, 0x4e3d06faUL,
		0x2965dcb9UL, 0x99e71d0fUL, 0x803e89d6UL, 0x5266c825UL,
		0x2e4cc978UL, 0x9c10b36aUL,
		0xc6150ebaUL, 0x94e2ea78UL, 0xa5fc3c53UL, 0x1e0a2df4UL,
		0xf2f74ea7UL, 0x361d2b3dUL,
		0x1939260fUL, 0x19c27960UL, 0x5223a708UL, 0xf71312b6UL,
		0xebadfe6eUL, 0xeac31f66UL,
		0xe3bc4595UL, 0xa67bc883UL, 0xb17f37d1UL, 0x018cff28UL,
		0xc332ddefUL, 0xbe6c5aa5UL,
		0x65582185UL, 0x68ab9802UL, 0xeecea50fUL, 0xdb2f953bUL,
		0x2aef7dadUL, 0x5b6e2f84UL,
		0x1521b628UL, 0x29076170UL, 0xecdd4775UL, 0x619f1510UL,
		0x13cca830UL, 0xeb61bd96UL,
		0x0334fe1eUL, 0xaa0363cfUL, 0xb5735c90UL, 0x4c70a239UL,
		0xd59e9e0bUL, 0xcbaade14UL,
		0xeecc86bcUL, 0x60622ca7UL, 0x9cab5cabUL, 0xb2f3846eUL,
		0x648b1eafUL, 0x19bdf0caUL,
		0xa02369b9UL, 0x655abb50UL, 0x40685a32UL, 0x3c2ab4b3UL,
		0x319ee9d5UL, 0xc021b8f7UL,
		0x9b540b19UL, 0x875fa099UL, 0x95f7997eUL, 0x623d7da8UL,
		0xf837889aUL, 0x97e32d77UL,
		0x11ed935fUL, 0x16681281UL, 0x0e358829UL, 0xc7e61fd6UL,
		0x96dedfa1UL, 0x7858ba99UL,
		0x57f584a5UL, 0x1b227263UL, 0x9b83c3ffUL, 0x1ac24696UL,
		0xcdb30aebUL, 0x532e3054UL,
		0x8fd948e4UL, 0x6dbc3128UL, 0x58ebf2efUL, 0x34c6ffeaUL,
		0xfe28ed61UL, 0xee7c3c73UL,
		0x5d4a14d9UL, 0xe864b7e3UL, 0x42105d14UL, 0x203e13e0UL,
		0x45eee2b6UL, 0xa3aaabeaUL,
		0xdb6c4f15UL, 0xfacb4fd0UL, 0xc742f442UL, 0xef6abbb5UL,
		0x654f3b1dUL, 0x41cd2105UL,
		0xd81e799eUL, 0x86854dc7UL, 0xe44b476aUL, 0x3d816250UL,
		0xcf62a1f2UL, 0x5b8d2646UL,
		0xfc8883a0UL, 0xc1c7b6a3UL, 0x7f1524c3UL, 0x69cb7492UL,
		0x47848a0bUL, 0x5692b285UL,
		0x095bbf00UL, 0xad19489dUL, 0x1462b174UL, 0x23820e00UL,
		0x58428d2aUL, 0x0c55f5eaUL,
		0x1dadf43eUL, 0x233f7061UL, 0x3372f092UL, 0x8d937e41UL,
		0xd65fecf1UL, 0x6c223bdbUL,
		0x7cde3759UL, 0xcbee7460UL, 0x4085f2a7UL, 0xce77326eUL,
		0xa6078084UL, 0x19f8509eUL,
		0xe8efd855UL, 0x61d99735UL, 0xa969a7aaUL, 0xc50c06c2UL,
		0x5a04abfcUL, 0x800bcadcUL,
		0x9e447a2eUL, 0xc3453484UL, 0xfdd56705UL, 0x0e1e9ec9UL,
		0xdb73dbd3UL, 0x105588cdUL,
		0x675fda79UL, 0xe3674340UL, 0xc5c43465UL, 0x713e38d8UL,
		0x3d28f89eUL, 0xf16dff20UL,
		0x153e21e7UL, 0x8fb03d4aUL, 0xe6e39f2bUL, 0xdb83adf7UL
	};

	uint32 ks2[] = {
		0xe93d5a68UL, 0x948140f7UL, 0xf64c261cUL, 0x94692934UL,
		0x411520f7UL, 0x7602d4f7UL,
		0xbcf46b2eUL, 0xd4a20068UL, 0xd4082471UL, 0x3320f46aUL,
		0x43b7d4b7UL, 0x500061afUL,
		0x1e39f62eUL, 0x97244546UL, 0x14214f74UL, 0xbf8b8840UL,
		0x4d95fc1dUL, 0x96b591afUL,
		0x70f4ddd3UL, 0x66a02f45UL, 0xbfbc09ecUL, 0x03bd9785UL,
		0x7fac6dd0UL, 0x31cb8504UL,
		0x96eb27b3UL, 0x55fd3941UL, 0xda2547e6UL, 0xabca0a9aUL,
		0x28507825UL, 0x530429f4UL,
		0x0a2c86daUL, 0xe9b66dfbUL, 0x68dc1462UL, 0xd7486900UL,
		0x680ec0a4UL, 0x27a18deeUL,
		0x4f3ffea2UL, 0xe887ad8cUL, 0xb58ce006UL, 0x7af4d6b6UL,
		0xaace1e7cUL, 0xd3375fecUL,
		0xce78a399UL, 0x406b2a42UL, 0x20fe9e35UL, 0xd9f385b9UL,
		0xee39d7abUL, 0x3b124e8bUL,
		0x1dc9faf7UL, 0x4b6d1856UL, 0x26a36631UL, 0xeae397b2UL,
		0x3a6efa74UL, 0xdd5b4332UL,
		0x6841e7f7UL, 0xca7820fbUL, 0xfb0af54eUL, 0xd8feb397UL,
		0x454056acUL, 0xba489527UL,
		0x55533a3aUL, 0x20838d87UL, 0xfe6ba9b7UL, 0xd096954bUL,
		0x55a867bcUL, 0xa1159a58UL,
		0xcca92963UL, 0x99e1db33UL, 0xa62a4a56UL, 0x3f3125f9UL,
		0x5ef47e1cUL, 0x9029317cUL,
		0xfdf8e802UL, 0x04272f70UL, 0x80bb155cUL, 0x05282ce3UL,
		0x95c11548UL, 0xe4c66d22UL,
		0x48c1133fUL, 0xc70f86dcUL, 0x07f9c9eeUL, 0x41041f0fUL,
		0x404779a4UL, 0x5d886e17UL,
		0x325f51ebUL, 0xd59bc0d1UL, 0xf2bcc18fUL, 0x41113564UL,
		0x257b7834UL, 0x602a9c60UL,
		0xdff8e8a3UL, 0x1f636c1bUL, 0x0e12b4c2UL, 0x02e1329eUL,
		0xaf664fd1UL, 0xcad18115UL,
		0x6b2395e0UL, 0x333e92e1UL, 0x3b240b62UL, 0xeebeb922UL,
		0x85b2a20eUL, 0xe6ba0d99UL,
		0xde720c8cUL, 0x2da2f728UL, 0xd0127845UL, 0x95b794fdUL,
		0x647d0862UL, 0xe7ccf5f0UL,
		0x5449a36fUL, 0x877d48faUL, 0xc39dfd27UL, 0xf33e8d1eUL,
		0x0a476341UL, 0x992eff74UL,
		0x3a6f6eabUL, 0xf4f8fd37UL, 0xa812dc60UL, 0xa1ebddf8UL,
		0x991be14cUL, 0xdb6e6b0dUL,
		0xc67b5510UL, 0x6d672c37UL, 0x2765d43bUL, 0xdcd0e804UL,
		0xf1290dc7UL, 0xcc00ffa3UL,
		0xb5390f92UL, 0x690fed0bUL, 0x667b9ffbUL, 0xcedb7d9cUL,
		0xa091cf0bUL, 0xd9155ea3UL,
		0xbb132f88UL, 0x515bad24UL, 0x7b9479bfUL, 0x763bd6ebUL,
		0x37392eb3UL, 0xcc115979UL,
		0x8026e297UL, 0xf42e312dUL, 0x6842ada7UL, 0xc66a2b3bUL,
		0x12754cccUL, 0x782ef11cUL,
		0x6a124237UL, 0xb79251e7UL, 0x06a1bbe6UL, 0x4bfb6350UL,
		0x1a6b1018UL, 0x11caedfaUL,
		0x3d25bdd8UL, 0xe2e1c3c9UL, 0x44421659UL, 0x0a121386UL,
		0xd90cec6eUL, 0xd5abea2aUL,
		0x64af674eUL, 0xda86a85fUL, 0xbebfe988UL, 0x64e4c3feUL,
		0x9dbc8057UL, 0xf0f7c086UL,
		0x60787bf8UL, 0x6003604dUL, 0xd1fd8346UL, 0xf6381fb0UL,
		0x7745ae04UL, 0xd736fcccUL,
		0x83426b33UL, 0xf01eab71UL, 0xb0804187UL, 0x3c005e5fUL,
		0x77a057beUL, 0xbde8ae24UL,
		0x55464299UL, 0xbf582e61UL, 0x4e58f48fUL, 0xf2ddfda2UL,
		0xf474ef38UL, 0x8789bdc2UL,
		0x5366f9c3UL, 0xc8b38e74UL, 0xb475f255UL, 0x46fcd9b9UL,
		0x7aeb2661UL, 0x8b1ddf84UL,
		0x846a0e79UL, 0x915f95e2UL, 0x466e598eUL, 0x20b45770UL,
		0x8cd55591UL, 0xc902de4cUL,
		0xb90bace1UL, 0xbb8205d0UL, 0x11a86248UL, 0x7574a99eUL,
		0xb77f19b6UL, 0xe0a9dc09UL,
		0x662d09a1UL, 0xc4324633UL, 0xe85a1f02UL, 0x09f0be8cUL,
		0x4a99a025UL, 0x1d6efe10UL,
		0x1ab93d1dUL, 0x0ba5a4dfUL, 0xa186f20fUL, 0x2868f169UL,
		0xdcb7da83UL, 0x573906feUL,
		0xa1e2ce9bUL, 0x4fcd7f52UL, 0x50115e01UL, 0xa70683faUL,
		0xa002b5c4UL, 0x0de6d027UL,
		0x9af88c27UL, 0x773f8641UL, 0xc3604c06UL, 0x61a806b5UL,
		0xf0177a28UL, 0xc0f586e0UL,
		0x006058aaUL, 0x30dc7d62UL, 0x11e69ed7UL, 0x2338ea63UL,
		0x53c2dd94UL, 0xc2c21634UL,
		0xbbcbee56UL, 0x90bcb6deUL, 0xebfc7da1UL, 0xce591d76UL,
		0x6f05e409UL, 0x4b7c0188UL,
		0x39720a3dUL, 0x7c927c24UL, 0x86e3725fUL, 0x724d9db9UL,
		0x1ac15bb4UL, 0xd39eb8fcUL,
		0xed545578UL, 0x08fca5b5UL, 0xd83d7cd3UL, 0x4dad0fc4UL,
		0x1e50ef5eUL, 0xb161e6f8UL,
		0xa28514d9UL, 0x6c51133cUL, 0x6fd5c7e7UL, 0x56e14ec4UL,
		0x362abfceUL, 0xddc6c837UL,
		0xd79a3234UL, 0x92638212UL, 0x670efa8eUL, 0x406000e0UL
	};

	uint32 ks3[] = {
		0x3a39ce37UL, 0xd3faf5cfUL, 0xabc27737UL, 0x5ac52d1bUL,
		0x5cb0679eUL, 0x4fa33742UL,
		0xd3822740UL, 0x99bc9bbeUL, 0xd5118e9dUL, 0xbf0f7315UL,
		0xd62d1c7eUL, 0xc700c47bUL,
		0xb78c1b6bUL, 0x21a19045UL, 0xb26eb1beUL, 0x6a366eb4UL,
		0x5748ab2fUL, 0xbc946e79UL,
		0xc6a376d2UL, 0x6549c2c8UL, 0x530ff8eeUL, 0x468dde7dUL,
		0xd5730a1dUL, 0x4cd04dc6UL,
		0x2939bbdbUL, 0xa9ba4650UL, 0xac9526e8UL, 0xbe5ee304UL,
		0xa1fad5f0UL, 0x6a2d519aUL,
		0x63ef8ce2UL, 0x9a86ee22UL, 0xc089c2b8UL, 0x43242ef6UL,
		0xa51e03aaUL, 0x9cf2d0a4UL,
		0x83c061baUL, 0x9be96a4dUL, 0x8fe51550UL, 0xba645bd6UL,
		0x2826a2f9UL, 0xa73a3ae1UL,
		0x4ba99586UL, 0xef5562e9UL, 0xc72fefd3UL, 0xf752f7daUL,
		0x3f046f69UL, 0x77fa0a59UL,
		0x80e4a915UL, 0x87b08601UL, 0x9b09e6adUL, 0x3b3ee593UL,
		0xe990fd5aUL, 0x9e34d797UL,
		0x2cf0b7d9UL, 0x022b8b51UL, 0x96d5ac3aUL, 0x017da67dUL,
		0xd1cf3ed6UL, 0x7c7d2d28UL,
		0x1f9f25cfUL, 0xadf2b89bUL, 0x5ad6b472UL, 0x5a88f54cUL,
		0xe029ac71UL, 0xe019a5e6UL,
		0x47b0acfdUL, 0xed93fa9bUL, 0xe8d3c48dUL, 0x283b57ccUL,
		0xf8d56629UL, 0x79132e28UL,
		0x785f0191UL, 0xed756055UL, 0xf7960e44UL, 0xe3d35e8cUL,
		0x15056dd4UL, 0x88f46dbaUL,
		0x03a16125UL, 0x0564f0bdUL, 0xc3eb9e15UL, 0x3c9057a2UL,
		0x97271aecUL, 0xa93a072aUL,
		0x1b3f6d9bUL, 0x1e6321f5UL, 0xf59c66fbUL, 0x26dcf319UL,
		0x7533d928UL, 0xb155fdf5UL,
		0x03563482UL, 0x8aba3cbbUL, 0x28517711UL, 0xc20ad9f8UL,
		0xabcc5167UL, 0xccad925fUL,
		0x4de81751UL, 0x3830dc8eUL, 0x379d5862UL, 0x9320f991UL,
		0xea7a90c2UL, 0xfb3e7bceUL,
		0x5121ce64UL, 0x774fbe32UL, 0xa8b6e37eUL, 0xc3293d46UL,
		0x48de5369UL, 0x6413e680UL,
		0xa2ae0810UL, 0xdd6db224UL, 0x69852dfdUL, 0x09072166UL,
		0xb39a460aUL, 0x6445c0ddUL,
		0x586cdecfUL, 0x1c20c8aeUL, 0x5bbef7ddUL, 0x1b588d40UL,
		0xccd2017fUL, 0x6bb4e3bbUL,
		0xdda26a7eUL, 0x3a59ff45UL, 0x3e350a44UL, 0xbcb4cdd5UL,
		0x72eacea8UL, 0xfa6484bbUL,
		0x8d6612aeUL, 0xbf3c6f47UL, 0xd29be463UL, 0x542f5d9eUL,
		0xaec2771bUL, 0xf64e6370UL,
		0x740e0d8dUL, 0xe75b1357UL, 0xf8721671UL, 0xaf537d5dUL,
		0x4040cb08UL, 0x4eb4e2ccUL,
		0x34d2466aUL, 0x0115af84UL, 0xe1b00428UL, 0x95983a1dUL,
		0x06b89fb4UL, 0xce6ea048UL,
		0x6f3f3b82UL, 0x3520ab82UL, 0x011a1d4bUL, 0x277227f8UL,
		0x611560b1UL, 0xe7933fdcUL,
		0xbb3a792bUL, 0x344525bdUL, 0xa08839e1UL, 0x51ce794bUL,
		0x2f32c9b7UL, 0xa01fbac9UL,
		0xe01cc87eUL, 0xbcc7d1f6UL, 0xcf0111c3UL, 0xa1e8aac7UL,
		0x1a908749UL, 0xd44fbd9aUL,
		0xd0dadecbUL, 0xd50ada38UL, 0x0339c32aUL, 0xc6913667UL,
		0x8df9317cUL, 0xe0b12b4fUL,
		0xf79e59b7UL, 0x43f5bb3aUL, 0xf2d519ffUL, 0x27d9459cUL,
		0xbf97222cUL, 0x15e6fc2aUL,
		0x0f91fc71UL, 0x9b941525UL, 0xfae59361UL, 0xceb69cebUL,
		0xc2a86459UL, 0x12baa8d1UL,
		0xb6c1075eUL, 0xe3056a0cUL, 0x10d25065UL, 0xcb03a442UL,
		0xe0ec6e0eUL, 0x1698db3bUL,
		0x4c98a0beUL, 0x3278e964UL, 0x9f1f9532UL, 0xe0d392dfUL,
		0xd3a0342bUL, 0x8971f21eUL,
		0x1b0a7441UL, 0x4ba3348cUL, 0xc5be7120UL, 0xc37632d8UL,
		0xdf359f8dUL, 0x9b992f2eUL,
		0xe60b6f47UL, 0x0fe3f11dUL, 0xe54cda54UL, 0x1edad891UL,
		0xce6279cfUL, 0xcd3e7e6fUL,
		0x1618b166UL, 0xfd2c1d05UL, 0x848fd2c5UL, 0xf6fb2299UL,
		0xf523f357UL, 0xa6327623UL,
		0x93a83531UL, 0x56cccd02UL, 0xacf08162UL, 0x5a75ebb5UL,
		0x6e163697UL, 0x88d273ccUL,
		0xde966292UL, 0x81b949d0UL, 0x4c50901bUL, 0x71c65614UL,
		0xe6c6c7bdUL, 0x327a140aUL,
		0x45e1d006UL, 0xc3f27b9aUL, 0xc9aa53fdUL, 0x62a80f00UL,
		0xbb25bfe2UL, 0x35bdd2f6UL,
		0x71126905UL, 0xb2040222UL, 0xb6cbcf7cUL, 0xcd769c2bUL,
		0x53113ec0UL, 0x1640e3d3UL,
		0x38abbd60UL, 0x2547adf0UL, 0xba38209cUL, 0xf746ce76UL,
		0x77afa1c5UL, 0x20756060UL,
		0x85cbfe4eUL, 0x8ae88dd8UL, 0x7aaaf9b0UL, 0x4cf9aa7eUL,
		0x1948c25cUL, 0x02fb8a8cUL,
		0x01c36ae4UL, 0xd6ebe1f9UL, 0x90d4f869UL, 0xa65cdea0UL,
		0x3f09252dUL, 0xc208e69fUL,
		0xb74e6132UL, 0xce77e25bUL, 0x578fdfe3UL, 0x3ac372e6UL
	};


	uint32 pi[] = {
		0x243f6a88UL, 0x85a308d3UL, 0x13198a2eUL, 0x03707344UL,
		0xa4093822UL, 0x299f31d0UL,
		0x082efa98UL, 0xec4e6c89UL, 0x452821e6UL, 0x38d01377UL,
		0xbe5466cfUL, 0x34e90c6cUL,
		0xc0ac29b7UL, 0xc97c50ddUL, 0x3f84d5b5UL, 0xb5470917UL,
		0x9216d5d9UL, 0x8979fb1bUL
	};


/* Initialize s-boxes without file read. */
	for (i = 0; i < 256; i++) {
		c->S[0][i] = ks0[i];
		c->S[1][i] = ks1[i];
		c->S[2][i] = ks2[i];
		c->S[3][i] = ks3[i];
	}

/* P-boxes */
	for (i = 0; i < 18; i++) {
		c->P[i] = pi[i];
	}
	return 0;
}

static short _blf_ExpandKey(blf_ctx * c, const uint8 * key, short keybytes,
			    const uint8 * bsalt)
{
	short i, j;
	int k;
	uint32 data, temp[2];
	uint32 wsalt[4];

	if (bsalt != NULL) {
		wsalt[0] = 0x00000000;
		wsalt[1] = 0x00000000;
		wsalt[2] = 0x00000000;
		wsalt[3] = 0x00000000;
		for (i = 0; i < 4; i++) {
			wsalt[0] = (wsalt[0] << 8) | bsalt[i];
			wsalt[1] = (wsalt[1] << 8) | bsalt[i + 4];
			wsalt[2] = (wsalt[2] << 8) | bsalt[i + 8];
			wsalt[3] = (wsalt[3] << 8) | bsalt[i + 12];
		}
	}

	temp[0] = temp[1] = 0x00000000;

	j = 0;
	/* Step 1: XOR the Pbox with the key */
	for (i = 0; i < BF_N + 2; i++) {
		data = 0x00000000;
		data = (data << 8) | key[(j) % keybytes];
		data = (data << 8) | key[(j + 1) % keybytes];
		data = (data << 8) | key[(j + 2) % keybytes];
		data = (data << 8) | key[(j + 3) % keybytes];

		c->P[i] ^= data;
		j = (j + 4) % keybytes;
	}

	k = 2;			/* This should be 0 ??? */
	/* Step 2: Use the salt on Pbox */
	for (i = 0; i < BF_N + 2; i += 2) {
		if (bsalt != NULL) {
			temp[0] ^= wsalt[(k + 2) % 4];
			temp[1] ^= wsalt[(k + 3) % 4];
			k = (k + 2) % 4;
		}
		enblf_noswap(c, temp);
		c->P[i] = temp[0];
		c->P[i + 1] = temp[1];
	}

	for (i = 0; i < 4; i++) {
		for (j = 0; j < 256; j += 2) {
			if (bsalt != NULL) {
				temp[0] ^= wsalt[(k + 2) % 4];
				temp[1] ^= wsalt[(k + 3) % 4];
				k = (k + 2) % 4;
			}
			enblf_noswap(c, temp);
			c->S[i][j] = temp[0];
			c->S[i][j + 1] = temp[1];

		}
	}
	return 0;
}




static blf_ctx *_blf_init(uint8 * salt, const char *key, int key_len,
			  int cost)
{
	blf_ctx *state = malloc(sizeof(blf_ctx));
	uint32 i, rcost;

	rcost = (uint32) 1 << cost;	/* 2^cost */

	initialize_blowfish(state);
	_blf_ExpandKey(state, (uint8 *) key, key_len, salt);
	for (i = 0; i < rcost; i++) {
		/* these should have been in reverse order */
		_blf_ExpandKey(state, (uint8 *) key, key_len, NULL);
		_blf_ExpandKey(state, salt, 16, NULL);
	}
	return state;
}

static void _blf_deinit(blf_ctx * ctx)
{
	free(ctx);
}
static const char magic[] = "$2$";

char *crypt_bcrypt(const char *passwd, const char *salt, MPI g, MPI n)
{
	unsigned char *sp;
	blf_ctx *ctx;
	unsigned char text[24] = "OrpheanBeholderScryDoubt";
	uint8 *csalt;
	uint8 *rtext;
	uint8 cost;
	int i, salt_size = strlen(salt), len;
	unsigned char *local_salt, *v;
	int passwd_len, vsize;
	opaque *tmp;

	passwd_len = strlen(passwd) + 1;	/* we want the null also */
	if (passwd_len > 56)
		passwd_len = 56;

	local_salt = malloc(salt_size + 1);
	strcpy((char *) local_salt, salt);

	sp = index( local_salt, ':'); /* move to salt - after verifier */
	if (sp==NULL) {
		gnutls_assert();
		return NULL;
	}
	sp++;

	len = (int)rindex(sp, ':');
	if (len==0) { /* no ':' was found */
		gnutls_assert();
		return NULL;
	}
	len -= (int) sp;
	
	if (_gnutls_sbase64_decode(sp, len, &csalt) < 0) {
		gnutls_assert();
		return NULL;
	}

	cost = (uint8) csalt[0];
	ctx = _blf_init(&csalt[1], passwd, passwd_len, cost);
	gnutls_free(csalt);

	for (i = 0; i < 64; i++) {
		_blf_encrypt(ctx, (uint8 *) text);
		_blf_encrypt(ctx, (uint8 *) & text[8]);
		_blf_encrypt(ctx, (uint8 *) & text[16]);
	}

	/* v = g^x mod n */
	vsize = _gnutls_srp_gx(text, 8 * 3, &v, g, n);
	if (vsize == -1 || v == NULL) {
		gnutls_assert();
		return NULL;
	}

	if (_gnutls_sbase64_encode(v, vsize, &rtext) < 0) {
		gnutls_free(v);
		gnutls_assert();
		return NULL;
	}
	gnutls_free(v);

	tmp =
	    gnutls_malloc(strlen(magic) + 3 + strlen(sp) + 1 +
			  strlen(rtext) + 1);

	sprintf(tmp, "%s%s:%s", magic, rtext, sp);

	gnutls_free(local_salt);
	gnutls_free(rtext);

	_blf_deinit(ctx);
	return tmp;
}

/* cost is stored as the first byte in salt (thus < 255) which is fine! */
char *crypt_bcrypt_wrapper(const char *pass_new, int cost, MPI g, MPI n)
{
	unsigned char *result;
	char *tcp;
	unsigned char *rand;
	char *e = NULL;
	int result_size;

	rand = _gnutls_get_random(17, GNUTLS_WEAK_RANDOM);
	/* cost should be <32 and >6 */
	if (cost >= 32)
		cost = 31;
	if (cost < 1)
		cost = 1;

	rand[0] = (uint8) cost;
	result_size = _gnutls_sbase64_encode(rand, 17, &result);
	if (result_size < 0) {
		_gnutls_free_rand(rand);
		gnutls_assert();
		return NULL;
	}

	tcp = gnutls_calloc(1, 1 + result_size + 1);
	sprintf(tcp, ":%s", result);

	gnutls_free(result);

	_gnutls_free_rand(rand);

	e = crypt_bcrypt(pass_new, (const char *) tcp, g, n);
	gnutls_free(tcp);

	return e;
}

void *_gnutls_calc_srp_bcrypt(char *passwd, opaque * salt, int salt_size, int* size)
{
	blf_ctx *ctx;
	opaque text[24] = "OrpheanBeholderScryDoubt";
	int passwd_len, i;
	opaque *tmp;

	*size = sizeof(text);
	
	/* we need 16 + cost */
	if (salt_size < 17) return NULL;
	
	passwd_len = strlen(passwd) + 1;	/* we want the null also */
	if (passwd_len > 56)
		passwd_len = 56;

	ctx = _blf_init(&salt[1], passwd, passwd_len, (uint32)salt[0]);

	tmp = malloc(sizeof(text));
	memcpy(tmp, text, sizeof(text));

	for (i = 0; i < 64; i++) {
		_blf_encrypt(ctx, (uint8 *) tmp);
		_blf_encrypt(ctx, (uint8 *) & tmp[8]);
		_blf_encrypt(ctx, (uint8 *) & tmp[16]);
	}

	_blf_deinit(ctx);
	return tmp;
}
