'use strict';

// eslint-disable-next-line no-multi-assign
exports.randomBytes = exports.rng = exports.pseudoRandomBytes = exports.prng = function () {
	throw new Error('Deprecated. Use Crypto.getRandomValues() - bring your own implementation for your runtime');
};

// eslint-disable-next-line no-multi-assign
exports.createHash = exports.Hash = require('./noble-hash-wrapper');

// eslint-disable-next-line no-multi-assign
exports.createHmac = exports.Hmac = require('./noble-hmac-wrapper');

const hashes = [
	'sha1',
	'sha224',
	'sha256',
	'sha384',
	'sha512',
	'md5',
	'rmd160'
];

exports.getHashes = function () {
	return hashes;
};

const p = require('./noble-pbkdf2-wrapper');
exports.pbkdf2 = p.pbkdf2;
exports.pbkdf2Sync = p.pbkdf2Sync;

const aes = require('./noble-cipher-wrapper');

exports.Cipher = aes.Cipher;
exports.createCipher = aes.createCipher;
exports.Cipheriv = aes.Cipheriv;
exports.createCipheriv = aes.createCipheriv;
exports.Decipher = aes.Decipher;
exports.createDecipher = aes.createDecipher;
exports.Decipheriv = aes.Decipheriv;
exports.createDecipheriv = aes.createDecipheriv;
exports.getCiphers = aes.getCiphers;
exports.listCiphers = aes.listCiphers;

const dh = require('./micro-dh-wrapper');

exports.DiffieHellmanGroup = dh.DiffieHellmanGroup;
exports.createDiffieHellmanGroup = dh.createDiffieHellmanGroup;
exports.getDiffieHellman = dh.getDiffieHellman;
exports.createDiffieHellman = dh.createDiffieHellman;
exports.DiffieHellman = dh.DiffieHellman;

const signVerify = require('./noble-sign-wrapper');

exports.createSign = signVerify.createSign;
exports.Sign = signVerify.Sign;
exports.createVerify = signVerify.createVerify;
exports.Verify = signVerify.Verify;

exports.createECDH = require('./noble-ecdh-wrapper');

const rsa = require('./noble-rsa-wrapper');

exports.publicEncrypt = rsa.publicEncrypt;
exports.privateEncrypt = rsa.privateEncrypt;
exports.publicDecrypt = rsa.publicDecrypt;
exports.privateDecrypt = rsa.privateDecrypt;

// the least I can do is make error messages for the rest of the node.js/crypto api.
// [
//   'createCredentials'
// ].forEach(function (name) {
//   exports[name] = function () {
//     throw new Error('sorry, ' + name + ' is not implemented yet\nwe accept pull requests\nhttps://github.com/browserify/crypto-browserify');
//   };
// });

exports.randomFill = function () {
	throw new Error('Deprecated. Use Crypto.getRandomValues() - bring your own implementation for your runtime');
};
exports.randomFillSync = function () {
	throw new Error('Deprecated. Use Crypto.getRandomValues() - bring your own implementation for your runtime');
};

exports.createCredentials = function () {
	throw new Error('sorry, createCredentials is not implemented yet\nwe accept pull requests\nhttps://github.com/browserify/crypto-browserify');
};

exports.constants = {
	DH_CHECK_P_NOT_SAFE_PRIME: 2,
	DH_CHECK_P_NOT_PRIME: 1,
	DH_UNABLE_TO_CHECK_GENERATOR: 4,
	DH_NOT_SUITABLE_GENERATOR: 8,
	NPN_ENABLED: 1,
	ALPN_ENABLED: 1,
	RSA_PKCS1_PADDING: 1,
	RSA_SSLV23_PADDING: 2,
	RSA_NO_PADDING: 3,
	RSA_PKCS1_OAEP_PADDING: 4,
	RSA_X931_PADDING: 5,
	RSA_PKCS1_PSS_PADDING: 6,
	POINT_CONVERSION_COMPRESSED: 2,
	POINT_CONVERSION_UNCOMPRESSED: 4,
	POINT_CONVERSION_HYBRID: 6
};
