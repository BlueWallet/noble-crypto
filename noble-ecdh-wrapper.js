'use strict';

var secp256k1 = require('@noble/curves/secp256k1');
var nist = require('@noble/curves/nist');
var Buffer = require('safe-buffer').Buffer;

// Fallback to create-ecdh/browser for unsupported curves and hybrid format
var createEcdhBrowser = require('create-ecdh/browser');

// Curve name mapping
var curveMap = {
	secp256k1: secp256k1.secp256k1,
	secp224r1: null, // Will fallback to create-ecdh
	prime256v1: nist.p256,
	prime192v1: null // Not available in noble
};

function ECDH(curveName) {
	// Fallback for secp224r1 and prime192v1
	if (curveName === 'secp224r1' || curveName === 'prime192v1') {
		// Use create-ecdh/browser fallback for secp224r1 and prime192v1
		return createEcdhBrowser(curveName);
	}
	if (!curveMap[curveName]) {
		throw new Error('Unsupported curve: ' + curveName);
	}

	this.curve = curveMap[curveName];
	this.privateKey = null;
	this.publicKey = null;
	this.curveName = curveName;
}

ECDH.prototype.generateKeys = function () {
	this.privateKey = this.curve.utils.randomPrivateKey();
	this.publicKey = this.curve.getPublicKey(this.privateKey);
	return this;
};

ECDH.prototype.getPrivateKey = function (encoding) {
	if (!this.privateKey) {
		throw new Error('Private key not set');
	}

	var key = Buffer.from(this.privateKey);
	return encoding === 'hex' ? key.toString('hex') : key;
};

ECDH.prototype.getPublicKey = function (encoding, format) {
	if (!this.publicKey) {
		throw new Error('Public key not set');
	}

	// Fallback for hybrid format
	if (format === 'hybrid') {
		// Use create-ecdh/browser fallback for hybrid format
		// This is required because noble-curves does not support hybrid format
		return createEcdhBrowser(this.curveName).setPrivateKey(this.getPrivateKey()).getPublicKey(encoding, format);
	}

	var key;
	if (format === 'compressed') {
		key = Buffer.from(this.curve.getPublicKey(this.privateKey, true));
	} else {
		// uncompressed
		key = Buffer.from(this.publicKey);
	}

	return encoding === 'hex' ? key.toString('hex') : key;
};

ECDH.prototype.setPrivateKey = function (privateKey) {
	var key;
	if (typeof privateKey === 'string') {
		key = Buffer.from(privateKey, 'hex');
	} else {
		key = Buffer.from(privateKey);
	}

	// Validate private key
	var expectedLength = this.curve.CURVE.n.toString(16).length / 2;
	if (key.length !== expectedLength) {
		throw new Error('Invalid private key length: expected ' + expectedLength + ', got ' + key.length);
	}

	this.privateKey = new global.Uint8Array(key);
	this.publicKey = this.curve.getPublicKey(this.privateKey);
	return this;
};

ECDH.prototype.setPublicKey = function (publicKey) {
	var key;
	if (typeof publicKey === 'string') {
		key = Buffer.from(publicKey, 'hex');
	} else {
		key = Buffer.from(publicKey);
	}

	// Validate public key
	try {
		this.curve.Point.fromHex(key.toString('hex'));
	} catch (e) {
		throw new Error('Invalid public key: ' + e.message);
	}

	this.publicKey = new global.Uint8Array(key);
	return this;
};

ECDH.prototype.computeSecret = function (otherPublicKey) {
	if (!this.privateKey) {
		throw new Error('Private key not set');
	}

	var otherKey;
	if (typeof otherPublicKey === 'string') {
		otherKey = Buffer.from(otherPublicKey, 'hex');
	} else {
		otherKey = Buffer.from(otherPublicKey);
	}

	try {
		var sharedSecret = this.curve.getSharedSecret(this.privateKey, otherKey);
		// Remove the prefix (first byte) from the shared secret
		return Buffer.from(sharedSecret.slice(1));
	} catch (e) {
		throw new Error('Failed to compute shared secret: ' + e.message);
	}
};

function createECDH(curveName) {
	return new ECDH(curveName);
}

module.exports = createECDH;
