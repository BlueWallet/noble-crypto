'use strict';

const secp256k1 = require('@noble/curves/secp256k1');
const nist = require('@noble/curves/nist');
const Buffer = require('safe-buffer').Buffer;

// Curve name mapping
const curveMap = {
	secp256k1: secp256k1.secp256k1,
	secp224r1: null, // Not available in noble
	prime256v1: nist.p256,
	prime192v1: null // Not available in noble
};

function ECDH(curveName) {

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

	const key = Buffer.from(this.privateKey);
	return encoding === 'hex' ? key.toString('hex') : key;
};

ECDH.prototype.getPublicKey = function (encoding, format) {
	if (!this.publicKey) {
		throw new Error('Public key not set');
	}

	if (format === 'hybrid') {
		// noble-curves does not support hybrid format
		throw new Error('Unsupported format: ' + format);
	}

	let key;
	if (format === 'compressed') {
		key = Buffer.from(this.curve.getPublicKey(this.privateKey, true));
	} else {
		// uncompressed
		key = Buffer.from(this.publicKey);
	}

	return encoding === 'hex' ? key.toString('hex') : key;
};

ECDH.prototype.setPrivateKey = function (privateKey) {
	let key;
	if (typeof privateKey === 'string') {
		key = Buffer.from(privateKey, 'hex');
	} else {
		key = Buffer.from(privateKey);
	}

	// Validate private key
	const expectedLength = this.curve.CURVE.n.toString(16).length / 2;
	if (key.length !== expectedLength) {
		throw new Error('Invalid private key length: expected ' + expectedLength + ', got ' + key.length);
	}

	this.privateKey = new global.Uint8Array(key);
	this.publicKey = this.curve.getPublicKey(this.privateKey);
	return this;
};

ECDH.prototype.setPublicKey = function (publicKey) {
	let key;
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

	let otherKey;
	if (typeof otherPublicKey === 'string') {
		otherKey = Buffer.from(otherPublicKey, 'hex');
	} else {
		otherKey = Buffer.from(otherPublicKey);
	}

	try {
		const sharedSecret = this.curve.getSharedSecret(this.privateKey, otherKey);
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
