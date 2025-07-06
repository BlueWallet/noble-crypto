'use strict';

/* global Uint8Array */

var secp256k1 = require('@noble/curves/secp256k1');
var p256 = require('@noble/curves/p256');
var p384 = require('@noble/curves/p384');
var p521 = require('@noble/curves/p521');
var ed25519 = require('@noble/curves/ed25519');
var ed448 = require('@noble/curves/ed448');
var sha2 = require('@noble/hashes/sha2');
var legacy = require('@noble/hashes/legacy');

// For RSA algorithms, fall back to browserify-sign (legacy, not noble)
var browserifySign = require('browserify-sign');

// Map algorithm names to noble curve functions
var curveFunctions = {
	secp256k1: secp256k1,
	p256: p256,
	p384: p384,
	p521: p521,
	ed25519: ed25519,
	ed448: ed448
};

// Map hash algorithms to noble hash functions
var hashFunctions = {
	sha1: legacy.sha1,
	sha224: sha2.sha224,
	sha256: sha2.sha256,
	sha384: sha2.sha384,
	sha512: sha2.sha512,
	md5: legacy.md5,
	rmd160: legacy.ripemd160
};

// Helper function to convert data to Uint8Array
function toUint8Array(data) {
	if (data instanceof Uint8Array) {
		return data;
	}
	if (typeof data === 'string') {
		return new Uint8Array(Buffer.from(data, 'utf8'));
	}
	if (Buffer.isBuffer(data)) {
		return new Uint8Array(data);
	}
	throw new Error('Unsupported data type');
}

// Helper function to create browserify-sign fallback
function createSignFallback(algorithm) {
	var signInstance = browserifySign.createSign(algorithm);
	return {
		update: signInstance.update.bind(signInstance),
		sign: signInstance.sign.bind(signInstance)
	};
}

// Helper function to create browserify-sign verify fallback
function createVerifyFallback(algorithm) {
	var verifyInstance = browserifySign.createVerify(algorithm);
	return {
		update: verifyInstance.update.bind(verifyInstance),
		verify: verifyInstance.verify.bind(verifyInstance)
	};
}

// Helper function to parse algorithm and determine if it should use noble
function parseAlgorithm(algorithm) {
	var parts = algorithm.toLowerCase().split('-');
	if (parts.length < 2) {
		return {
			useNoble: false,
			reason: 'invalid-format'
		};
	}

	var curveName = parts[0];
	var hashName = parts[1];

	// Handle RSA algorithms
	if (curveName === 'rsa') {
		return {
			useNoble: false,
			reason: 'rsa'
		};
	}

	// Check if curve and hash are supported
	var curve = curveFunctions[curveName];
	var hash = hashFunctions[hashName];

	if (!curve) {
		return {
			useNoble: false,
			reason: 'unsupported-curve'
		};
	}
	if (!hash) {
		return {
			useNoble: false,
			reason: 'unsupported-hash'
		};
	}

	return {
		useNoble: true, curve: curve, hash: hash
	};
}

function Sign(algorithm) {
	this.algorithm = algorithm;
	this.curve = null;
	this.hashFunction = null;
	this.privateKey = null;
	this.data = [];
	this.finalized = false;

	var parsed = parseAlgorithm(algorithm);
	if (!parsed.useNoble) {
		var fallback = createSignFallback(algorithm);
		this.update = fallback.update;
		this.sign = fallback.sign;
		return;
	}

	this.curve = parsed.curve;
	this.hashFunction = parsed.hash;
}

Sign.prototype.update = function (data, encoding) {
	if (this.finalized) {
		throw new Error('Sign already finalized');
	}
	var uint8Data;
	if (encoding) {
		if (encoding === 'hex') {
			uint8Data = new Uint8Array(Buffer.from(data, 'hex'));
		} else if (encoding === 'base64') {
			uint8Data = new Uint8Array(Buffer.from(data, 'base64'));
		} else {
			throw new Error('Unsupported encoding: ' + encoding);
		}
	} else {
		uint8Data = toUint8Array(data);
	}
	this.data.push(uint8Data);
	return this;
};

Sign.prototype.sign = function (privateKey, encoding) {
	if (this.finalized) {
		throw new Error('Sign already finalized');
	}
	if (!privateKey) {
		throw new Error('Private key is required');
	}
	// Concatenate all data
	var allData = new Uint8Array(this.data.reduce(function (total, chunk) {
		return total + chunk.length;
	}, 0));
	var offset = 0;
	for (var i = 0; i < this.data.length; i++) {
		allData.set(this.data[i], offset);
		offset += this.data[i].length;
	}
	// Hash the data
	var hashedData = this.hashFunction(allData);
	// Sign the hash
	var signature = this.curve.sign(hashedData, privateKey);
	this.finalized = true;
	if (encoding === 'hex') {
		return signature.toHex();
	}
	if (encoding === 'base64') {
		return signature.toBase64();
	}
	return signature.toBytes();
};

function Verify(algorithm) {
	this.algorithm = algorithm;
	this.curve = null;
	this.hashFunction = null;
	this.publicKey = null;
	this.data = [];
	this.finalized = false;

	var parsed = parseAlgorithm(algorithm);
	if (!parsed.useNoble) {
		var fallback = createVerifyFallback(algorithm);
		this.update = fallback.update;
		this.verify = fallback.verify;
		return;
	}

	this.curve = parsed.curve;
	this.hashFunction = parsed.hash;
}

Verify.prototype.update = function (data, encoding) {
	if (this.finalized) {
		throw new Error('Verify already finalized');
	}
	var uint8Data;
	if (encoding) {
		if (encoding === 'hex') {
			uint8Data = new Uint8Array(Buffer.from(data, 'hex'));
		} else if (encoding === 'base64') {
			uint8Data = new Uint8Array(Buffer.from(data, 'base64'));
		} else {
			throw new Error('Unsupported encoding: ' + encoding);
		}
	} else {
		uint8Data = toUint8Array(data);
	}
	this.data.push(uint8Data);
	return this;
};

Verify.prototype.verify = function (publicKey, signature, encoding) {
	if (this.finalized) {
		throw new Error('Verify already finalized');
	}
	if (!publicKey) {
		throw new Error('Public key is required');
	}
	if (!signature) {
		throw new Error('Signature is required');
	}
	// Concatenate all data
	var allData = new Uint8Array(this.data.reduce(function (total, chunk) {
		return total + chunk.length;
	}, 0));
	var offset = 0;
	for (var i = 0; i < this.data.length; i++) {
		allData.set(this.data[i], offset);
		offset += this.data[i].length;
	}
	// Hash the data
	var hashedData = this.hashFunction(allData);
	// Parse signature based on encoding
	var signatureBytes;
	if (encoding === 'hex') {
		signatureBytes = new Uint8Array(Buffer.from(signature, 'hex'));
	} else if (encoding === 'base64') {
		signatureBytes = new Uint8Array(Buffer.from(signature, 'base64'));
	} else {
		signatureBytes = toUint8Array(signature);
	}
	// Verify the signature
	this.finalized = true;
	return this.curve.verify(signatureBytes, hashedData, publicKey);
};

// Export the functions
exports.createSign = function (algorithm) {
	return new Sign(algorithm);
};

exports.Sign = Sign;

exports.createVerify = function (algorithm) {
	return new Verify(algorithm);
};

exports.Verify = Verify;
