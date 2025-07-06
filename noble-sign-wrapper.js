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

function parseSingleHash(parts) {
	var singleHashName = parts[0];
	var singleHash = hashFunctions[singleHashName];
	if (singleHash) {
		return {
			useNoble: true,
			curve: curveFunctions.p256,
			hash: singleHash,
			reason: 'legacy-hash-only'
		};
	}
	return {
		useNoble: false,
		reason: 'invalid-format'
	};
}

function parseMultiPart(parts) {
	var curveName = parts[0];
	var hashName = parts[1];
	if (curveName === 'rsa') {
		return {
			useNoble: false,
			reason: 'rsa'
		};
	}
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
		useNoble: true,
		curve: curve,
		hash: hash
	};
}

// Helper function to parse algorithm and determine if it should use noble
function parseAlgorithm(algorithm) {
	var parts = algorithm.toLowerCase().split('-');
	if (parts.length === 1) {
		return parseSingleHash(parts);
	}
	if (parts.length < 2) {
		return { useNoble: false, reason: 'invalid-format' };
	}
	return parseMultiPart(parts);
}

// Helper function to try noble curve signing
function tryNobleSign(curve, hashedData, privateKeyBytes) {
	if (curve.sign) {
		return curve.sign(hashedData, privateKeyBytes);
	}
	if (curve.Signature && curve.Signature.sign) {
		return curve.Signature.sign(hashedData, privateKeyBytes);
	}
	if (curve.secp256k1 && curve.secp256k1.sign) {
		return curve.secp256k1.sign(hashedData, privateKeyBytes);
	}
	return null;
}

// Helper function to try noble curve verification
function tryNobleVerify(curve, signatureBytes, hashedData, publicKeyBytes) {
	if (curve.verify) {
		return curve.verify(signatureBytes, hashedData, publicKeyBytes);
	}
	if (curve.Signature && curve.Signature.verify) {
		return curve.Signature.verify(signatureBytes, hashedData, publicKeyBytes);
	}
	if (curve.secp256k1 && curve.secp256k1.verify) {
		return curve.secp256k1.verify(signatureBytes, hashedData, publicKeyBytes);
	}
	return null;
}

// Helper function to create fallback instances
function createFallbackInst(algorithm, data, type) {
	var inst = type === 'sign' ? createSignFallback(algorithm) : createVerifyFallback(algorithm);
	inst.data = data;
	return inst;
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

	// Convert private key to Uint8Array if needed
	var privateKeyBytes = toUint8Array(privateKey);

	// Try to sign using noble curve
	var signature;
	try {
		signature = tryNobleSign(this.curve, hashedData, privateKeyBytes);
		if (signature === null) {
			var signFallback = createFallbackInst(this.algorithm, this.data, 'sign');
			return signFallback.sign(privateKey, encoding);
		}
	} catch (error) {
		var signFallbackCatch = createFallbackInst(this.algorithm, this.data, 'sign');
		return signFallbackCatch.sign(privateKey, encoding);
	}

	this.finalized = true;

	// Return signature based on encoding
	if (encoding === 'hex') {
		return signature.toHex ? signature.toHex() : Buffer.from(signature).toString('hex');
	}
	if (encoding === 'base64') {
		return signature.toBase64 ? signature.toBase64() : Buffer.from(signature).toString('base64');
	}
	return signature.toBytes ? signature.toBytes() : Buffer.from(signature);
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

	// Convert public key to Uint8Array if needed
	var publicKeyBytes = toUint8Array(publicKey);

	// Verify the signature using noble curve
	var isValid;
	try {
		isValid = tryNobleVerify(this.curve, signatureBytes, hashedData, publicKeyBytes);
		if (isValid === null) {
			var verifyFallback = createFallbackInst(this.algorithm, this.data, 'verify');
			return verifyFallback.verify(publicKey, signature, encoding);
		}
	} catch (error) {
		var verifyFallbackCatch = createFallbackInst(this.algorithm, this.data, 'verify');
		return verifyFallbackCatch.verify(publicKey, signature, encoding);
	}

	this.finalized = true;
	return isValid;
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
