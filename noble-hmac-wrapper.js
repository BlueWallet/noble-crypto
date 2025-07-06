'use strict';

/* global Uint8Array */

var hmac = require('@noble/hashes/hmac').hmac;
var sha2 = require('@noble/hashes/sha2');
var legacy = require('@noble/hashes/legacy');

// Map algorithm names to noble hash functions
var hashFunctions = {
	sha1: legacy.sha1,
	sha224: sha2.sha224,
	sha256: sha2.sha256,
	sha384: sha2.sha384,
	sha512: sha2.sha512,
	md5: legacy.md5,
	rmd160: legacy.ripemd160
};

// Helper function to convert Buffer/string to Uint8Array
function toUint8Array(data) {
	if (data instanceof Uint8Array) {
		return data;
	}
	if (data instanceof Buffer) {
		return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
	}
	if (typeof data === 'string') {
		return new TextEncoder().encode(data);
	}
	throw new Error('Unsupported data type');
}

// Helper function to convert Uint8Array to hex string
function toHex(bytes) {
	var result = '';
	var hexBase = 16;
	var padLength = 2;
	for (var i = 0; i < bytes.length; i++) {
		result += bytes[i].toString(hexBase).padStart(padLength, '0');
	}
	return result;
}

// Helper function to convert Uint8Array to base64 string
function toBase64(bytes) {
	return Buffer.from(bytes).toString('base64');
}

function Hmac(algorithm, key, encoding) {
	this.algorithm = algorithm;
	this.hashFunction = hashFunctions[algorithm];
	if (!this.hashFunction) {
		throw new Error('Unsupported hash algorithm: ' + algorithm);
	}

	// Node's createHmac allows key to be a string with encoding
	var keyBuf;
	if (typeof key === 'string') {
		// If encoding is not provided, default to 'utf8' (Node's default)
		keyBuf = Buffer.from(key, encoding || 'utf8');
	} else if (Buffer.isBuffer(key)) {
		keyBuf = key;
	} else if (key instanceof Uint8Array) {
		keyBuf = Buffer.from(key);
	} else {
		throw new Error('Invalid key type for HMAC');
	}

	// Create noble HMAC instance
	this.hmacInstance = hmac.create(this.hashFunction, new Uint8Array(keyBuf));
	this.finalized = false;
}

Hmac.prototype.update = function (data, encoding) {
	if (this.finalized) {
		throw new Error('Digest already called');
	}

	var uint8Data;
	if (encoding) {
		// Handle encoding parameter
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

	this.hmacInstance.update(uint8Data);
	return this;
};

Hmac.prototype.digest = function (encoding) {
	if (this.finalized) {
		throw new Error('Digest already called');
	}

	// Calculate HMAC
	var result = this.hmacInstance.digest();
	this.finalized = true;

	// Return based on encoding
	if (!encoding) {
		return Buffer.from(result);
	}
	if (encoding === 'hex') {
		return toHex(result);
	}
	if (encoding === 'base64') {
		return toBase64(result);
	}
	throw new Error('Unsupported encoding: ' + encoding);
};

Hmac.prototype.copy = function () {
	if (this.finalized) {
		throw new Error('Cannot copy after digest');
	}
	var newHmac = new Hmac(this.algorithm, Buffer.from(this.hmacInstance.cloneInto().iHash.digest()));
	newHmac.hmacInstance = this.hmacInstance.clone();
	return newHmac;
};

Hmac.prototype.end = function (data, encoding) {
	if (typeof data !== 'undefined') {
		this.update(data, encoding);
	}
	this.result = this.digest();
	return this;
};

Hmac.prototype.read = function () {
	if (this.result) {
		return this.result;
	}
	return this.digest();
};

function createHmac(algorithm, key, encoding) {
	return new Hmac(algorithm, key, encoding);
}

module.exports = createHmac;
module.exports.Hmac = Hmac;
