'use strict';

const sha2 = require('@noble/hashes/sha2');
const legacy = require('@noble/hashes/legacy');

// Map algorithm names to noble hash functions
const hashFunctions = {
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
	let result = '';
	const hexBase = 16;
	const padLength = 2;
	for (let i = 0; i < bytes.length; i++) {
		result += bytes[i].toString(hexBase).padStart(padLength, '0');
	}
	return result;
}

// Helper function to convert Uint8Array to base64 string
function toBase64(bytes) {
	return Buffer.from(bytes).toString('base64');
}

function Hash(algorithm) {
	this.algorithm = algorithm;
	this.hashFunction = hashFunctions[algorithm];
	if (!this.hashFunction) {
		throw new Error('Unsupported hash algorithm: ' + algorithm);
	}
	this.data = [];
	this.finalized = false;
}

Hash.prototype.update = function (data, encoding) {
	if (this.finalized) {
		throw new Error('Digest already called');
	}

	let uint8Data;
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

	this.data.push(uint8Data);
	return this;
};

Hash.prototype.digest = function (encoding) {
	if (this.finalized) {
		throw new Error('Digest already called');
	}

	// Concatenate all data
	let totalLength = 0;
	for (let i = 0; i < this.data.length; i++) {
		totalLength += this.data[i].length;
	}
	const concatenated = new Uint8Array(totalLength);
	let offset = 0;
	for (let j = 0; j < this.data.length; j++) {
		const chunk = this.data[j];
		concatenated.set(chunk, offset);
		offset += chunk.length;
	}

	// Calculate hash
	const result = this.hashFunction(concatenated);
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

Hash.prototype.copy = function () {
	if (this.finalized) {
		throw new Error('Cannot copy after digest');
	}
	const newHash = new Hash(this.algorithm);
	newHash.data = [];
	for (let i = 0; i < this.data.length; i++) {
		newHash.data.push(new Uint8Array(this.data[i]));
	}
	return newHash;
};

Hash.prototype.end = function (data) {
	if (typeof data !== 'undefined') {
		this.update(data);
	}
	this.result = this.digest();
	return this;
};

Hash.prototype.read = function () {
	if (this.result) {
		return this.result;
	}
	return this.digest();
};

function createHash(algorithm) {
	return new Hash(algorithm);
}

module.exports = createHash;
module.exports.Hash = Hash;

