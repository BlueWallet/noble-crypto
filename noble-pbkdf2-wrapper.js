'use strict';

const noblePbkdf2 = require('@noble/hashes/pbkdf2');
const sha1 = require('@noble/hashes/sha1');
const sha2 = require('@noble/hashes/sha2');
const legacy = require('@noble/hashes/legacy');

// Map digest names to noble hash functions
const hashFunctions = {
	sha1: sha1.sha1,
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

function pbkdf2Sync(password, salt, iterations, keylen, digest) {
	// Default to sha1 if no digest specified
	const hashName = digest || 'sha1';

	// Get the hash function
	const hashFunction = hashFunctions[hashName];
	if (!hashFunction) {
		throw new Error('Unsupported digest algorithm: ' + hashName);
	}

	// Convert inputs to Uint8Array
	const passwordBytes = toUint8Array(password);
	const saltBytes = toUint8Array(salt);

	// Call noble PBKDF2
	const result = noblePbkdf2.pbkdf2(hashFunction, passwordBytes, saltBytes, {
		c: iterations,
		dkLen: keylen
	});

	// Return as Buffer
	return Buffer.from(result);
}

function pbkdf2(password, salt, iterations, keylen, digest, callback) {
	// Default to sha1 if no digest specified
	const hashName = digest || 'sha1';

	// Get the hash function
	const hashFunction = hashFunctions[hashName];
	if (!hashFunction) {
		callback(new Error('Unsupported digest algorithm: ' + hashName));
		return;
	}

	// Convert inputs to Uint8Array
	let passwordBytes, saltBytes;
	try {
		passwordBytes = toUint8Array(password);
		saltBytes = toUint8Array(salt);
	} catch (err) {
		callback(err);
		return;
	}

	// Use async version for callback-based API
	noblePbkdf2.pbkdf2Async(hashFunction, passwordBytes, saltBytes, {
		c: iterations,
		dkLen: keylen
	}).then(function (result) {
		callback(null, Buffer.from(result));
	})['catch'](function (err) {
		callback(err);
	});
}

module.exports = {
	pbkdf2Sync: pbkdf2Sync,
	pbkdf2: pbkdf2
};
