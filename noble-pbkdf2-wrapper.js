'use strict';

/* global Uint8Array */

var noblePbkdf2 = require('@noble/hashes/pbkdf2');
var sha1 = require('@noble/hashes/sha1');
var sha2 = require('@noble/hashes/sha2');
var legacy = require('@noble/hashes/legacy');

// Map digest names to noble hash functions
var hashFunctions = {
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
	var hashName = digest || 'sha1';

	// Get the hash function
	var hashFunction = hashFunctions[hashName];
	if (!hashFunction) {
		throw new Error('Unsupported digest algorithm: ' + hashName);
	}

	// Convert inputs to Uint8Array
	var passwordBytes = toUint8Array(password);
	var saltBytes = toUint8Array(salt);

	// Call noble PBKDF2
	var result = noblePbkdf2.pbkdf2(hashFunction, passwordBytes, saltBytes, {
		c: iterations,
		dkLen: keylen
	});

	// Return as Buffer
	return Buffer.from(result);
}

function pbkdf2(password, salt, iterations, keylen, digest, callback) {
	// Default to sha1 if no digest specified
	var hashName = digest || 'sha1';

	// Get the hash function
	var hashFunction = hashFunctions[hashName];
	if (!hashFunction) {
		callback(new Error('Unsupported digest algorithm: ' + hashName));
		return;
	}

	// Convert inputs to Uint8Array
	var passwordBytes, saltBytes;
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
