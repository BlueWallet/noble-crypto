'use strict';

var DHGroupsModule = require('micro-rsa-dsa-dh/dh.js');
var DHGroups = DHGroupsModule.DHGroups;
var Buffer = require('safe-buffer').Buffer;

/* global window */

// Cross-platform random bytes function
function getRandomBytes(buffer) {
	if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.getRandomValues) {
		// Browser environment - use Web Crypto API
		globalThis.crypto.getRandomValues(buffer);
	} else if (typeof window !== 'undefined' && window.crypto && window.crypto.getRandomValues) {
		// Browser environment - use Web Crypto API
		window.crypto.getRandomValues(buffer);
	} else {
		throw new Error('crypto.getRandomValues() is not shimmed in properly');
	}
}

// Convert bigint to Buffer with proper padding
function bigintToBuffer(bigint, length) {
	var hex = bigint.toString(16);
	// Ensure even length by padding with leading zero if needed
	var paddedHex = hex.length % 2 === 0 ? hex : '0' + hex;
	var buffer = Buffer.from(paddedHex, 'hex');

	if (length && buffer.length < length) {
		// Pad with leading zeros to reach desired length
		var pad = Buffer.alloc(length - buffer.length, 0);
		return Buffer.concat([pad, buffer]);
	}

	return buffer;
}

// Helper function for BigInt power operation
function bigintPow(base, exponent) {
	var result = BigInt(1);
	var localBase = BigInt(base);
	var localExponent = BigInt(exponent);
	while (localExponent > 0) {
		if (localExponent % BigInt(2) === BigInt(1)) {
			result = result * localBase;
		}
		localBase = localBase * localBase;
		localExponent = localExponent / BigInt(2);
	}
	return result;
}

// Convert Buffer to bigint
function bufferToBigint(buffer) {
	return BigInt('0x' + buffer.toString('hex'));
}

// Modular exponentiation
function modPow(base, exp, mod) {
	var result = BigInt(1);
	var localBase = base % mod;
	var localExp = exp;
	while (localExp > BigInt(0)) {
		if (localExp % BigInt(2) === BigInt(1)) {
			result = (result * localBase) % mod;
		}
		localExp = localExp >> BigInt(1);
		localBase = (localBase * localBase) % mod;
	}
	return result;
}

// Miller-Rabin primality test helper
function millerRabinTest(n, a, d, r) {
	var x = modPow(a, d, n);
	if (x === BigInt(1) || x === n - BigInt(1)) {
		return true;
	}

	for (var i = 0; i < r - 1; i++) {
		x = modPow(x, BigInt(2), n);
		if (x === n - BigInt(1)) {
			return true;
		}
	}

	return false;
}

// Simple probabilistic primality test
function isProbablePrime(n) {
	if (n < BigInt(2)) {
		return false;
	}
	if (n === BigInt(2)) {
		return true;
	}
	if (n % BigInt(2) === BigInt(0)) {
		return false;
	}

	// Miller-Rabin primality test (simplified)
	var d = n - BigInt(1);
	var r = 0;
	while (d % BigInt(2) === BigInt(0)) {
		d /= BigInt(2);
		r = r + 1;
	}

	// Test with a few witnesses
	var witnesses = [
		BigInt(2),
		BigInt(3),
		BigInt(5),
		BigInt(7),
		BigInt(11),
		BigInt(13),
		BigInt(17),
		BigInt(19),
		BigInt(23),
		BigInt(29),
		BigInt(31),
		BigInt(37)
	];
	for (var i = 0; i < witnesses.length; i++) {
		var a = witnesses[i];
		if (a < n) {
			if (!millerRabinTest(n, a, d, r)) {
				return false;
			}
		}
	}

	return true;
}

// Generate a random prime of specified bit length
function generatePrime(bitLength) {
	// Simple prime generation (not cryptographically secure, but sufficient for this demo)
	// In production, you'd use a proper prime generation algorithm
	var min = bigintPow(BigInt(2), BigInt(bitLength - 1));
	var max = bigintPow(BigInt(2), BigInt(bitLength)) - BigInt(1);

	// Generate random number in range
	var candidate;
	do {
		var randomBytes = Buffer.allocUnsafe(Math.ceil(bitLength / 8));
		getRandomBytes(randomBytes);
		candidate = bufferToBigint(randomBytes);
		candidate = (candidate % (max - min + BigInt(1))) + min;
	} while (!isProbablePrime(candidate));

	return candidate;
}

// Custom DH implementation for arbitrary primes/generators
function CustomDH(prime, generator) {
	this.prime = prime;
	this.generator = generator;
	this.privateKey = null;
	this.publicKey = null;
}

CustomDH.prototype.randomPrivateKey = function () {
	// Generate random private key in range [1, prime-1]
	var keyBytes = Buffer.allocUnsafe(Math.ceil(this.prime.toString(16).length / 2));
	getRandomBytes(keyBytes);
	var key = bufferToBigint(keyBytes);
	key = (key % (this.prime - BigInt(1))) + BigInt(1);
	return key;
};

CustomDH.prototype.getPublicKey = function (privateKey) {
	return modPow(this.generator, privateKey, this.prime);
};

CustomDH.prototype.getSharedSecret = function (privateKey, otherPublicKey) {
	var otherPubKeyBigint = typeof otherPublicKey === 'bigint' ? otherPublicKey : bufferToBigint(otherPublicKey);
	return modPow(otherPubKeyBigint, privateKey, this.prime);
};

// DiffieHellman class that wraps our custom implementation
function DiffieHellman(prime, generator) {
	if (typeof prime === 'string' && DHGroups[prime]) {
		// Using predefined group - use DHGroups data with our custom implementation
		this.customDH = new CustomDH(DHGroups[prime].p, DHGroups[prime].g);
		this.group = prime;
		this.customPrime = DHGroups[prime].p;
		this.customGenerator = DHGroups[prime].g;
		this.primeLength = Math.ceil(DHGroups[prime].p.toString(16).length / 2);
	} else if (typeof prime === 'number') {
		// Key length specified - generate prime of that length
		var generatedPrime = generatePrime(prime);
		var generatedGenerator = BigInt(2); // Use 2 as generator (safe for most primes)
		this.customDH = new CustomDH(generatedPrime, generatedGenerator);
		this.customPrime = generatedPrime;
		this.customGenerator = generatedGenerator;
		this.primeLength = Math.ceil(generatedPrime.toString(16).length / 2);
	} else if (Buffer.isBuffer(prime)) {
		// Custom prime provided
		var primeBigint = bufferToBigint(prime);
		var genBigint = BigInt(2); // Default generator
		if (Buffer.isBuffer(generator)) {
			genBigint = bufferToBigint(generator);
		} else if (typeof generator === 'number') {
			genBigint = BigInt(generator);
		}
		this.customDH = new CustomDH(primeBigint, genBigint);
		this.customPrime = primeBigint;
		this.customGenerator = genBigint;
		this.primeLength = Math.ceil(primeBigint.toString(16).length / 2);
	} else {
		throw new Error('Invalid prime type for DiffieHellman constructor');
	}

	this.privateKey = null;
	this.publicKey = null;
}

DiffieHellman.prototype.generateKeys = function (encoding) {
	// Always use custom DH implementation
	this.privateKey = this.customDH.randomPrivateKey();
	this.publicKey = this.customDH.getPublicKey(this.privateKey);

	if (encoding) {
		return this.getPublicKey(encoding);
	}
	return this.getPublicKey(); // Return as Buffer
};

DiffieHellman.prototype.computeSecret = function (otherPublicKey, inputEncoding, outputEncoding) {
	if (!this.privateKey) {
		throw new Error('Keys not generated. Call generateKeys() first.');
	}

	// Using custom DH implementation for all cases
	var otherKeyInput;
	if (Buffer.isBuffer(otherPublicKey)) {
		otherKeyInput = otherPublicKey;
	} else if (typeof otherPublicKey === 'string') {
		otherKeyInput = Buffer.from(otherPublicKey, inputEncoding || 'hex');
	} else if (otherPublicKey && typeof otherPublicKey.constructor === 'function' && otherPublicKey.constructor.name === 'Uint8Array') {
		otherKeyInput = Buffer.from(otherPublicKey);
	} else {
		throw new Error('Invalid public key type for computeSecret');
	}

	var sharedSecret = this.customDH.getSharedSecret(this.privateKey, otherKeyInput);
	var result = bigintToBuffer(sharedSecret, this.primeLength);

	if (outputEncoding) {
		return result.toString(outputEncoding);
	}
	return result;
};

DiffieHellman.prototype.getPrime = function (encoding) {
	if (!this.customPrime) {
		throw new Error('No prime available');
	}

	var result = bigintToBuffer(this.customPrime);
	if (encoding) {
		return result.toString(encoding);
	}
	return result;
};

DiffieHellman.prototype.getGenerator = function (encoding) {
	if (!this.customGenerator) {
		throw new Error('No generator available');
	}

	var result = bigintToBuffer(this.customGenerator);
	if (encoding) {
		return result.toString(encoding);
	}
	return result;
};

DiffieHellman.prototype.getPublicKey = function (encoding) {
	if (!this.publicKey) {
		throw new Error('Keys not generated. Call generateKeys() first.');
	}

	var result = bigintToBuffer(this.publicKey, this.primeLength);

	if (encoding) {
		return result.toString(encoding);
	}
	return result;
};

DiffieHellman.prototype.getPrivateKey = function (encoding) {
	if (!this.privateKey) {
		throw new Error('Keys not generated. Call generateKeys() first.');
	}

	var result = bigintToBuffer(this.privateKey);
	if (encoding) {
		return result.toString(encoding);
	}
	return result;
};

// Factory functions that match the diffie-hellman API
function createDiffieHellman(prime, generator, keyLength) {
	return new DiffieHellman(prime, generator, keyLength);
}

function getDiffieHellman(groupName) {
	return new DiffieHellman(groupName);
}

function createDHGroup(groupName) {
	return new DiffieHellman(groupName);
}

// Export the same API as diffie-hellman
module.exports = {
	DiffieHellman: DiffieHellman,
	createDiffieHellman: createDiffieHellman,
	getDiffieHellman: getDiffieHellman,
	createDiffieHellmanGroup: createDHGroup,
	DiffieHellmanGroup: createDHGroup
};
