'use strict';

const aes = require('@noble/ciphers/aes');
const utils = require('@noble/ciphers/utils');
const sha256 = require('@noble/hashes/sha256');

// Map cipher names to noble AES functions
const cipherMap = {
	// AES modes
	'aes-128-ecb': { fn: aes.ecb, keySize: 16 },
	'aes-192-ecb': { fn: aes.ecb, keySize: 24 },
	'aes-256-ecb': { fn: aes.ecb, keySize: 32 },
	'aes-128-cbc': { fn: aes.cbc, keySize: 16 },
	'aes-192-cbc': { fn: aes.cbc, keySize: 24 },
	'aes-256-cbc': { fn: aes.cbc, keySize: 32 },
	'aes-128-cfb': { fn: aes.cfb, keySize: 16 },
	'aes-192-cfb': { fn: aes.cfb, keySize: 24 },
	'aes-256-cfb': { fn: aes.cfb, keySize: 32 },
	'aes-128-cfb8': { fn: aes.cfb, keySize: 16 },
	'aes-192-cfb8': { fn: aes.cfb, keySize: 24 },
	'aes-256-cfb8': { fn: aes.cfb, keySize: 32 },
	'aes-128-cfb1': { fn: aes.cfb, keySize: 16 },
	'aes-192-cfb1': { fn: aes.cfb, keySize: 24 },
	'aes-256-cfb1': { fn: aes.cfb, keySize: 32 },
	'aes-128-ofb': { fn: aes.ctr, keySize: 16 }, // OFB is similar to CTR
	'aes-192-ofb': { fn: aes.ctr, keySize: 24 },
	'aes-256-ofb': { fn: aes.ctr, keySize: 32 },
	'aes-128-ctr': { fn: aes.ctr, keySize: 16 },
	'aes-192-ctr': { fn: aes.ctr, keySize: 24 },
	'aes-256-ctr': { fn: aes.ctr, keySize: 32 },
	'aes-128-gcm': { fn: aes.gcm, keySize: 16 },
	'aes-192-gcm': { fn: aes.gcm, keySize: 24 },
	'aes-256-gcm': { fn: aes.gcm, keySize: 32 },
	// Legacy names
	aes128: { fn: aes.cbc, keySize: 16 },
	aes192: { fn: aes.cbc, keySize: 24 },
	aes256: { fn: aes.cbc, keySize: 32 }
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

// Helper function to convert Uint8Array to Buffer
function toBuffer(data) {
	if (data instanceof Buffer) {
		return data;
	}
	return Buffer.from(data);
}

// Helper function to derive key from password
function deriveKey(password, salt, keySize) {
	const passwordBytes = toUint8Array(password);
	const saltBytes = toUint8Array(salt);

	// Simple key derivation - in real usage you'd want PBKDF2
	const hash = sha256.sha256(utils.concatBytes(passwordBytes, saltBytes));
	return hash.slice(0, keySize);
}

// Helper function to generate IV
function generateIV(ivSize) {
	const iv = new Uint8Array(ivSize);
	for (let i = 0; i < ivSize; i++) {
		iv[i] = Math.floor(Math.random() * 256);
	}
	return iv;
}

// Cipher class
function Cipher(algorithm, password) {
	this.algorithm = algorithm;
	this.password = password;
	this.cipherInfo = cipherMap[algorithm];

	if (!this.cipherInfo) {
		throw new Error('Unsupported cipher: ' + algorithm);
	}

	this.keySize = this.cipherInfo.keySize;
	this.isGcm = algorithm.indexOf('gcm') > -1;
	this.isEcb = algorithm.indexOf('ecb') > -1;

	// Generate salt and IV
	this.salt = generateIV(16);
	if (this.isEcb) {
		this.iv = null;
	} else if (this.isGcm) {
		this.iv = generateIV(12);
	} else {
		this.iv = generateIV(16);
	}

	// Derive key
	this.key = deriveKey(password, this.salt, this.keySize);

	// Initialize cipher
	if (this.isEcb) {
		this.cipher = this.cipherInfo.fn(this.key);
	} else {
		this.cipher = this.cipherInfo.fn(this.key, this.iv);
	}

	this.encrypted = [];
	this.authTag = null;
}

Cipher.prototype.update = function (data) {
	const dataBytes = toUint8Array(data);
	this.encrypted.push(dataBytes);
	return Buffer.alloc(0); // No output until final
};

Cipher.prototype['final'] = function () {
	const input = Buffer.concat(this.encrypted.map(toBuffer));
	let result;
	let output;
	if (this.isGcm) {
		const encResult = this.cipher.encrypt(input);
		const tagLen = 16;
		const ciphertext = encResult.slice(0, -tagLen);
		const tag = encResult.slice(-tagLen);
		this.authTag = Buffer.from(tag);
		output = Buffer.concat([
			Buffer.from(this.salt), Buffer.from(this.iv), Buffer.from(ciphertext)
		]);
	} else if (this.isEcb) {
		result = this.cipher.encrypt(input);
		output = Buffer.concat([Buffer.from(this.salt), Buffer.from(result)]);
	} else {
		result = this.cipher.encrypt(input);
		output = Buffer.concat([
			Buffer.from(this.salt), Buffer.from(this.iv), Buffer.from(result)
		]);
	}
	return output;
};

Cipher.prototype.getAuthTag = function () {
	if (!this.isGcm) {
		throw new Error('getAuthTag only supported for GCM mode');
	}
	return this.authTag;
};

// Cipheriv class
function Cipheriv(algorithm, key, iv) {
	this.algorithm = algorithm;
	this.key = toUint8Array(key);
	this.iv = toUint8Array(iv);
	this.cipherInfo = cipherMap[algorithm];

	if (!this.cipherInfo) {
		throw new Error('Unsupported cipher: ' + algorithm);
	}

	this.isGcm = algorithm.indexOf('gcm') > -1;
	this.isEcb = algorithm.indexOf('ecb') > -1;

	// Initialize cipher
	if (this.isEcb) {
		this.cipher = this.cipherInfo.fn(this.key);
	} else {
		this.cipher = this.cipherInfo.fn(this.key, this.iv);
	}

	this.encrypted = [];
	this.authTag = null;
}

Cipheriv.prototype.update = function (data) {
	const dataBytes = toUint8Array(data);
	let result;

	if (this.isEcb) {
		result = this.cipher.encrypt(dataBytes);
	} else {
		result = this.cipher.encrypt(dataBytes);
	}

	this.encrypted.push(result);
	return toBuffer(result);
};

Cipheriv.prototype['final'] = function () {
	const result = Buffer.concat(this.encrypted.map(toBuffer));

	if (this.isGcm) {
		this.authTag = toBuffer(this.cipher.tag);
	}

	return result;
};

Cipheriv.prototype.getAuthTag = function () {
	if (!this.isGcm) {
		throw new Error('getAuthTag only supported for GCM mode');
	}
	return this.authTag;
};

// Decipher class
function Decipher(algorithm, password) {
	this.algorithm = algorithm;
	this.password = password;
	this.cipherInfo = cipherMap[algorithm];

	if (!this.cipherInfo) {
		throw new Error('Unsupported cipher: ' + algorithm);
	}

	this.keySize = this.cipherInfo.keySize;
	this.isGcm = algorithm.indexOf('gcm') > -1;
	this.isEcb = algorithm.indexOf('ecb') > -1;

	this.decrypted = [];
	this.authTag = null;
}

Decipher.prototype.update = function (data) {
	const dataBytes = toUint8Array(data);
	this.decrypted.push(dataBytes);
	return Buffer.alloc(0); // No output until final
};

Decipher.prototype['final'] = function () {
	const input = Buffer.concat(this.decrypted.map(toBuffer));
	// For first call, extract salt and IV, derive key, and initialize cipher
	if (!this.cipher) {
		this.salt = input.slice(0, 16);
		if (this.isGcm) {
			this.iv = input.slice(16, 28);
			this.key = deriveKey(this.password, this.salt, this.keySize);
			const gcmCipherData = input.slice(28);
			if (!this.authTag) {
				throw new Error('GCM: authTag must be set before final');
			}
			this.cipher = this.cipherInfo.fn(this.key, this.iv);
			const gcmCiphertextWithTag = Buffer.concat([gcmCipherData, this.authTag]);
			const gcmResult = this.cipher.decrypt(gcmCiphertextWithTag);
			return toBuffer(gcmResult);
		}
		this.iv = this.isEcb ? null : input.slice(16, 32);
		this.key = deriveKey(this.password, this.salt, this.keySize);
		const blockCipherData = input.slice(this.isEcb ? 16 : 32);
		if (this.isEcb) {
			this.cipher = this.cipherInfo.fn(this.key);
		} else {
			this.cipher = this.cipherInfo.fn(this.key, this.iv);
		}
		const blockResult = this.cipher.decrypt(blockCipherData);
		return toBuffer(blockResult);
	}
	const result = this.cipher.decrypt(input);
	return toBuffer(result);
};

Decipher.prototype.setAuthTag = function (tag) {
	if (!this.isGcm) {
		throw new Error('setAuthTag only supported for GCM mode');
	}
	this.authTag = toUint8Array(tag);
};

// Decipheriv class
function Decipheriv(algorithm, key, iv) {
	this.algorithm = algorithm;
	this.key = toUint8Array(key);
	this.iv = toUint8Array(iv);
	this.cipherInfo = cipherMap[algorithm];

	if (!this.cipherInfo) {
		throw new Error('Unsupported cipher: ' + algorithm);
	}

	this.isGcm = algorithm.indexOf('gcm') > -1;
	this.isEcb = algorithm.indexOf('ecb') > -1;

	// Initialize cipher
	if (this.isEcb) {
		this.cipher = this.cipherInfo.fn(this.key);
	} else {
		this.cipher = this.cipherInfo.fn(this.key, this.iv);
	}

	this.decrypted = [];
	this.authTag = null;
}

Decipheriv.prototype.update = function (data) {
	const dataBytes = toUint8Array(data);
	const result = this.cipher.decrypt(dataBytes);
	this.decrypted.push(result);
	return toBuffer(result);
};

Decipheriv.prototype['final'] = function () {
	const result = Buffer.concat(this.decrypted.map(toBuffer));
	return result;
};

Decipheriv.prototype.setAuthTag = function (tag) {
	if (!this.isGcm) {
		throw new Error('setAuthTag only supported for GCM mode');
	}
	this.authTag = toUint8Array(tag);
};

// Factory functions
function createCipher(algorithm, password) {
	return new Cipher(algorithm, password);
}

function createCipheriv(algorithm, key, iv) {
	return new Cipheriv(algorithm, key, iv);
}

function createDecipher(algorithm, password) {
	return new Decipher(algorithm, password);
}

function createDecipheriv(algorithm, key, iv) {
	return new Decipheriv(algorithm, key, iv);
}

function getCiphers() {
	return Object.keys(cipherMap);
}

module.exports = {
	Cipher: Cipher,
	createCipher: createCipher,
	Cipheriv: Cipheriv,
	createCipheriv: createCipheriv,
	Decipher: Decipher,
	createDecipher: createDecipher,
	Decipheriv: Decipheriv,
	createDecipheriv: createDecipheriv,
	getCiphers: getCiphers,
	listCiphers: getCiphers
};
