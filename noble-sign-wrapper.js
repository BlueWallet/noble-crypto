'use strict';

/* global Uint8Array */

var rsa = require('micro-rsa-dsa-dh/rsa.js');
var parseASN1 = require('parse-asn1');

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

// Use parse-asn1 to parse RSA keys reliably
function parseRSAKey(keyData) {
	try {
		var parsed = parseASN1(keyData);

		// Extract the raw values we need
		var n = parsed.modulus;
		var e = parsed.publicExponent;
		var d = parsed.privateExponent;

		if (!n) {
			throw new Error('Missing modulus');
		}
		if (!e) {
			throw new Error('Missing exponent');
		}

		// Convert to BigInt format expected by micro-rsa-dsa-dh
		var nBig = BigInt('0x' + n.toString('hex'));
		var eBig = BigInt('0x' + e.toString('hex'));

		if (d) {
			// Private key
			var dBig = BigInt('0x' + d.toString('hex'));
			return {
				n: nBig, e: eBig, d: dBig
			};
		}
		// Public key
		return { n: nBig, e: eBig };

	} catch (error) {
		throw new Error('Failed to parse RSA key: ' + error.message);
	}
}

// Map algorithm names to micro-rsa-dsa-dh signers
var signers = {
	'RSA-SHA1': rsa.PKCS1_SHA1,
	'RSA-SHA256': rsa.PKCS1_SHA256,
	'RSA-SHA384': rsa.PKCS1_SHA384,
	'RSA-SHA512': rsa.PKCS1_SHA512,
	sha1WithRSAEncryption: rsa.PKCS1_SHA1,
	sha256WithRSAEncryption: rsa.PKCS1_SHA256
};

function Sign(algorithm) {
	this.algorithm = algorithm;
	this.signer = signers[algorithm];
	if (!this.signer) {
		throw new Error('Unsupported algorithm: ' + algorithm);
	}
	this.data = [];
	this.finished = false;
}

Sign.prototype.update = function (data, encoding) {
	if (this.finished) {
		throw new Error('Cannot update after sign has been called');
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
	if (this.finished) {
		throw new Error('Sign already called');
	}

	// Concatenate all data
	var totalLength = 0;
	for (var i = 0; i < this.data.length; i++) {
		totalLength += this.data[i].length;
	}
	var concatenated = new Uint8Array(totalLength);
	var offset = 0;
	for (var j = 0; j < this.data.length; j++) {
		var chunk = this.data[j];
		concatenated.set(chunk, offset);
		offset += chunk.length;
	}

	// Parse private key
	var keyData;
	if (typeof privateKey === 'string' || privateKey instanceof Buffer) {
		keyData = parseRSAKey(privateKey);
	} else {
		throw new Error('Unsupported private key format');
	}

	// Sign the data
	var signature = this.signer.sign(keyData, concatenated);
	this.finished = true;

	// Return signature in requested format
	if (encoding === 'hex') {
		return Buffer.from(signature).toString('hex');
	} else if (encoding === 'base64') {
		return Buffer.from(signature).toString('base64');
	}
	return Buffer.from(signature);

};

function Verify(algorithm) {
	this.algorithm = algorithm;
	this.signer = signers[algorithm];
	if (!this.signer) {
		throw new Error('Unsupported algorithm: ' + algorithm);
	}
	this.data = [];
	this.finished = false;
}

Verify.prototype.update = function (data, encoding) {
	if (this.finished) {
		throw new Error('Cannot update after verify has been called');
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
	if (this.finished) {
		throw new Error('Verify already called');
	}

	// Concatenate all data
	var totalLength = 0;
	for (var i = 0; i < this.data.length; i++) {
		totalLength += this.data[i].length;
	}
	var concatenated = new Uint8Array(totalLength);
	var offset = 0;
	for (var j = 0; j < this.data.length; j++) {
		var chunk = this.data[j];
		concatenated.set(chunk, offset);
		offset += chunk.length;
	}

	// Parse public key
	var keyData;
	if (typeof publicKey === 'string' || publicKey instanceof Buffer) {
		keyData = parseRSAKey(publicKey);
	} else {
		throw new Error('Unsupported public key format');
	}

	// Convert signature to Uint8Array
	var sigData;
	if (encoding === 'hex') {
		sigData = new Uint8Array(Buffer.from(signature, 'hex'));
	} else if (encoding === 'base64') {
		sigData = new Uint8Array(Buffer.from(signature, 'base64'));
	} else {
		sigData = toUint8Array(signature);
	}

	// Verify the signature
	var result = this.signer.verify(keyData, concatenated, sigData);
	this.finished = true;

	return result;
};

function createSign(algorithm) {
	return new Sign(algorithm);
}

function createVerify(algorithm) {
	return new Verify(algorithm);
}

module.exports = {
	createSign: createSign,
	Sign: Sign,
	createVerify: createVerify,
	Verify: Verify
};
