'use strict';

const rsa = require('micro-rsa-dsa-dh/rsa.js');
const parseASN1 = require('parse-asn1');
const { p256 } = require('@noble/curves/p256');
const { secp256k1 } = require('@noble/curves/secp256k1');
const { sha1 } = require('@noble/hashes/sha1');
const { sha256 } = require('@noble/hashes/sha2');

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

// Use parse-asn1 to parse keys reliably
function parseKey(keyData) {
	try {
		const parsed = parseASN1(keyData);
		
		// Check if it's an RSA key (has modulus)
		if (parsed.modulus) {
			// RSA key
			const n = parsed.modulus;
			const e = parsed.publicExponent;
			const d = parsed.privateExponent;
			
			if (!n) {
				throw new Error('Missing modulus');
			}
			if (!e) {
				throw new Error('Missing exponent');
			}
			
			// Convert to BigInt format expected by micro-rsa-dsa-dh
			const nBig = BigInt('0x' + n.toString('hex'));
			const eBig = BigInt('0x' + e.toString('hex'));
			
			if (d) {
				// Private key
				const dBig = BigInt('0x' + d.toString('hex'));
				return {
					type: 'rsa',
					n: nBig, e: eBig, d: dBig
				};
			}
			// Public key
			return { 
				type: 'rsa',
				n: nBig, e: eBig 
			};
		} else if (parsed.privateKey && parsed.curve) {
			// EC private key - convert OID to curve name
			let curveName = 'prime256v1'; // default
			if (Array.isArray(parsed.curve)) {
				// OID [1, 3, 132, 0, 10] = secp256k1
				const oidStr = parsed.curve.join('.');
				if (oidStr === '1.3.132.0.10') {
					curveName = 'secp256k1';
				} else if (oidStr === '1.2.840.10045.3.1.7') {
					curveName = 'prime256v1';
				}
			}

			return {
				type: 'ec',
				privateKey: parsed.privateKey,
				curve: curveName
			};
		} else if (parsed.type === 'ec' && parsed.data && parsed.data.subjectPublicKey) {
			// EC public key with full structure
			let curveName = 'prime256v1'; // default
			if (parsed.data.algorithm && parsed.data.algorithm.curve && Array.isArray(parsed.data.algorithm.curve)) {
				const oidStr = parsed.data.algorithm.curve.join('.');
				if (oidStr === '1.3.132.0.10') {
					curveName = 'secp256k1';
				} else if (oidStr === '1.2.840.10045.3.1.7') {
					curveName = 'prime256v1';
				}
			}

			return {
				type: 'ec',
				publicKey: parsed.data.subjectPublicKey.data,
				curve: curveName
			};
		} else {
			throw new Error('Unknown key type');
		}
	} catch (error) {
		throw new Error('Failed to parse key: ' + error.message);
	}
}

// Map algorithm names to signers and hash functions
const algorithms = {
	// RSA algorithms
	'RSA-SHA1': { type: 'rsa', signer: rsa.PKCS1_SHA1 },
	'RSA-SHA256': { type: 'rsa', signer: rsa.PKCS1_SHA256 },
	'RSA-SHA384': { type: 'rsa', signer: rsa.PKCS1_SHA384 },
	'RSA-SHA512': { type: 'rsa', signer: rsa.PKCS1_SHA512 },
	sha1WithRSAEncryption: { type: 'rsa', signer: rsa.PKCS1_SHA1 },
	sha256WithRSAEncryption: { type: 'rsa', signer: rsa.PKCS1_SHA256 },
	
	// EC algorithms (ECDSA)
	'sha1': { type: 'ec', hash: sha1 },
	'sha256': { type: 'ec', hash: sha256 },
	'ECDSA-SHA1': { type: 'ec', hash: sha1 },
	'ECDSA-SHA256': { type: 'ec', hash: sha256 }
};

function Sign(algorithm) {
	this.algorithm = algorithm;
	this.algorithmInfo = algorithms[algorithm];
	if (!this.algorithmInfo) {
		throw new Error('Unsupported algorithm: ' + algorithm);
	}
	this.data = [];
	this.finished = false;
}

Sign.prototype.update = function (data, encoding) {
	if (this.finished) {
		throw new Error('Cannot update after sign has been called');
	}

	let uint8Data;
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
	
	// Parse private key
	let keyData;
	if (typeof privateKey === 'string' || privateKey instanceof Buffer) {
		keyData = parseKey(privateKey);
	} else {
		throw new Error('Unsupported private key format');
	}
	
	let signature;
	
	if (this.algorithmInfo.type === 'rsa') {
		// RSA signing
		if (keyData.type !== 'rsa') {
			throw new Error('RSA algorithm requires RSA key');
		}
		signature = this.algorithmInfo.signer.sign(keyData, concatenated);
	} else if (this.algorithmInfo.type === 'ec') {
		// EC signing
		if (keyData.type !== 'ec') {
			throw new Error('EC algorithm requires EC key');
		}
		
		// Hash the data
		const hash = this.algorithmInfo.hash(concatenated);
		
		// Choose the curve - for now default to p256
		let curve = p256;
		if (keyData.curve === 'secp256k1') {
			curve = secp256k1;
		}

		
		// Convert private key to hex string if it's a Buffer
		let privKeyHex = keyData.privateKey;
		if (Buffer.isBuffer(privKeyHex)) {
			privKeyHex = privKeyHex.toString('hex');
		}
		
		// Sign with the curve
		signature = curve.sign(hash, privKeyHex).toDERRawBytes();
	} else {
		throw new Error('Unknown algorithm type');
	}
	
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
	this.algorithmInfo = algorithms[algorithm];
	if (!this.algorithmInfo) {
		throw new Error('Unsupported algorithm: ' + algorithm);
	}
	this.data = [];
	this.finished = false;
}

Verify.prototype.update = function (data, encoding) {
	if (this.finished) {
		throw new Error('Cannot update after verify has been called');
	}

	let uint8Data;
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
	
	// Parse public key
	let keyData;
	if (typeof publicKey === 'string' || publicKey instanceof Buffer) {
		keyData = parseKey(publicKey);
	} else {
		throw new Error('Unsupported public key format');
	}
	
	// Convert signature to Uint8Array
	let sigData;
	if (encoding === 'hex') {
		sigData = new Uint8Array(Buffer.from(signature, 'hex'));
	} else if (encoding === 'base64') {
		sigData = new Uint8Array(Buffer.from(signature, 'base64'));
	} else {
		sigData = toUint8Array(signature);
	}
	
	let result;
	
	if (this.algorithmInfo.type === 'rsa') {
		// RSA verification
		if (keyData.type !== 'rsa') {
			throw new Error('RSA algorithm requires RSA key');
		}
		result = this.algorithmInfo.signer.verify(keyData, concatenated, sigData);
	} else if (this.algorithmInfo.type === 'ec') {
		// EC verification
		if (keyData.type !== 'ec') {
			throw new Error('EC algorithm requires EC key');
		}
		
		// Hash the data
		const hash = this.algorithmInfo.hash(concatenated);
		
		// Choose the curve - for now default to p256
		let curve = p256;
		if (keyData.curve === 'secp256k1') {
			curve = secp256k1;
		}
		
		// Convert public key to hex string if it's a Buffer
		let pubKeyHex = keyData.publicKey;
		if (Buffer.isBuffer(pubKeyHex)) {
			pubKeyHex = pubKeyHex.toString('hex');
		} else if (pubKeyHex instanceof Uint8Array) {
			pubKeyHex = Buffer.from(pubKeyHex).toString('hex');
		}
		
		// Verify with the curve
		try {
			const sig = curve.Signature.fromDER(sigData);
			
			// Try verification with original signature
			let verified = curve.verify(sig, hash, pubKeyHex);
			
			// If verification fails, try signature malleability fix
			// In ECDSA, both (r, s) and (r, n - s) are valid signatures
			if (!verified) {
				try {
					// Create alternate signature with s' = n - s
					const n = curve.CURVE.n;
					const altS = n - sig.s;
					const altSig = new curve.Signature(sig.r, altS);
					verified = curve.verify(altSig, hash, pubKeyHex);
				} catch (e) {
					// If that also fails, the signature is genuinely invalid
					verified = false;
				}
			}
			
			result = verified;
		} catch (error) {
			result = false;
		}
	} else {
		throw new Error('Unknown algorithm type');
	}
	
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
