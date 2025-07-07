'use strict';

const { OAEP, mgf1 } = require('micro-rsa-dsa-dh/rsa.js');
const { sha1 } = require('@noble/hashes/sha1');
const parseAsn1 = require('parse-asn1');

// Helper function to extract RSA components from PEM using parse-asn1
function parseKeyComponents(keyData) {
	if (Buffer.isBuffer(keyData)) {
		keyData = keyData.toString('utf8');
	}
	
	try {
		// Use parse-asn1 to parse the key
		const parsed = parseAsn1(keyData);
		
		// Convert BN objects to BigInt
		const n = bnToBigInt(parsed.modulus);
		const e = bnToBigInt(parsed.publicExponent);
		
		// For private keys, also get the private exponent
		let d = null;
		if (parsed.privateExponent) {
			d = bnToBigInt(parsed.privateExponent);
		}
		
		return { n, e, d };
	} catch (error) {
		throw new Error(`Failed to parse key: ${error.message}`);
	}
}

// Helper function to convert BN objects to BigInt
function bnToBigInt(bn) {
	if (!bn) return null;
	// Convert BN to hex string, then to BigInt
	const hex = bn.toString(16);
	return BigInt('0x' + hex);
}



// Helper function to prepare key object
function prepareKey(key) {
	if (typeof key === 'object' && !Buffer.isBuffer(key)) {
		// If key is an options object
		const keyData = key.key || key;
		const parsed = parseKeyComponents(keyData);
		return { ...parsed, options: key };
	} else {
		// If key is just the key material
		return parseKeyComponents(key);
	}
}

function publicEncrypt(key, buffer) {
	try {
		const parsedKey = prepareKey(key);
		
		if (!parsedKey.n || !parsedKey.e) {
			throw new Error('Invalid public key');
		}
		
		const publicKey = { n: parsedKey.n, e: parsedKey.e };
		
		// Use OAEP padding by default (for compatibility with public-encrypt module)
		// Node.js uses SHA-1 by default for OAEP
		const oaep = OAEP(sha1, mgf1(sha1));
		const encrypted = oaep.encrypt(publicKey, new Uint8Array(buffer));
		
		return Buffer.from(encrypted);
	} catch (error) {
		throw new Error(`Public encryption failed: ${error.message}`);
	}
}

function privateDecrypt(key, buffer) {
	try {
		const parsedKey = prepareKey(key);
		
		if (!parsedKey.n || !parsedKey.d) {
			throw new Error('Invalid private key');
		}
		
		const privateKey = { n: parsedKey.n, d: parsedKey.d };
		
		// Use OAEP padding by default (for compatibility with public-encrypt module)
		// Node.js uses SHA-1 by default for OAEP
		const oaep = OAEP(sha1, mgf1(sha1));
		const decrypted = oaep.decrypt(privateKey, new Uint8Array(buffer));
		
		return Buffer.from(decrypted);
	} catch (error) {
		throw new Error(`Private decryption failed: ${error.message}`);
	}
}

function privateEncrypt(key, buffer) {
	try {
		const parsedKey = prepareKey(key);
		
		if (!parsedKey.n || !parsedKey.d) {
			throw new Error('Invalid private key');
		}
		
		const privateKey = { n: parsedKey.n, d: parsedKey.d };
		
		// We'll implement this using the low-level primitives
		const { _TEST } = require('micro-rsa-dsa-dh/rsa.js');
		const { OS2IP, I2OSP } = require('micro-rsa-dsa-dh/utils.js');
		
		// Pad the message using PKCS1 v1.5 padding for signatures
		const k = Math.ceil(parsedKey.n.toString(16).length / 2);
		const mLen = buffer.length;
		if (mLen > k - 11) {
			throw new Error('message too long');
		}
		
		// Create PKCS1 v1.5 padding for signature (type 1)
		const psLen = k - mLen - 3;
		const PS = new Uint8Array(psLen).fill(0xff);
		const EM = new Uint8Array([0x00, 0x01, ...PS, 0x00, ...buffer]);
		
		const m = OS2IP(EM);
		const s = _TEST.RSASP1(privateKey, m);
		const encrypted = I2OSP(s, k);
		
		return Buffer.from(encrypted);
	} catch (error) {
		throw new Error(`Private encryption failed: ${error.message}`);
	}
}

function publicDecrypt(key, buffer) {
	try {
		const parsedKey = prepareKey(key);
		
		if (!parsedKey.n || !parsedKey.e) {
			throw new Error('Invalid public key');
		}
		
		const publicKey = { n: parsedKey.n, e: parsedKey.e };
		
		// For public decrypt (signature verification), we need to use the public key
		const { _TEST } = require('micro-rsa-dsa-dh/rsa.js');
		const { OS2IP, I2OSP } = require('micro-rsa-dsa-dh/utils.js');
		
		const k = Math.ceil(parsedKey.n.toString(16).length / 2);
		if (buffer.length !== k) {
			throw new Error('incorrect signature length');
		}
		
		const s = OS2IP(new Uint8Array(buffer));
		const m = _TEST.RSAEP(publicKey, s);
		
		if (m === false) {
			throw new Error('signature verification failed');
		}
		
		const EM = I2OSP(m, k);
		
		// Verify PKCS1 v1.5 padding for signature (type 1)
		if (EM[0] !== 0x00 || EM[1] !== 0x01) {
			throw new Error('invalid signature padding');
		}
		
		// Find the 0x00 separator
		let sepIdx = -1;
		for (let i = 2; i < EM.length; i++) {
			if (EM[i] === 0x00) {
				sepIdx = i;
				break;
			} else if (EM[i] !== 0xff) {
				throw new Error('invalid signature padding');
			}
		}
		
		if (sepIdx === -1 || sepIdx < 10) {
			throw new Error('invalid signature padding');
		}
		
		return Buffer.from(EM.slice(sepIdx + 1));
	} catch (error) {
		throw new Error(`Public decryption failed: ${error.message}`);
	}
}

module.exports = {
	publicEncrypt,
	privateDecrypt,
	privateEncrypt,
	publicDecrypt
}; 