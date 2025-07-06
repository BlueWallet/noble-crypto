'use strict';

const { DH, DHGroups } = require('micro-rsa-dsa-dh/dh.js');
const Buffer = require('safe-buffer').Buffer;

// Convert bigint to Buffer
function bigintToBuffer(bigint) {
	const hex = bigint.toString(16);
	// Ensure even length by padding with leading zero if needed
	const paddedHex = hex.length % 2 === 0 ? hex : '0' + hex;
	return Buffer.from(paddedHex, 'hex');
}

// Convert Buffer to bigint
function bufferToBigint(buffer) {
	return BigInt('0x' + buffer.toString('hex'));
}

// DiffieHellman class that wraps micro-rsa-dsa-dh
class DiffieHellman {
	constructor(prime, generator, keyLength) {
		if (typeof prime === 'string' && DHGroups[prime]) {
			// Using predefined group - test if micro-rsa-dsa-dh works correctly
			try {
				const dh = DH(prime);
				const priv1 = dh.randomPrivateKey();
				const pub1 = dh.getPublicKey(priv1);
				const priv2 = dh.randomPrivateKey();
				const pub2 = dh.getPublicKey(priv2);
				
				// Test if shared secret computation works correctly
				const secret1 = dh.getSharedSecret(priv1, pub2);
				const secret2 = dh.getSharedSecret(priv2, pub1);
				
				// If secrets don't match, micro-rsa-dsa-dh is broken for this group
				if (secret1 !== secret2) {
					throw new Error('micro-rsa-dsa-dh shared secret computation is broken for this group');
				}
				
				// Test key size validation
				const expectedPrimeLen = Math.ceil(DHGroups[prime].p.toString(16).length / 2);
				const actualPubLen = Math.ceil(pub1.toString(16).length / 2);
				
				// If the generated public key is too small, fallback to Node.js
				if (actualPubLen < expectedPrimeLen / 2) {
					throw new Error('micro-rsa-dsa-dh generated invalid keys for this group');
				}
				
				// If we get here, micro-rsa-dsa-dh works correctly for this group
				this.dh = dh;
				this.group = prime;
			} catch (error) {
				// Fallback to Node.js diffie-hellman for this group
				const originalDH = require('diffie-hellman');
				const fallbackInstance = originalDH.getDiffieHellman(prime);
				// Copy all properties and methods from the fallback instance
				Object.setPrototypeOf(this, Object.getPrototypeOf(fallbackInstance));
				Object.assign(this, fallbackInstance);
				return;
			}
		} else if (typeof prime === 'number') {
			// Key length specified - we'll need to fallback to diffie-hellman
			// as micro-rsa-dsa-dh doesn't support custom key lengths
			throw new Error('Custom key lengths not supported by micro-rsa-dsa-dh, falling back to diffie-hellman');
		} else {
			// Custom prime/generator - fallback to diffie-hellman
			throw new Error('Custom primes not supported by micro-rsa-dsa-dh, falling back to diffie-hellman');
		}
		
		this.privateKey = null;
		this.publicKey = null;
	}

	generateKeys(encoding) {
		this.privateKey = this.dh.randomPrivateKey();
		this.publicKey = this.dh.getPublicKey(this.privateKey);
		
		if (encoding) {
			return this.getPublicKey(encoding);
		}
		return this.publicKey;
	}

	computeSecret(otherPublicKey, inputEncoding, outputEncoding) {
		if (!this.privateKey) {
			throw new Error('Keys not generated. Call generateKeys() first.');
		}

		let otherKeyBuf;
		if (Buffer.isBuffer(otherPublicKey)) {
			otherKeyBuf = otherPublicKey;
		} else if (typeof otherPublicKey === 'string') {
			otherKeyBuf = Buffer.from(otherPublicKey, inputEncoding || 'hex');
		} else if (otherPublicKey instanceof Uint8Array) {
			otherKeyBuf = Buffer.from(otherPublicKey);
		} else {
			throw new Error('Invalid public key type for computeSecret');
		}

		const sharedSecret = this.dh.getSharedSecret(this.privateKey, otherKeyBuf);
		let result = bigintToBuffer(sharedSecret);

		// Normalize to prime length (Node.js behavior)
		let primeLen = 0;
		if (this.group && DHGroups[this.group]) {
			primeLen = Math.ceil(DHGroups[this.group].p.toString(16).length / 2);
		} else {
			// fallback: get prime length from getPrime()
			primeLen = this.getPrime().length;
		}
		if (result.length < primeLen) {
			const pad = Buffer.alloc(primeLen - result.length, 0);
			result = Buffer.concat([pad, result]);
		}

		if (outputEncoding) {
			return result.toString(outputEncoding);
		}
		return result;
	}

	getPrime(encoding) {
		if (this.group && DHGroups[this.group]) {
			const prime = DHGroups[this.group].p;
			const result = bigintToBuffer(prime);
			if (encoding) {
				return result.toString(encoding);
			}
			return result;
		}
		// Fallback to original diffie-hellman package for custom primes
		const originalDH = require('diffie-hellman');
		const fallbackInstance = originalDH.getDiffieHellman(this.group || 'modp1');
		return fallbackInstance.getPrime(encoding);
	}

	getGenerator(encoding) {
		if (this.group && DHGroups[this.group]) {
			const generator = DHGroups[this.group].g;
			const result = bigintToBuffer(generator);
			if (encoding) {
				return result.toString(encoding);
			}
			return result;
		}
		// Fallback to original diffie-hellman package for custom generators
		const originalDH = require('diffie-hellman');
		const fallbackInstance = originalDH.getDiffieHellman(this.group || 'modp1');
		return fallbackInstance.getGenerator(encoding);
	}

	getPublicKey(encoding) {
		if (!this.publicKey) {
			throw new Error('Keys not generated. Call generateKeys() first.');
		}
		
		const result = bigintToBuffer(this.publicKey);
		if (encoding) {
			return result.toString(encoding);
		}
		return result;
	}

	getPrivateKey(encoding) {
		if (!this.privateKey) {
			throw new Error('Keys not generated. Call generateKeys() first.');
		}
		
		const result = bigintToBuffer(this.privateKey);
		if (encoding) {
			return result.toString(encoding);
		}
		return result;
	}
}

// Factory functions that match the diffie-hellman API
function createDiffieHellman(prime, generator, keyLength) {
	try {
		return new DiffieHellman(prime, generator, keyLength);
	} catch (error) {
		// Fallback to original diffie-hellman package
		const originalDH = require('diffie-hellman');
		return originalDH.createDiffieHellman(prime, generator, keyLength);
	}
}

function getDiffieHellman(groupName) {
	try {
		return new DiffieHellman(groupName);
	} catch (error) {
		// Fallback to original diffie-hellman package
		const originalDH = require('diffie-hellman');
		return originalDH.getDiffieHellman(groupName);
	}
}

function createDiffieHellmanGroup(groupName) {
	try {
		return new DiffieHellman(groupName);
	} catch (error) {
		// Fallback to original diffie-hellman package
		const originalDH = require('diffie-hellman');
		return originalDH.createDiffieHellmanGroup(groupName);
	}
}

// Export the same API as diffie-hellman
module.exports = {
	DiffieHellman,
	createDiffieHellman,
	getDiffieHellman,
	createDiffieHellmanGroup,
	DiffieHellmanGroup: createDiffieHellmanGroup
}; 