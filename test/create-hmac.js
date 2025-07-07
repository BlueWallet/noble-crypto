'use strict';

const test = require('tape');
const satisfies = require('semver').satisfies;

const algorithms = ['sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'md5', 'rmd160'];
const vectors = require('hash-test-vectors/hmac');

function testLib(name, createHmac) {
	algorithms.forEach(function (alg) {
		const isUnsupported = satisfies(process.version, '^17') && (
			alg === 'rmd160'
			|| alg === 'hmac(rmd160)'
		);
		test(
			name + ' hmac(' + alg + ')',
			{ skip: isUnsupported && 'this node version does not support ' + alg },
			function (t) {
				vectors.forEach(function (input) {
					let output = createHmac(alg, new Buffer(input.key, 'hex'))
						.update(input.data, 'hex').digest();

					output = input.truncate ? output.slice(0, input.truncate) : output;
					output = output.toString('hex');
					t.equal(output, input[alg]);
				});

				t.end();
			}
		);

		test(
			'hmac(' + alg + ')',
			{ skip: isUnsupported && 'this node version does not support ' + alg },
			function (t) {
				vectors.forEach(function (input) {
					const hmac = createHmac(alg, new Buffer(input.key, 'hex'));

					hmac.end(input.data, 'hex');
					let output = hmac.read();

					output = input.truncate ? output.slice(0, input.truncate) : output;
					output = output.toString('hex');
					t.equal(output, input[alg]);
				});

				t.end();
			}
		);
	});
}

testLib('createHmac in crypto-browserify', require('../').createHmac);
testLib('create-hmac/browser', require('create-hmac/browser'));
