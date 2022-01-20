/** @format */

import { strict as assert } from 'assert';

export const ok = (test: any, message?: string): void =>
	assert.ok(test, message ?? 'Check failed.');

export const equals = (actual: any, expected: any, message?: string): void => {
	let error = `Expected value ${expected} does not equal received value ${actual}.`;

	if (message) {
		error = `${error} ${message}`;
	}

	return assert.equal(actual, expected, message);
};

export const notEquals = (
	actual: any,
	expected: any,
	message?: string
): void => {
	let error = `Expected value of ${expected} equals received value of ${actual}.`;

	if (message) {
		error = `${error} ${message}`;
	}

	return assert.notEqual(actual, expected, message);
};
