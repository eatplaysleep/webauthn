/** @format */

import base64url from 'base64url';
import crypto from 'crypto';

export class CryptoUtil {
	async hash(type: string, data: Buffer | string) {
		try {
			return crypto.createHash(type).update(data).digest();
		} catch (error) {
			throw new Error(`unable to create hash [${error}]`);
		}
	}

	async sha1(data: Buffer | string) {
		try {
			return await this.hash('sha1', data);
		} catch (error) {
			throw new Error(`unable to create sha1 hash [${error}]`);
		}
	}

	async sha256(data: Buffer | string) {
		try {
			return await this.hash('sha256', data);
		} catch (error) {
			throw new Error(`unable to create sha256 hash [${error}]`);
		}
	}
	/*
	Converts a buffer to base64url
	*/
	async toBase64Url(value: string | Buffer) {
		try {
			return base64url(value);
		} catch (error) {
			throw new Error(`unable to convert buffer => base64url [${error}]`);
		}
	}
	/*
	Converts buffer => base64url => ArrayBuffer.
	*/
	async toArrayBuffer(value: string | Buffer) {
		try {
			return Buffer.from(await this.toBase64Url(value));
		} catch (error) {
			throw new Error(`unable to convert base64url => buffer [${error}]`);
		}
	}
	/*
	Converts base64url => utf8 string
	*/
	async fromBase64url(string: string) {
		try {
			return base64url.decode(string);
		} catch (error) {
			throw new Error(`unable to convert base64url => buffer [${error}]`);
		}
	}
	/*
	Converts ArrayBuffer => base64url => utf8 string
	*/
	async fromArrayBuffer(arrayBuffer: ArrayBuffer) {
		try {
			const base64urlString = Buffer.from(arrayBuffer).toString('utf8');
			return this.fromBase64url(base64urlString);
		} catch (error) {
			throw new Error(`unable to convert ArrayBuffer => string [${error}]`);
		}
	}
	/*
	Converts a base64url encoded buffer into a utf8 string
	*/
	// async fromBuffer(buffer: Buffer) {
	// 	try {

	// 		const base64UrlString = await this.toBase64Url(buffer);

	// 		return base64url.decode(base64UrlString);
	// 	} catch (error) {
	// 		throw new Error(`unable to convert base64url => buffer [${error}]`);
	// 	}
	// }
}
