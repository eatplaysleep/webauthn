/** @format */

import { CryptoUtil } from '../utils';
import crypto from 'crypto';

const { toBase64Url, toArrayBuffer } = new CryptoUtil();

export class Challenge {
	async generate(length: number = 32, buffer: boolean = true) {
		try {
			const challengeBuffer = crypto.randomBytes(length);

			if (!buffer) {
				return await toBase64Url(challengeBuffer);
			} else {
				return toArrayBuffer(challengeBuffer);
			}
		} catch (error) {
			throw new Error(`unable to generate challenge [${error}]`);
		}
	}
}
