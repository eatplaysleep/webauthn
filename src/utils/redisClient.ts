/** @format */

import Redis = require('ioredis');
import { CreateUserRequest, User as OktaUser } from '@okta/okta-sdk-nodejs';
import { PublicKeyCreateOptions, User } from '../models';
import { CryptoUtil, OktaClient } from '.';

const { fromBase64url, toBase64Url } = new CryptoUtil();

const REDIS_URL = process.env.REDIS_URL;

const redis = new Redis(REDIS_URL);

export class RedisClient {
	async dbGet(key: string) {
		try {
			/* fetch the data */
			const result = (await redis.get(key)) as string;

			/* base64url => utf8 => JSON */
			const data: any = JSON.parse(await fromBase64url(result));

			return data;
		} catch (error: any) {
			throw new Error(error);
		}
	}

	async getUser(userId: string) {
		try {
			/* First, see if a user exists in Redis */
			const redisUser = await this.dbGet(userId);

			/* Then, fetch the Okta user */
			let oktaUser = (await OktaClient.getUser(userId)) as unknown as User;

			delete oktaUser._links;

			/* Then, synchronize the Redis User */
			const mergedUser = {
				...redisUser,
				...oktaUser,
				factors: {
					...redisUser.factors,
				},
			};

			await this.dbSet(userId, JSON.stringify(mergedUser));

			return new User(mergedUser);
		} catch (error) {
			throw new Error(`unable to fetch user ${error}`);
		}
	}

	async createUser(
		profile: Partial<Record<keyof CreateUserRequest, unknown>>
	): Promise<User> {
		try {
			/* First, create the user in Okta */
			let oktaUser = (await OktaClient.createUser(profile)) as unknown as User;

			delete oktaUser._links;

			/* Then, create the user in Redis */

			await this.dbSet(oktaUser.id, JSON.stringify(oktaUser));

			return new User(oktaUser);
		} catch (error) {
			throw new Error(`unable to fetch user ${error}`);
		}
	}

	async dbGetPubCred(key: string) {
		try {
			/* fetch the data */
			const result = (await redis.get(key)) as string;

			/* base64url => utf8 => JSON */
			const data: PublicKeyCreateOptions | PublicKeyCredentialCreationOptions =
				JSON.parse(await fromBase64url(result));

			return data;
		} catch (error: any) {
			throw new Error(error);
		}
	}

	async dbSet(key: string, data: string, expire: boolean = false) {
		try {
			let result: 'OK' | null;
			/// base64 encode the data for simplicity
			const encodedData = await toBase64Url(data);

			/// persist response to redis
			if (expire) {
				result = await redis.set(key, encodedData, 'EX', 300);
			} else {
				result = await redis.set(key, encodedData);
			}

			if (result === 'OK') {
				return true;
			} else throw 'Unable to store data!';
		} catch (error: any) {
			throw new Error(error);
		}
	}
}
