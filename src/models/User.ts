/** @format */
import {
	Collection,
	CreateUserRequest,
	User as OktaUser,
	UserFactor,
} from '@okta/okta-sdk-nodejs';
import { Resource } from '.';
import { OktaClient, RedisClient } from '../utils';

const { dbGet } = new RedisClient();

export interface User {
	readonly _embedded: { [name: string]: unknown };
	_links?: { [name: string]: unknown };
	readonly activated: string;
	readonly created: string;
	readonly id: string;
	readonly lastLogin: string;
	readonly lastUpdated: string;
	readonly passwordChanged: string;
	profile: UserProfile;
	readonly status: string;
	readonly statusChanged: string;
	readonly transitioningToStatus: string;
	type: string;
	factors?: Factor[];
}

export class User extends Resource {
	constructor(json: User) {
		super(json);
		if (json?.profile) {
			this.profile = new UserProfile(json.profile);
		}
	}
	async getUser(userId: string) {
		try {
			const { getUser, dbSet } = new RedisClient();
			/* First, see if a user exists in Redis */
			const redisUser = await getUser(userId);

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

			await dbSet(userId, JSON.stringify(mergedUser));

			return mergedUser;
		} catch (error) {
			throw new Error(`unable to fetch user ${error}`);
		}
	}
	async getOktaUser(userId: string) {
		try {
			return await OktaClient.getUser(userId);
		} catch (error) {
			throw new Error(`unable to fetch user ${error}`);
		}
	}
	async createOktaUser(
		profile: Partial<Record<keyof CreateUserRequest, unknown>>
	): Promise<OktaUser> {
		try {
			return await OktaClient.createUser(profile);
		} catch (error) {
			throw new Error(`Unable to create Okta user [${error}]`);
		}
	}
	/* Only returns the WebAuthn factors from Okta */
	async getOktaFactors(userId: string) {
		try {
			let factors: Factor[] = [];

			const oktaUser = await this.getOktaUser(userId);

			const oktaFactors =
				(await oktaUser.listFactors()) as unknown as Collection<Factor>;

			oktaFactors.each(factor => {
				const {
					id,
					factorType,
					created,
					lastUpdated,
					provider,
					status,
					profile,
				} = factor || {};

				if (factorType === 'webauthn') {
					factors.push({
						id,
						factorType,
						created,
						lastUpdated,
						provider,
						status,
						profile,
					});
				}
			});

			return factors;
		} catch (error) {
			throw new Error(`Unable to create Okta user [${error}]`);
		}
	}
}

class UserProfile extends Resource {
	constructor(json: UserProfile) {
		super(json);
	}
}

interface UserProfile {
	city?: string;
	costCenter?: string;
	countryCode?: string;
	department?: string;
	displayName?: string;
	division?: string;
	email: string;
	employeeNumber?: string;
	firstName?: string;
	honorificPrefix?: string;
	honorificSuffix?: string;
	lastName: string;
	locale?: string;
	login: string;
	manager?: string;
	managerId?: string;
	middleName?: string;
	mobilePhone?: string;
	nickName?: string;
	organization?: string;
	postalAddress?: string;
	preferredLanguage?: string;
	primaryPhone?: string;
	profileUrl?: string;
	secondEmail?: string;
	state?: string;
	streetAddress?: string;
	timezone?: string;
	title?: string;
	userType?: string;
	zipCode?: string;
}

interface Factor {
	id: string;
	factorType: 'webauthn';
	vendorName?: 'FIDO';
	created: Date;
	lastUpdated: Date;
	provider: 'FIDO';
	status:
		| 'NOT_SETUP'
		| 'PENDING_ACTIVATION'
		| 'ENROLLED'
		| 'ACTIVE'
		| 'INACTIVE'
		| 'EXPIRED';
	profile: {
		credentialId: string;
		appId?: string;
		authenticatorName?: string;
	};
}
