/** @format */

import crypto from 'crypto';

import base64url from 'base64url';
import * as uuid from 'uuid-parse';
import { Client } from '@okta/okta-sdk-nodejs';
import { ulid } from 'ulid';
import CBOR = require('cbor');
import * as EmailValidator from 'email-validator';

import {
	Challenge,
	CredentialType,
	ECJwk,
	FactorType,
	isTPMAttestation,
	isPackedAttestation,
	isAndroidKeyAttestation,
	isAndroidSafetyNetAttestation,
	isFIDOU2FAttestation,
	isNoneAttestation,
	ParsedAttestedCredentialData,
	ParsedAuthenticatorData,
	ProviderMap,
	PublicKeyCredential,
	PublicKeyCredentialCreateResponse,
	PublicKeyCreateOptions,
	RSAJwk,
	User,
	TPMVerify,
	TPMStmt,
	TokenBindingStatus,
} from './models';

import {
	equals,
	ok,
	OktaClient,
	ORG_URL,
	RedisClient,
	CryptoUtil,
} from './utils';
// import { CryptoUtil } from './utils';

const { sha256, fromArrayBuffer, toArrayBuffer } = new CryptoUtil();
const { dbGet, dbSet, getUser, createUser } = new RedisClient();

const RP_ID = process.env.RP_ID;

// TODO find a better home for stray enums

const credentialTypeMap = {
	'public-key': CredentialType.PUBLIC_KEY,
	[CredentialType.PUBLIC_KEY]: 'public-key',
};

const tokenBindingStatusMap = {
	present: TokenBindingStatus.PRESENT,
	supported: TokenBindingStatus.SUPPORTED,
};

// TODO is this in use?
const coseToJwk = (cose: any): ECJwk | RSAJwk => {
	try {
		const publicKeyCbor = CBOR.decodeFirstSync(cose);
		// Determine which encryption method was used to create the public key
		if (publicKeyCbor.get(3) === -7) {
			return {
				kty: 'EC',
				crv: 'P-256',
				x: publicKeyCbor.get(-2).toString('base64'),
				y: publicKeyCbor.get(-3).toString('base64'),
			};
		} else if (publicKeyCbor.get(3) === -257) {
			return {
				kty: 'RSA',
				n: publicKeyCbor.get(-1).toString('base64'),
				e: publicKeyCbor.get(-2).toString('base64'),
			};
		} else {
			throw new Error('Unknown public key algorithm');
		}
	} catch (error) {
		throw error;
	}
};

interface PotentialUser {
	displayName?: string;
	login: string;
	email: string;
}

const isValidEmail = async (email: string) => {
	try {
		return EmailValidator.validate(email);
	} catch (error) {
		throw new Error(
			`Unable to verify if string is an email address [${error}]`
		);
	}
};

class Register {
	async generateUserCreateOptions(
		user: PublicKeyCredentialUserEntity | string
	): Promise<PublicKeyCredentialUserEntity> {
		try {
			let userId: string,
				oktaUserId: string,
				oktaDisplayName: string | undefined,
				oktaLogin: string | undefined,
				oktaFirstName: string | undefined,
				oktaLastName: string | undefined,
				potentialUser: PotentialUser | any = {},
				response: any,
				isEmail: boolean = false,
				id: BufferSource,
				displayName: string,
				name: string;

			if (typeof user !== 'string') {
				({ id, displayName, name } = user || {});

				userId = await fromArrayBuffer(id as ArrayBuffer);

				potentialUser = {
					login: name,
					email: name,
				};

				if (displayName) {
					potentialUser.displayName = displayName;
				}
			} else userId = user;

			const oktaUser = await getUser(userId);

			if (oktaUser) {
				oktaUserId = oktaUser?.id;
				oktaDisplayName = oktaUser?.profile?.displayName;
				oktaFirstName = oktaUser?.profile?.firstName;
				oktaLastName = oktaUser?.profile?.lastName;
				oktaLogin = oktaUser?.profile?.login;

				/* Fetch existing webauthn factors */
			} else {
				/*
				There was not a user found in Okta.

				Check if the `id` is a valid email (in format) so we can create a new user in Okta.
				*/
				isEmail = await isValidEmail(userId);

				ok(
					isEmail,
					'`id` is not an email address'
				); /* Unable to continue but error must be vague to avoid user enumeration */

				const newOktaUser = (await createUser(potentialUser)) || {};

				oktaUserId = newOktaUser?.id;
				oktaDisplayName = newOktaUser?.profile?.displayName;
				oktaFirstName = newOktaUser?.profile?.firstName;
				oktaLastName = newOktaUser?.profile?.lastName;
				oktaLogin = newOktaUser?.profile?.login;
			}

			response.id = await toArrayBuffer(oktaUserId);
			response.name = oktaLogin as string;

			if (oktaDisplayName || (oktaFirstName && oktaLastName)) {
				response.displayName =
					(oktaDisplayName as string) ||
					(`${oktaFirstName} ${oktaLastName}` as string);
			}

			return response as PublicKeyCredentialUserEntity;
		} catch (error) {
			throw new Error(`unable to generate 'user' options [${error}]`);
		}
	}

	async generatePublicKeyOptions(
		userId: string,
		options?: PublicKeyCreateOptions
	): Promise<PublicKeyCredentialCreationOptions> {
		try {
			const challengeBuffer = await new Challenge().generate();

			const user = await this.generateUserCreateOptions(options?.user);
			if (options) {
			}
			const authenticatorSelection: AuthenticatorSelectionCriteria = {
				userVerification: 'preferred',
				residentKey: 'required',
				...options?.authenticatorSelection,
			};

			const publicCredParams = [
				{
					type: credentialTypeMap[CredentialType.PUBLIC_KEY],
					alg: -7,
				},
				{
					type: credentialTypeMap[CredentialType.PUBLIC_KEY],
					alg: -257,
				},
			];

			return {
				challenge: challengeBuffer,
				attestation: 'direct',
				authenticatorSelection: authenticatorSelection,
				pubKeyCredParams: publicCredParams,
				rp: {
					name: 'EXPEDIA CUSTOM',
					id: options?.rp?.id,
				},
				user: user,
			} as PublicKeyCredentialCreationOptions;
		} catch (error) {
			throw error;
		}
	}

	async register(
		options: PublicKeyCreateOptions
	): Promise<PublicKeyCredentialCreateResponse> {
		try {
			const publicKeyOptions = await this.generatePublicKeyOptions(options);

			const result: PublicKeyCredentialCreateResponse = {
				factorType: 'WEBAUTHN',
				factorId: ulid(),
				provider: 'FIDO',
				status: 'PENDING_ACTIVATION',
				created: new Date(),
				lastUpdated: new Date(),
				options: publicKeyOptions,
			};

			await dbSet(result.factorId, result);

			return result;
		} catch (error) {
			throw error;
		}
	}

	async verifyClientData(
		c: ParsedClientData,
		ceremony: ClientDataType,
		options: PublicKeyCredentialCreationOptions,
		rpOrigin: string
	) {
		try {
			/*
			Registration Step 7 & Assertion Step 11.

			Verify that the value of C.type is 'webauthn.create'/'webauthn.get'
			*/
			equals(
				c.type as ClientDataType,
				ceremony as ClientDataType,
				'Failed ceremony type test.'
			);
			/*
			Registration Step 8.

			Verify that the value of c.challenge matches options.challenge

			// Assertion Step 8.
			// Verify the value of data.challenge matches the challenge
			// sent to the authenticator in the create() call.
			*/
			equals(
				c.challenge as string,
				options.challenge,
				'Failed challenge test.'
			);
			/*
			Registration Step 9
			& Assertion Step 9.

			Verify that the value of c.origin matches Relying Party's origin.

			We test first against the actual incoming origin and then again against options.rp.id.
			*/
			equals(rpOrigin as string, options.rp.id as string, 'Failed RP Id test.');
			// Check against client origin
			equals(c.origin as string, options.rp.id as string, 'Failed RP Id test.');

			// TODO: remove tokenBinding verification?
			// Verify that the value of data.tokenBinding.status matches the
			// state of the Token Binding for the TLS connection over which the
			// assertion was obtained. If the Token Binding was used on that TLS
			// connection, also verify that the data.tokenBinding.id matches
			// the base64url encoding of the Token Binding ID for the connection.

			// THIS IS HANDLED AS PART OF parseClientData. If Token Binding is
			// present and does not match a types status, it will fail.

			return;
		} catch (error) {
			throw error;
		}
	}

	async parseAuthData(authData: Buffer): Promise<ParsedAuthenticatorData> {
		try {
			let attestedCredentialData: any = {};

			const rpIdHash: Buffer = authData.slice(0, 32),
				flagByte: number = authData[32],
				flags: AuthenticatorFlags = {
					UP: !!(flagByte & 0x01),
					RFU1: !!(flagByte & 0x02),
					UV: !!(flagByte & 0x04),
					RFU2a: !!(flagByte & 0x08),
					RFU2b: !!(flagByte & 0x10),
					RFU2c: !!(flagByte & 0x20),
					AT: !!(flagByte & 0x40),
					ED: !!(flagByte & 0x80),
				},
				signCount: number =
					(authData[33] << 24) |
					(authData[34] << 16) |
					(authData[35] << 8) |
					authData[36];
			//
			// Check if the client sent attestedCredentialData, which is
			// necessary for every new public key.This is indicated by the 6th
			// bit of the flag byte being 1
			if (flags?.AT) {
				// Extract the data from the Buffer.
				// Reference of the structure can be found at
				// https://w3c.github.io/webauthn/#sctn-attested-credential-data
				const AAGUID = uuid.unparse(authData.slice(37, 53)).toUpperCase(),
					credentialIdLength = (authData[53] << 8) | authData[54],
					credentialId = authData.slice(55, 55 + credentialIdLength),
					// Public key is the first CBOR element of the remaining buffer
					publicKeyCoseBuffer = authData.slice(
						55 + credentialIdLength,
						authData.length
					),
					// convert the public key to JWK for storage
					credentialPublicKey = coseToJwk(publicKeyCoseBuffer);

				attestedCredentialData = {
					AAGUID,
					credentialIdLength,
					credentialId,
					credentialPublicKey,
				} as ParsedAttestedCredentialData;
			}

			let authenticatorData: ParsedAuthenticatorData = {
				rpIdHash,
				flags,
				signCount,
				attestedCredentialData,
			};

			// Check for extension data in the authData, which is indicated by
			// the 7th bit of the flag byte being 1(See specification at
			// function start for reference)
			if (flags?.ED) {
				// has extension data
				let extensionDataCbor: any;

				if (attestedCredentialData) {
					// if we have attestedCredentialData, then extension data is
					// the second element
					extensionDataCbor = CBOR.decodeAllSync(
						authData.slice(
							55 + attestedCredentialData.credentialIdLength,
							authData.length
						)
					);
					extensionDataCbor = extensionDataCbor[1];
				} else {
					// ELse it is the first element
					extensionDataCbor = CBOR.decodeFirstSync(
						authData.slice(37, authData.length)
					);
				}
				authenticatorData.extensions =
					CBOR.encode(extensionDataCbor).toString('base64');
			}

			return authenticatorData;
		} catch (error) {
			throw new Error(`Authenticator Data could not be parsed [${error}]`);
		}
	}

	async parseClientData(
		data: ArrayBuffer
	): Promise<{ clientDataJSON: ParsedClientData; rawClientData?: string }> {
		try {
			const utf8Decoder = new TextDecoder('utf-8');

			const rawClientData = utf8Decoder.decode(data);
			const clientDataJSON = JSON.parse(rawClientData);

			let response = {
				...clientDataJSON,
				type: credentialTypeMap[clientDataJSON.type],
			};

			if (clientDataJSON?.tokenBindingId) {
				response = {
					...response,
					tokenBindingId: {
						...clientDataJSON.tokenBindingId,
						status:
							tokenBindingStatusMap[clientDataJSON.tokenBindingId?.status],
					},
				};
			}

			return { clientDataJSON, rawClientData };
		} catch (error) {
			throw error;
		}
	}

	async parsePublicKeyCredentialResponse(data: PublicKeyCredential): Promise<{
		publicKeyCredential: ParsedPublicKeyCredential;
		rawClientData: string;
	}> {
		try {
			// decode and parse clientDataJSON
			const { clientDataJSON, rawClientData } = await this.parseClientData(
				data.response.clientDataJSON
			);

			//
			// parse PublicKeyCredential
			const publicKeyCredential: ParsedPublicKeyCredential = {
				...data,
				response: {
					// parsed clientDataJSON
					clientDataJSON: clientDataJSON,
					// decode attestationObject
					attestationObject: CBOR.decode(data.response.attestationObject),
				},
			};

			return { publicKeyCredential, rawClientData };
		} catch (error) {
			throw error;
		}
	}

	async activate(
		factorId: string,
		rpOrigin: string,
		data: PublicKeyCredential
	) {
		try {
			// parse the PublicKeyCredential
			const {
				publicKeyCredential: { response },
				rawClientData,
			} = (await this.parsePublicKeyCredentialResponse(data)) || {};

			const { clientDataJSON, attestationObject } =
				response as ParsedAuthenticatorAttestationResponse;
			//
			// fetch stored data
			const storedData = (await dbGet(
				factorId
			)) as unknown as PublicKeyCredentialCreateResponse;

			const options =
				storedData?.activation as PublicKeyCredentialCreationOptions;

			/*
			Registration Steps 7 - 9.
			*/
			await this.verifyClientData(
				clientDataJSON,
				ClientDataType.WEBAUTHN_CREATE,
				options,
				rpOrigin
			);
			const { attStmt, authData, fmt } = attestationObject;
			/*
			Registration Step 10.
			// TODO & Assertion Step 10.

			Let 'hash' be the result of computing a hash over response.clientDataJSON using SHA-256.
			*/
			const clientDataHash = sha256(base64url.toBuffer(rawClientData));
			/*
			Registration Step 11.

			Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse structure to obtain the attestation statement format 'fmt', the authenticator data 'authData', and the attestation statement attStmt.

			+----------------------------------- NOTE ------------------------------------+
			|                                                                             |
			| * Decoding was already done when the publicKey was parsed.                  |
			|                                                                             |
			| * Now we only need to convert the authData Buffer into a usable JSON object |
			// TODO finish note
			|	in order to complete Steps 12 - ?
			|                                                                             |
			+-----------------------------------------------------------------------------+
			*/
			const parsedAuthData: ParsedAuthenticatorData = await this.parseAuthData(
				authData as Buffer
			);
			/*
			Registration Step 12
			// TODO & Assertion Step 11.

			Verify that the authData.rpIdHash is equal to the SHA256 encoded rpId that we specified in the options at the client.

			+----------------------------------- NOTE ------------------------------------+
			|                                                                             |
			| If no rpId was specified, skip this step.                                   |
			|                                                                             |
			+-----------------------------------------------------------------------------+
			*/
			if (options.rp?.id) {
				equals(
					parsedAuthData.rpIdHash as Buffer,
					sha256(options?.rp?.id) as Buffer,
					'Failed relying party test.'
				);
			}

			/*
			Registration Step 13
			// TODO & Assertion Step 12.

			Verify that the User Present bit of the flags in authData is set.

			+----------------------------------- NOTE ------------------------------------+
			|                                                                             |
			| * The flags attribute in authenticatorData represents an 8bit array (one    |
			| 	byte) that encodes possible flags that the client uses to transport       |
			| 	information. You can find more details in the documentation of            |
			| 	parseAuthenticationData.                                                  |
			|                                                                             |
			| * User Present is the first bit, meaning that xxxxxxx1 AND 00000001 must be |
			| 	1.                                                                        |
			|                                                                             |
			+-----------------------------------------------------------------------------+
			*/
			equals(parsedAuthData.flags?.UP, true, 'Failed user presence test.');
			/*
			Registration Step 14
			// TODO & Assertion Step 13.

			If user verification is required for this registration, verify that the User Verified bit of the flags in authData is set.

			This is only necessary when the registration requires user authentication (which is the case most times).

			+----------------------------------- NOTE ------------------------------------+
			|                                                                             |
			| User Verified is encoded on the third bit, meaning xxxxx1xx AND 00000100    |
			| must be at least 4.                                                         |
			|                                                                             |
			+-----------------------------------------------------------------------------+
			*/
			equals(parsedAuthData.flags?.UV, true, 'Failed user verification test.');
			/*
			Registration Step 15
			// TODO & Assertion Step 14.

			Verify that the 'alg' parameter in the credential public key in authData matches the 'alg' attribute of ONE of the items in options.pubKeyCredParams.

			+----------------------------------- NOTE ------------------------------------+
			|                                                                             |
			| If no value was specified during creation, skip this step.                  |
			|                                                                             |
			+-----------------------------------------------------------------------------+
			*/
			if (options?.pubKeyCredParams?.length > 0) {
				let allowedAlgs = [];

				options?.pubKeyCredParams.forEach(param => allowedAlgs.push(param.alg));

				const alg = data.response.getPublicKeyAlgorithm();

				ok(
					allowedAlgs.includes(alg),
					`Expected one of: ${allowedAlgs}, Received: ${alg}`
				);
			}
			/*
			Registration Step 16.

			Verify that the values of the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData are as expected, considering the client extension input values that were given in options.extensions and any specific policy of the Relying Party regarding unsolicited extensions, i.e., those that were not specified as part of the options.extensions.

			In the general case, the meaning of are as expected' is specific to the Relying Party and which extensions are in use.

			+----------------------------------- NOTE ------------------------------------+
			|                                                                             |
			| Client platforms MAY enact local policy that sets additional authenticator  |
			| extensions or client extensions and thus cause values to appear in the      |
			| authenticator extension outputs or client extension outputs that were not   |
			| originally specified as part of options.extensions. Relying Parties MUST be |
			| prepared to handle such situations, whether it be to ignore the unsolicited |
			| extensions or reject the attestation.                                       |
			|                                                                             |
			| The Relying Party can make this based on local policy and the extensions in |
			| use.                                                                        |
			|                                                                             |
			+-----------------------------------------------------------------------------+

			+----------------------------------- NOTE ------------------------------------+
			|                                                                             |
			| Since all extensions are OPTIONAL for both the client and the authenticator,|
			| the Relying Party MUST also be prepared to handle cases where none or not   |
			| all of the requested extensions were acted upon.                            |
			|                                                                             |
			+-----------------------------------------------------------------------------+
			*/
			if (parsedAuthData?.extensions && options?.extensions) {
				const expectedExtensions = Object.keys(options.extensions),
					extensions = Object.keys(parsedAuthData.extensions);

				for (let i = 0; i < extensions.length; i++) {
					ok(
						expectedExtensions.includes(extensions[i]),
						`Expected: ${expectedExtensions}, Received: ${extensions}. Failed extensions test.`
					);
				}
			}
			/*
			Registration Step 17.

			Determine the attestation statement format by performing a USASCII case-sensitive match on `fmt` against the set of supported WebAuthn Attestation Statement Format Identifier values.

			An up-to-date list of registered WebAuthn Attestation Statement Format Identifier values is maintained in the IANA "WebAuthn Attestation Statement Format Identifiers" registry [(IANA-WebAuthn-Registries)[https://w3c.github.io/webauthn/#biblio-iana-webauthn-registries]] established by [[RFC8809](https://w3c.github.io/webauthn/#biblio-rfc8809)].
			*/
			ok(
				isTPMAttestation(attestationObject) ||
					isPackedAttestation(attestationObject) ||
					isAndroidKeyAttestation(attestationObject) ||
					isAndroidSafetyNetAttestation(attestationObject) ||
					isFIDOU2FAttestation(attestationObject) ||
					isNoneAttestation(attestationObject),
				`Expected one of ['android-key', android-safetynet', fido-u2f', 'none', 'packed', 'tpm'], Received: ${fmt}. Failed Attestation Statement Format test.`
			);
			/*
			Registration Step 18.

			Verify that attStmt is a correct attestation statement, conveying a valid attestation signature, by using the attestation statement format fmt’s verification procedure given attStmt, authData and hash.

			+----------------------------------- NOTE ------------------------------------+
			|                                                                             |
			| Each attestation statement format specifies its own verification procedure. |
			|                                                                             |
			| See § 8 Defined Attestation Statement Formats for the initially-defined     |
			| formats, and [IANA-WebAuthn-Registries] for the up-to-date list.            |
			|                                                                             |
			+-----------------------------------------------------------------------------+
			*/

			let attestationSignatureIsValid = false;

			switch (fmt) {
				case 'tpm':
					attestationSignatureIsValid = await TPMVerify(
						authData as Buffer,
						attStmt as TPMStmt,
						clientDataHash,
						parsedAuthData
					);
					break;
				default:
					break;
			}
			/*
			Registration Step 19.

			If validation is successful, obtain a list of acceptable trust anchors (i.e. attestation root certificates) for that attestation type and attestation statement format `fmt`, from a trusted source or from policy.

			For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information, using the aaguid in the `attestedCredentialData` in `authData`.
			*/

			/*
			Registration Step 20.

			Assess the attestation trustworthiness using the outputs of the verification procedure in step 19, as follows:

			→ If no attestation was provided, verify that None attestation is acceptable under Relying Party policy.

			→ If self attestation was used, verify that self attestation is acceptable under Relying Party policy.

			→ Otherwise, use the X.509 certificates returned as the attestation trust path from the verification procedure to verify that the attestation public key either correctly chains up to an acceptable root certificate, or is itself an acceptable certificate (i.e., it and the root certificate obtained in Step 19 may be the same).
			*/

			/*
			Registration Step 21.

			Check that the credentialId is ≤ 1023 bytes. Credential IDs larger than this many bytes SHOULD cause the RP to fail this registration ceremony.
			*/

			/*
			Registration Step 22.

			Check that the `credentialId` is not yet registered to any other user. If registration is requested for a credential that is already registered to a different user, the Relying Party SHOULD fail this registration ceremony, or it MAY decide to accept the registration, e.g. while deleting the older registration.
*/

			/*
			Registration Step 23.

			If the attestation statement `attStmt` verified successfully and is found to be trustworthy, then register the new credential with the account that was denoted in options.user:

			Associate the user’s account with the `credentialId` and `credentialPublicKey` in `authData.attestedCredentialData`, as appropriate for the Relying Party's system.

			Associate the `credentialId` with a new stored signature counter value initialized to the value of `authData.signCount`.

			It is RECOMMENDED to also:

			Associate the `credentialId` with the transport hints returned by calling `credential.response.getTransports()`. This value SHOULD NOT be modified before or after storing it. It is RECOMMENDED to use this value to populate the transports of the `allowCredentials` option in future get() calls to help the client know how to find a suitable authenticator.
			*/

			/*
			Registration Step 24.

			If the attestation statement `attStmt` successfully verified but is not trustworthy per step 20 above, the Relying Party SHOULD fail the registration ceremony.

			+----------------------------------- NOTE ------------------------------------+
			|                                                                             |
			| If permitted by policy, the Relying Party MAY register the credential ID    |
			| and credential public key but treat the credential as one with self         |
			| attestation (see § 6.5.3 Attestation Types).                                |
			|                                                                             |
			| If doing so, the Relying Party is asserting there is no cryptographic proof |
			| that the public key credential has been generated by a particular           |
			| authenticator model.                                                        |
			|                                                                             |
			| See [FIDOSecRef] and [UAFProtocol] for a more detailed discussion.          |
			|                                                                             |
			+-----------------------------------------------------------------------------+
			*/
		} catch (error) {
			throw error;
		}
	}

	async parseCredentialCreationResponseBody(data: PublicKeyCredential) {
		try {
			// parse PublicKeyCredential
		} catch (error) {
			throw error;
		}
	}
}
