/** @format */

export interface PubArea {
	authPolicy: Buffer;
	nameAlg: string;
	objectAttributes: {
		adminWithPolicy: boolean;
		decrypt: boolean;
		encryptedDuplication: boolean;
		fixedParent: boolean;
		fixedTPM: boolean;
		noDA: boolean;
		restricted: boolean;
		sensitiveDataOrigin: boolean;
		signORencrypt: boolean;
		stClear: boolean;
		userWithAuth: boolean;
	};
	type: string;
	unique: Buffer;
	parameters: {
		exponent: number;
		keyBits: number;
		scheme: string;
		symmetric: string;
	};
}

//Copied from https://medium.com/@herrjemand/verifying-fido-tpm2-0-attestation-fc7243847498
//Full specification can be found here (Chapter 12.2.4): https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
export const parsePubArea = async (pubAreaBuffer: Buffer) => {
	try {
		let typeBuffer = pubAreaBuffer.slice(0, 2);
		//@ts-ignore Because of parsing issues with types that I didn't want to get into too deep
		let type = TPM_ALG[typeBuffer.readUInt16BE(0)];
		pubAreaBuffer = pubAreaBuffer.slice(2);

		let nameAlgBuffer = pubAreaBuffer.slice(0, 2);
		//@ts-ignore Because of parsing issues with types that I didn't want to get into too deep
		let nameAlg = TPM_ALG[nameAlgBuffer.readUInt16BE(0)];
		pubAreaBuffer = pubAreaBuffer.slice(2);

		let objectAttributesBuffer = pubAreaBuffer.slice(0, 4);
		let objectAttributesInt = objectAttributesBuffer.readUInt32BE(0);
		let objectAttributes = {
			fixedTPM: !!(objectAttributesInt & 1),
			stClear: !!(objectAttributesInt & 2),
			fixedParent: !!(objectAttributesInt & 8),
			sensitiveDataOrigin: !!(objectAttributesInt & 16),
			userWithAuth: !!(objectAttributesInt & 32),
			adminWithPolicy: !!(objectAttributesInt & 64),
			noDA: !!(objectAttributesInt & 512),
			encryptedDuplication: !!(objectAttributesInt & 1024),
			restricted: !!(objectAttributesInt & 32768),
			decrypt: !!(objectAttributesInt & 65536),
			signORencrypt: !!(objectAttributesInt & 131072),
		};
		pubAreaBuffer = pubAreaBuffer.slice(4);

		let authPolicyLength = pubAreaBuffer.slice(0, 2).readUInt16BE(0);
		pubAreaBuffer = pubAreaBuffer.slice(2);
		let authPolicy = pubAreaBuffer.slice(0, authPolicyLength);
		pubAreaBuffer = pubAreaBuffer.slice(authPolicyLength);

		let parameters = undefined;
		if (type === 'TPM_ALG_RSA') {
			parameters = {
				//@ts-ignore Because of parsing issues with types that I didn't want to get into too deep
				symmetric: TPM_ALG[pubAreaBuffer.slice(0, 2).readUInt16BE(0)],
				//@ts-ignore Because of parsing issues with types that I didn't want to get into too deep
				scheme: TPM_ALG[pubAreaBuffer.slice(2, 4).readUInt16BE(0)],
				keyBits: pubAreaBuffer.slice(4, 6).readUInt16BE(0),
				exponent: pubAreaBuffer.slice(6, 10).readUInt32BE(0),
			};
			pubAreaBuffer = pubAreaBuffer.slice(10);
		} else if (type === 'TPM_ALG_ECC') {
			parameters = {
				//@ts-ignore Because of parsing issues with types that I didn't want to get into too deep
				symmetric: TPM_ALG[pubAreaBuffer.slice(0, 2).readUInt16BE(0)],
				//@ts-ignore Because of parsing issues with types that I didn't want to get into too deep
				scheme: TPM_ALG[pubAreaBuffer.slice(2, 4).readUInt16BE(0)],
				//@ts-ignore Because of parsing issues with types that I didn't want to get into too deep
				curveID: TPM_ECC_CURVE[pubAreaBuffer.slice(4, 6).readUInt16BE(0)],
				//@ts-ignore Because of parsing issues with types that I didn't want to get into too deep
				kdf: TPM_ALG[pubAreaBuffer.slice(6, 8).readUInt16BE(0)],
			};
			pubAreaBuffer = pubAreaBuffer.slice(8);
		} else throw new Error(type + ' is an unsupported type!');

		let uniqueLength = pubAreaBuffer.slice(0, 2).readUInt16BE(0);
		pubAreaBuffer = pubAreaBuffer.slice(2);
		let unique = pubAreaBuffer.slice(0, uniqueLength);
		pubAreaBuffer = pubAreaBuffer.slice(uniqueLength);

		return {
			type,
			nameAlg,
			objectAttributes,
			authPolicy,
			parameters,
			unique,
		};
	} catch (error) {
		throw new Error(`Unable to parse pub area [${error}]`);
	}
};
