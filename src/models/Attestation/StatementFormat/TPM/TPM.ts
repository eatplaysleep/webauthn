/** @format */

import {
	ParsedAttestationObject,
	ParsedAuthenticatorData,
	RSAJwk,
	x5cInterface,
} from '../../..';
import { equals, ok, CryptoUtil } from '../../../../utils';
// import {,
// 	coseToJwk,
// 	ecdaaWarning,
// } from '../../../authentication/util';
import { PubArea, parsePubArea } from './PubArea';
import { CertInfo, parseCertInfo } from './CertInfo';

// import jwkToPem, { JWK } from 'jwk-to-pem';
// import * as CBOR from 'cbor';
import { createVerify } from 'crypto';
import { Certificate } from '@fidm/x509';
// import { x5cInterface } from 'models/custom/x5cCertificate';

const { sha1, sha256 } = new CryptoUtil();

/**
 * Specification: https://w3c.github.io/webauthn/#sctn-tpm-attestation
 */
export interface TPMAttestation extends ParsedAttestationObject {
	fmt: 'tpm';
	attStmt: TPMStmt;
}

export interface TPMStmt {
	ver: '2.0';
	alg: number;
	x5c?: Array<Buffer>;
	ecdaaKeyId?: Buffer;
	sig: Buffer;
	certInfo: Buffer;
	pubArea: Buffer;
}

export const isTPMAttestation = (obj: { [key: string]: any }): boolean => {
	if (
		obj['fmt'] &&
		obj['fmt'] === 'tpm' &&
		obj['attStmt'] &&
		obj['attStmt']['ver'] &&
		obj['attStmt']['ver'] === '2.0' &&
		obj['attStmt']['alg'] &&
		(obj['attStmt']['x5c'] || obj['attStmt']['ecdaaKeyId']) &&
		obj['attStmt']['sig'] &&
		obj['attStmt']['certInfo'] &&
		obj['attStmt']['pubArea']
	)
		return true;
	return false;
};

/*
To simplify readability and optimize performance, we additionally pass the attestation to have authData as a raw Buffer
*/
export const TPMVerify = async (
	authData: Buffer,
	attStmt: TPMStmt,
	clientDataHash: Buffer,
	parsedAuthData: ParsedAuthenticatorData
): Promise<boolean> => {
	/*
	To work with pubArea and certInfo, we have to convert its Buffer structure into JSON.

	Specification and additional information can be found at the respective function documentations.
	*/
	const pubArea: PubArea = (await parsePubArea(attStmt.pubArea)) as PubArea,
		certInfo: CertInfo = await parseCertInfo(attStmt.certInfo);

	//Concatenate authData and clientDataHash to attToBeSigned
	const attToBeSigned = Buffer.concat([authData, clientDataHash]);

	//Check if all information provided in pubInfo is correct
	await validatePubInfo(pubArea, parsedAuthData);

	//Check if all information provided in certInfo is correct
	await validateCertInfo(certInfo, attStmt.pubArea, attToBeSigned);

	if (attStmt.x5c) {
		//Verify the sig is a valid signature over certInfo using the attestation public key in aikCert (x5c first element, caCert second element) with the algorithm specified in alg.
		let x5cString = attStmt.x5c[0].toString('base64');

		//Add headers to cert to make it a valid PEM certificate
		let cert =
			'-----BEGIN CERTIFICATE-----\n' +
			x5cString +
			'\n-----END CERTIFICATE-----';

		//TODO: Abstract algorithm (currently -65535 is hardcoded)
		//A list of all COSE algorithms can be found here (https://www.iana.org/assignments/cose/cose.xhtml#algorithms), a list of all Node.js crypto supported algorithms here (https://stackoverflow.com/questions/14168703/crypto-algorithm-list)
		if (attStmt.alg != -65535) {
			console.warn(
				'The authenticator is using an algorithm which is not supported to encrypt its signature. This is a shortcoming of this library and will be fixed in further releases. If you want to support the development of this library, please create an issue on the GitHub repository with following information:\n\n TPM Verification Algorithm not supported!\nAlgorithm:',
				attStmt.alg
			);
		} else {
			const verify = await createVerify('RSA-SHA1').update(attStmt.certInfo);

			ok(verify.verify(cert, attStmt.sig), 'Sig invalid');
		}

		//Verify that aikCert meets the requirements in § 8.3.1 TPM Attestation Statement Certificate Requirements.
		//We first have to decode the PEM certificate in order to verify its values
		const decryptCert: any = Certificate.fromPEM(Buffer.from(cert));

		await validatex509Cert(decryptCert);
	} else if (attStmt.ecdaaKeyId) {
		console.warn(
			'Your clients TPM module is using an ECDAA key to encrypt its verification data. ECDAA verification is not yet supported in this framework and will be implemented in a further release. If you want to support the development of this library, please create an issue on the GitHub repository with the following information:\n\n ECDAA Verification not supported!\nClient machine: <your-device>\nAuthentication method used: <e.g. Windows Hello, Apple Touch ID, ...>'
		);
		//TODO: Perform ECDAA-Verify on sig to verify that it is a valid signature over certInfo (see [FIDOEcdaaAlgorithm]).
		//Unfortunately no test scenario found so far on which this could have been implemented
	}

	return true;
};

const validatePubInfo = async (
	pubArea: PubArea,
	authenticatorData: ParsedAuthenticatorData
): Promise<void> => {
	//Check if the same algorithms were used to create the Public Key
	try {
		ok(
			pubArea.type.includes(
				authenticatorData.attestedCredentialData.credentialPublicKey.kty
			),
			`Mismatch on algorithms!`
		);

		//Check if the public key encoded in pubAreaKey matches the public key that authenticatorData attested us
		//To check if the public key in authenticatorData matches the public key in pubArea, we have to convert the pubArea unique Buffer into a string
		const pubAreaKey = pubArea.unique.toString('base64'),
			credentialPublicKey = authenticatorData.attestedCredentialData
				.credentialPublicKey as RSAJwk;
		ok(pubAreaKey === credentialPublicKey?.n, `Invalid public key.`);
	} catch (error) {
		throw new Error(`Unable to verify pub info [${error}]`);
	}
};

const validateCertInfo = async (
	certInfo: CertInfo,
	pubAreaBuffer: Buffer,
	attToBeSigned: Buffer
): Promise<void> => {
	try {
		//Check if certInfo.magic is set to "TPM_GENERATED_VALUE". In the specification, this string is encoded by the HEX value 0xFF544347, which translates into the decimal number 4283712327.
		equals(certInfo.magic, 4283712327);

		//Check if certInfo.magic is set to "TPM_ST_ATTEST_CERTIF".
		equals(
			certInfo.type,
			'TPM_ST_ATTEST_CERTIFY',
			'CertInfo type test failed.'
		);

		//Verify that extraData is set to the hash of attToBeSigned using the hash algorithm employed in "alg".
		//TODO abstract alg to work not only with TPM modules (Translate https://www.iana.org/assignments/cose/cose.xhtml#algorithms in https://stackoverflow.com/questions/14168703/crypto-algorithm-list)
		const sha1Secret = await sha1(attToBeSigned);

		ok(sha1Secret.equals(certInfo.extraData), 'SHA1 hash invalid');

		//Verify that attested contains a TPMS_CERTIFY_INFO structure as specified in https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf section 10.12.3
		if (!certInfo.attested.name || !certInfo.attested.qualifiedName) {
			ok(false, 'CertInfo structure invalid');
		}

		//Check if the name of certInfo matches the hash of pubArea with the nameAlg specified in certInfo.attested

		const strippedName = certInfo.attested.name.slice(2);

		const pubAreaHash = await sha256(pubAreaBuffer);

		ok(strippedName.equals(pubAreaHash), 'Hash mismatch');
	} catch (error) {
		throw new Error(`Unable to verify Cert Info [${error}]`);
	}
};

const validatex509Cert = async (cert: x5cInterface): Promise<void> => {
	try {
		//Version MUST be set to 3.
		equals(cert.version, 3);

		//Subject field MUST be set to empty.
		ok(cert.subject.uniqueId !== null, 'Subject field MUST NOT be empty');

		//The Subject Alternative Name extension MUST be set as defined in section 3.2.9 of https://www.trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf
		const subAltText = cert.extensions.find(extension => {
			return extension.name === 'subjectAltName';
		});
		const subAltTextBuf = subAltText ? subAltText.value : [];
		//TODO parse value, needs to be ASN1 decoded, tcpaTpmManufacturer to be matched with https://trustedcomputinggroup.org/wp-content/uploads/Vendor_ID_Registry_0-8_clean.pdf
		let subAltText64 = subAltTextBuf.toString('base64');

		//The Extended Key Usage extension MUST contain the "joint-iso-itu-t(2) internationalorganizations(23) 133 tcg-kp(8) tcg-kp-AIKCertificate(3)" OID
		const extKeyUsage = cert.extensions.find((extension: any) => {
			return extension.name === 'extKeyUsage';
		});

		ok(
			extKeyUsage && extKeyUsage['2.23.133.8.3'],
			'Extended key usage test fail.'
		);

		//The Basic Constraints extension MUST have the CA component set to false.
		const basicConstraints = cert.extensions.find((extension: any) => {
			return extension.name === 'basicConstraints';
		});
		ok(
			!basicConstraints?.isCA,
			'Basic Constraints extension MUST have CA component set to false'
		);
	} catch (error) {
		throw new Error(`Unable to validate x509 Certificate [${error}]`);
	}
};
