/** @format */
/**
 * Generic representation of a ClientAttestation. Specific attestation types are specified in types -> fido -> Attestation Statement Format
 * https://w3c.github.io/webauthn/#attestation-statement
 */

import {
	ParsedAuthenticatorResponse,
	ParsedAuthenticatorData,
} from '../../models';

export interface ParsedAttestationObject {
	authData: Buffer | ParsedAuthenticatorData;
	fmt: string;
	attStmt: {
		// alg: number;
		// certInfo: ArrayBuffer;
		// sig: ArrayBuffer;
		// pubArea: ArrayBuffer;
		// ver: string;
		// x5c: Array<ArrayBuffer>;
	};
}

/**
 * Specification: https://w3c.github.io/webauthn/#sctn-attested-credential-data
 */

export interface ParsedAttestationResponse extends ParsedAuthenticatorResponse {
	readonly attestationObject: ParsedAttestationObject;
}

export interface ParsedAttestedCredentialData {
	AAGUID: string;
	credentialId: Buffer;
	credentialIdLength: number;
	credentialPublicKey: ECJwk | RSAJwk;
}

export interface ECJwk {
	kty: 'EC';
	crv: 'P-256';
	x: string;
	y: string;
}

export interface RSAJwk {
	kty: 'RSA';
	n: string;
	e: string;
}
