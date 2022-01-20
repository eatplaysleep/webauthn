/** @format */

import {
	ParsedAttestationObject,
	ParsedAttestedCredentialData,
} from '../../../models';

/**
 * Specification: https://w3c.github.io/webauthn/#sctn-fido-u2f-attestation
 */
export interface FIDOU2FAttestation extends ParsedAttestedCredentialData {
	fmt: 'fido-u2f';
	attStmt: {
		x5c: Array<Buffer>;
		sig: Buffer;
	};
}

export const isFIDOU2FAttestation = (obj: { [key: string]: any }): boolean => {
	if (
		obj['fmt'] &&
		obj['fmt'] === 'fido-u2f' &&
		obj['attStmt'] &&
		obj['attStmt']['x5c'] &&
		obj['attStmt']['sig']
	)
		return true;
	return false;
};

export const FIDOU2FVerify = (
	attestation: ParsedAttestationObject,
	clientDataHash: Buffer
): boolean => {
	//TODO
	return true;
};
