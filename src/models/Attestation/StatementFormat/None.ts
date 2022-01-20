/** @format */

import { ParsedAttestationObject } from '../../../models';
/**
 * Specification: https://w3c.github.io/webauthn/#sctn-none-attestation
 */
export interface NoneAttestation extends ParsedAttestationObject {
	readonly fmt: 'none';
	readonly attStmt: {};
}

export const isNoneAttestation = (obj: { [key: string]: any }): boolean => {
	if (obj['fmt'] && obj['fmt'] === 'none' && obj['attStmt']) return true;
	return false;
};

export const NoneVerify = (): boolean => {
	// TODO implement noneVerify
	return true;
};
