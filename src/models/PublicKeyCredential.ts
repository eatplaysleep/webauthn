/** @format */

import {
	ParsedCredential,
	ParsedAssertionResponse,
	ParsedAttestationResponse,
} from '../models';

export interface PublicKeyCredential extends Omit<Credential, 'type'> {
	readonly type: PublicKeyCredentialType;
	readonly rawId: ArrayBuffer;
	readonly response: AuthenticatorResponse;
}

interface AuthenticatorResponse {
	authenticatorData: string;
	clientDataJSON: string;
	signature: string;
	userHandle: string;
}

// The PublicKeyCredential interface extends Credential, and contains
//  the attributes that are returned to the caller when a new credential
// is created, or a new assertion is requested.
export interface ParsedPublicKeyCredential extends ParsedCredential {
	readonly rawId: ArrayBuffer;
	response: ParsedAttestationResponse | ParsedAssertionResponse;
	authenticatorAttachment?: AuthenticatorAttachment;
}

export interface PublicKeyCreateOptions
	extends Omit<PublicKeyCredentialCreationOptions, 'rp'> {
	rp: PublicKeyRpEntity;
}

interface PublicKeyRpEntity extends Omit<PublicKeyCredentialRpEntity, 'name'> {
	name?: string;
}

export interface PublicKeyCredentialCreateResponse {
	factorType: FactorType;
	factorId: string;
	provider: ProviderType;
	status: FactorStatus;
	created: Date;
	lastUpdated: Date;
	options: PublicKeyCredentialCreationOptions;
}

export type FactorType = 'WEBAUTHN';

export type ProviderType = 'FIDO';

export type FactorStatus = 'PENDING_ACTIVATION' | 'ACTIVE';
