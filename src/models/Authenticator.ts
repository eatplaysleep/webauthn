/**
 * @format
 * In its original form, AuthenticatorData is represented as a bit buffer. The encoding of these bits can be found in the specification.
 * https://w3c.github.io/webauthn/#sctn-authenticator-data
 *
 */

/*
	AuthenticatorData From §6.1 of the spec.

	The authenticator data structure encodes contextual bindings made by the authenticator. These bindings are controlled by the authenticator itself, and derive their trust from the WebAuthn Relying Party's assessment of the security properties of the authenticator. In one extreme case, the authenticator may be embedded in the client, and its bindings may be no more trustworthy than the client data.

	At the other extreme, the authenticator may be a discrete entity with high - security hardware and software, connected to the client over a secure channel.In both cases, the Relying Party receives the authenticator data in the same format, and uses its knowledge of the authenticator to make trust decisions.

	The authenticator data, at least during attestation, contains the Public Key that the RP stores and will associate with the user attempting to register.
*/
import { ParsedAttestedCredentialData } from '../models';

export interface ParsedAuthenticatorResponse {
	// From the spec https://www.w3.org/TR/webauthn/#dom-authenticatorresponse-clientdatajson
	// This attribute contains a JSON serialization of the client data passed to the authenticator
	// by the client in its call to either create() or get().
	clientDataJSON: ParsedClientData;
}

export interface ParsedAuthenticatorData {
	readonly attestedCredentialData: ParsedAttestedCredentialData;
	extensions?: string;
	/*
	AuthenticatorFlags A byte of information returned during during ceremonies in the authenticatorData that contains bits that give us information about the whether the user was present and/or verified during authentication, and whether there is attestation or extension data present. Bit 0 is the least significant bit.
	*/
	readonly flags: AuthenticatorFlags;
	readonly rpIdHash: Buffer;
	signCount: number;
}

interface ParsedClientData {
	readonly challenge: string;
	// Chromium (Chrome) returns a hint sometimes about how to handle
	// clientDataJSON in a safe manner
	readonly hint: string;
	readonly origin: string;
	readonly tokenBindingId?: TokenBinding;
	readonly type: ClientDataType;
}

interface TokenBinding {
	readonly status: TokenBindingStatus;
	readonly id: string;
}

/*
AuthenticatorFlags A byte of information returned during during ceremonies in the authenticatorData that contains bits that give us information about whether the user was present and/or verified during authentication, and whether there is attestation or extension data present. Bit 0 is the least significant bit.
*/
interface AuthenticatorFlags {
	/* FlagUserPresent Bit 00000001 in the byte sequence. Tells us if user is present */
	UP: boolean /* 'USER_PRESENT - Referred to as UP */;
	/* FlagUserVerified Bit 00000100 in the byte sequence. Tells us if user is verified by the authenticator using a biometric or PIN */
	RFU1: boolean;
	UV: boolean /* 'USER_VERIFIED' - Referred to as UV */;
	/* FlagAttestedCredentialData Bit 01000000 in the byte sequence. Indicates whether the authenticator added attested credential data. */
	RFU2a: boolean;
	RFU2b: boolean;
	RFU2c: boolean;
	AT: boolean /* 'ATTESTATION_CREDENTIAL_DATA' - Referred to as AT */;
	/* FlagHasExtension Bit 10000000 in the byte sequence. Indicates if the authenticator data has extensions. */
	ED: boolean /* 'HAS_EXTENSIONS' - Referred to as ED */;
}

enum ClientDataType {
	'WEBAUTHN_CREATE',
}

export enum TokenBindingStatus {
	'SUPPORTED',
	'PRESENT',
}
