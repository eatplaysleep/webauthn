/** @format */

// The basic credential type that is inherited by WebAuthn's
// PublicKeyCredential type.
// https://w3c.github.io/webappsec-credential-management/#credential
export enum CredentialType {
	'PUBLIC_KEY',
}

export interface ParsedCredential {
	// ID is The credential’s identifier. The requirements for the
	// identifier are distinct for each type of credential. It might
	// represent a username for username/password tuples, for example.
	readonly id: string;
	// Type is the value of the object’s interface object's [[type]] slot,
	// which specifies the credential type represented by this object.
	// This should be type "public-key" for Webauthn credentials.
	readonly type: PublicKeyCredentialType;
}
