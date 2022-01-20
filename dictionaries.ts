/** @format */

export const Dictionaries = {
	UserVerificationRequirement: {
		required: UserVerificationRequirementEnum.REQUIRED,
		preferred: UserVerificationRequirementEnum.PREFERRED,
		discouraged: UserVerificationRequirementEnum.DISCOURAGED,
	},

	AuthenticatorAttachment: {
		platform: AuthenticatorAttachmentEnum.PLATFORM,
		'cross-platform': AuthenticatorAttachmentEnum.CROSS_PLATFORM,
	},

	AttestationConveyancePreference: {
		none: AttestationPreference.NONE,
		direct: AttestationPreference.DIRECT,
		indirect: AttestationPreference.INDIRECT,
	},

	PublicKeyCredentialType: {
		'public-key': CredentialType.PUBLIC_KEY,
	},

	AuthenticatorTransport: {
		ble: AuthenticatorTransportType.BLE,
		internal: AuthenticatorTransportType.INTERNAL,
		nfc: AuthenticatorTransportType.NFC,
		usb: AuthenticatorTransportType.USB,
	},
};
