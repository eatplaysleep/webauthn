/** @format */

export interface CertInfo {
	attested: {
		name: Buffer;
		nameAlg: string;
		qualifiedName: Buffer;
	};
	clockInfo: {
		clock: Buffer;
		resetCount: number;
		restartCount: number;
		safe: boolean;
	};
	extraData: Buffer;
	firmwareVersion: Buffer;
	magic: number;
	qualifiedSigner: Buffer;
	type: string;
}

//Copied from https://medium.com/@herrjemand/verifying-fido-tpm2-0-attestation-fc7243847498
//Full specification can be found here (Chapter 10.12.8): https://www.trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
export const parseCertInfo = async (certInfoBuffer: Buffer) => {
	try {
		let magicBuffer = certInfoBuffer.slice(0, 4);
		let magic = magicBuffer.readUInt32BE(0);
		certInfoBuffer = certInfoBuffer.slice(4);

		let typeBuffer = certInfoBuffer.slice(0, 2);
		//@ts-ignore Because of parsing issues with types that I didn't want to get into too deep
		let type = TPM_ST[typeBuffer.readUInt16BE(0)];
		certInfoBuffer = certInfoBuffer.slice(2);

		let qualifiedSignerLength = certInfoBuffer.slice(0, 2).readUInt16BE(0);
		certInfoBuffer = certInfoBuffer.slice(2);
		let qualifiedSigner = certInfoBuffer.slice(0, qualifiedSignerLength);
		certInfoBuffer = certInfoBuffer.slice(qualifiedSignerLength);

		let extraDataLength = certInfoBuffer.slice(0, 2).readUInt16BE(0);
		certInfoBuffer = certInfoBuffer.slice(2);
		let extraData = certInfoBuffer.slice(0, extraDataLength);
		certInfoBuffer = certInfoBuffer.slice(extraDataLength);

		let clockInfo = {
			clock: certInfoBuffer.slice(0, 8),
			resetCount: certInfoBuffer.slice(8, 12).readUInt32BE(0),
			restartCount: certInfoBuffer.slice(12, 16).readUInt32BE(0),
			safe: !!certInfoBuffer[16],
		};
		certInfoBuffer = certInfoBuffer.slice(17);

		let firmwareVersion = certInfoBuffer.slice(0, 8);
		certInfoBuffer = certInfoBuffer.slice(8);

		let attestedNameBufferLength = certInfoBuffer.slice(0, 2).readUInt16BE(0);
		let attestedNameBuffer = certInfoBuffer.slice(
			2,
			attestedNameBufferLength + 2
		);
		certInfoBuffer = certInfoBuffer.slice(2 + attestedNameBufferLength);

		let attestedQualifiedNameBufferLength = certInfoBuffer
			.slice(0, 2)
			.readUInt16BE(0);
		let attestedQualifiedNameBuffer = certInfoBuffer.slice(
			2,
			attestedQualifiedNameBufferLength + 2
		);
		certInfoBuffer = certInfoBuffer.slice(
			2 + attestedQualifiedNameBufferLength
		);

		let attested = {
			//@ts-ignore Because of parsing issues with types that I didn't want to get into too deep
			nameAlg: TPM_ALG[attestedNameBuffer.slice(0, 2).readUInt16BE(0)],
			name: attestedNameBuffer,
			qualifiedName: attestedQualifiedNameBuffer,
		};

		return {
			magic,
			type,
			qualifiedSigner,
			extraData,
			clockInfo,
			firmwareVersion,
			attested,
		};
	} catch (error) {
		throw new Error(`Unable to parse cert info [${error}]`);
	}
};
