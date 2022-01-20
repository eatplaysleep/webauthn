/** @format */

import {
	ParsedAuthenticatorData,
	ParsedAuthenticatorResponse,
} from '../models';

export interface ParsedAssertionResponse extends ParsedAuthenticatorResponse {
	authenticatorData: ParsedAuthenticatorData;
	signature: Array<Byte>;
	userHandle?: Array<Byte>;
}

type Byte = number;
