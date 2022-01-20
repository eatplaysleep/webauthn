/** @format */

import * as okta from '@okta/okta-sdk-nodejs';

const API_KEY = process.env.API_OKTA_KEY;
// const CLIENT_ID = process.env.API_OKTA_CLIENT_ID;
export const ORG_URL = process.env.ORG_URL ?? '';

export const OktaClient = new okta.Client({
	orgUrl: ORG_URL,
	token: API_KEY,
});
