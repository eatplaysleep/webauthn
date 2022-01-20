/** @format */

const okta = require('@okta/okta-sdk-nodejs');
const User = require('./src/models/User/User');

const { getFactors } = new User();

// const client = new okta.Client({
// 	orgUrl: 'https://expedia-oie.dannyfuhriman.com',
// 	token: '00gi-kd79IbDkaSseBItwYbwqnGTUv-AI59BEs4HWn',
// });

const main = async () => {
	// const user = await client.getUser('00u1gbdg7qdSYpEZ91d7');
	const factors = await getFactors('00u1gbdg7qdSYpEZ91d7');

	console.log(factors);
	// const factors = await user.listFactors();

	// factors.each(factor => {
	// 	console.log(factor);
	// });
};

main();
