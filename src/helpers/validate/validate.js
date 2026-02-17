function validateUUID(uuid) {
	return uuid != null && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(uuid);
}

function validateEmail(email) {
	const reg = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|.(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
	return email != null && reg.test(email);
}

const usernameMinLength = process.env.USERNAME_MIN_LENGTH;
const usernameMaxLength = process.env.USERNAME_MAX_LENGTH;
function validateUsername(username) {
	return username != null && username?.length >= usernameMinLength && username?.length <= usernameMaxLength;
}

function validateSRPSalt(salt) {
	return salt != null && salt?.length == 64;
}

function validateSRPVerifier(verifier) {
	return verifier != null && verifier?.length == 512;
}

module.exports = { validateUUID, validateEmail, validateUsername, validateSRPSalt, validateSRPVerifier };