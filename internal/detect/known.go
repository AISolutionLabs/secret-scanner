// SPDX-License-Identifier: Apache-2.0

package detect

// knownPublic holds SHA-256 hashes of credentials that are published in
// vendor documentation or tooling (AWS docs keys, the Azure Storage emulator
// key, the jwt.io sample token, Stripe's docs test keys). Findings whose
// secret matches are never real leaks. Hashes, not literals, so this file
// itself does not trip secret scanners or push protection.
var knownPublic = map[string]bool{
	"1a5d44a2dca19669d72edf4c4f1c27c4c1ca4b4408fbb17f6ce4ad452d78ddb3": true,
	"78314b11be2e581549ac1c4f616563fad3fdf0c3b71678f6e2299182080e0598": true,
	"c6ea27c534f993d31f0aef882e3d200e7b87470c379ae79c8f9b19d3bd363dc9": true,
	"e21b597ba6b9cafa59d9ebc4d65c0385f5eb3fa56abab2607fa76589ad849a33": true,
	"0011cc25eb4320717494d2703e8cba85743e71b500283c21c8b88147992f9059": true,
	"7f75367e7881255134e1375e723d1dea8ad5f6a4fdb79d938df1f1754a830606": true,
	"2cafc0970149a84f3b9e62eaf169f36f59907a3b3e31f7b82e68c69cd27f7326": true,
	"b1471f544ceeea31333bde7e1ecbaad6eac0d4a749412ad29bd66ef895b81c6b": true,
	"f2d6ca16515033e5dce14eba840b979d27b5cbae24bb3e5bf484339667f86397": true,
	"b8e148545b13c78bc74da2f1a7275dd71e56ddece129d7d2f7b3ecc06f7994da": true, // RFC 6750 example bearer token
}
