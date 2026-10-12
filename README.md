# SAML 2.0 parser and validator

![Build Status](https://github.com/ory/saml20/actions/workflows/node.js.yml/badge.svg)

A SAML 2.0 library for Node.js: it validates SAML Responses, and creates and parses AuthnRequests, logout messages and metadata. It started as a fork of [saml20](https://github.com/leandrob/saml20) and has since diverged from it. Ory maintains it, and it is published on npm as [`@boxyhq/saml20`](https://www.npmjs.com/package/@boxyhq/saml20).

## Installation

```bash
$ npm install @boxyhq/saml20
```

## Usage

`validate()` returns a promise.

### saml.validate(rawResponse, options)

Verifies a SAML Response (or a lone Assertion) and resolves with the user's profile. It rejects when anything fails: an unsuccessful `StatusCode`, a missing or invalid signature, an expired assertion, or a failed audience, `InResponseTo`, `Recipient` or replay check.

`rawResponse` is the XML as a string (decode the base64 `SAMLResponse` form field first).

`options` (TypeScript: `ValidateOptions`):

- `publicKey`: the trusted IdP signing certificate, as base64 DER or PEM. Several certificates (for key rotation) are separated by commas.
- `thumbprint`: the SHA-1 thumbprint(s) of a trusted certificate, comma-separated. The certificate itself is taken from the `KeyInfo` of the signature being verified. Pass either `publicKey` or `thumbprint`, not both.
- `privateKey` (optional): decrypts an `EncryptedAssertion`.
- `audience`: the expected audience, or a list of accepted ones. Every `AudienceRestriction` in the assertion must name one of them exactly. Fails with `Invalid audience.` A missing or empty value fails with `audience is required.`
- `inResponseTo` (optional): the ID of the `AuthnRequest` this response answers. When set, the signed content must carry the same `InResponseTo`; a missing value fails. Fails with `Invalid InResponseTo.`
- `recipient` (optional). The ACS URL the response was posted to. When set, the signed content must name it: a signed `Response/@Destination` must equal it, when any bearer `SubjectConfirmationData` carries a `Recipient`, one bearer confirmation must both name it and be within its own `NotBefore`/`NotOnOrAfter` window (so `NotOnOrAfter` is required on it; `bypassExpiration` skips this window check but not the `Recipient` match), and at least one of the two must be present. An empty `Recipient` counts as present and never matches. The unsigned `Response` wrapper is never used. Fails with `Invalid Recipient.`
- `assertionReplayValidator` (optional): `(info) => boolean | Promise<boolean>`, called after every other check passes, with `{ assertionId, sessionIndex, notOnOrAfter, inResponseTo }` from the signed assertion. Return `true` if the assertion was already used, and the response is rejected as a replay. Keep each entry until at least `notOnOrAfter` plus 10 minutes, the clock skew `validate()` allows.
- `bypassExpiration` (optional). This flag indicates expiration validation bypass (useful for testing, not recommended in production environments);
- `allowedSignatureAlgorithms` / `allowedHashAlgorithms` (optional). Algorithm allowlists forwarded to `validateSignature`, see below.
- `maxSignatureReferences` (optional). Ceiling on `SignedInfo/Reference` elements, forwarded to `validateSignature`, see below.

```javascript
const saml = require('@boxyhq/saml20').default;

const profile = await saml.validate(rawResponse, {
  publicKey: 'MIICDzCCAXygAwIBAgIQVWXAvbbQyI5Bc...',
  audience: 'https://sp.example.com',
  inResponseTo: requestId,
  recipient: 'https://sp.example.com/acs',
});

const { claims, issuer, sessionIndex, assertionId, notOnOrAfter } = profile;
```

Errors are `Error`s with a fixed message. When the cause is more specific (for example, why a signature failed), the error is a `WrapError` and the cause is in `error.inner`.

### saml.parseIssuer(rawResponse)

Returns the `Issuer` of a SAML Response without validating anything. Use it to find out which IdP a response claims to come from, so you can pick the certificate to pass to `validate()`.

```javascript
const issuer = saml.parseIssuer(rawResponse);
```

### saml.validateSignature(xml, publicKey, thumbprint, options?)

Verifies the XML signature on `xml` and returns the signed XML. Read the document from that return value, not from `xml`: only the signed content is covered. It throws when the signature is invalid or cannot be checked; a signature that does not verify fails with `invalid signature: the signature does not verify`. Pass either `publicKey` (one certificate, or several separated by commas for key rotation) or `thumbprint`, not both.

`options` (optional) restricts which algorithms are accepted:

- `allowedSignatureAlgorithms` — accepted `SignatureMethod` URIs.
- `allowedHashAlgorithms` — accepted `DigestMethod` URIs.

When an allowlist is omitted, the default set from `xml-crypto` applies (RSA-SHA1, RSA-SHA256, RSA-SHA512 and SHA-1, SHA-256, SHA-512 digests). When one is given, a document using any other algorithm is rejected; an empty list rejects everything.

- `maxSignatureReferences` — maximum number of `Reference` elements accepted in the signature's `SignedInfo` (default 16). A SAML signature carries exactly one. The ceiling bounds the work `xml-crypto` does before it verifies `SignatureValue`: every Reference is canonicalized first, so an unbounded list is an unauthenticated CPU denial of service. A document over the ceiling is rejected with `invalid signature: SignedInfo declares N References; at most M are allowed`, before any canonicalization.

```javascript
var saml = require('@boxyhq/saml20').default;

var signedXml = saml.validateSignature(xml, publicKey, null, {
  allowedSignatureAlgorithms: [
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
  ],
  allowedHashAlgorithms: [
    'http://www.w3.org/2001/04/xmlenc#sha256',
    'http://www.w3.org/2001/04/xmlenc#sha512',
  ],
});
```

## Upgrading to 2.0

2.0 removes APIs that were deprecated or that Polis no longer uses:

- Only the package root can be imported. `package.json` now has an `exports` map, so paths inside the package such as `@boxyhq/saml20/dist/typings` fail with `ERR_PACKAGE_PATH_NOT_EXPORTED` (and with TS2307 under `moduleResolution` `node16`, `nodenext` or `bundler`). Import from the root instead, for example `import type { SAMLProfile } from '@boxyhq/saml20'`. Everything the root exports is listed in `test/lib/compat.spec.ts`.
- `parse()` is gone. It returned a profile without checking the signature, expiry, audience or anything else, so its output could be forged. Use `validate()` to authenticate a response, and `parseIssuer()` to read the Issuer before validating (for example, to pick the IdP certificate).
- `decryptXml` and `PubKeyInfo` are no longer exported from the package root. They were internal helpers for `validate()` and `sign()`.
- `hasValidSignature` is removed. Use `validateSignature()`, which also rejects being given both a certificate and a thumbprint.
- `isMultiRootedXMLError` is removed. A multi-rooted document is rejected with the error `multirooted xml not allowed.`
- `strictAudienceValidation` is gone and audiences are always compared exactly. Before 2.0, without that option an `Audience` that merely started with the expected value was accepted (`https://sp.example.com/metadata.evil.example` passed for `https://sp.example.com/metadata`). If you relied on a prefix match, pass every accepted audience in `audience` instead.
- `validateSignature()` throws when the signature does not verify, where it used to return `null`. It now either returns the signed XML or throws.
- `audience` is required. Before 2.0, leaving it out skipped the audience check, so an assertion issued for any other service provider that trusts the same IdP was accepted.
- `parseMetadata()`, `parseSAMLRequest()`, `parseLogoutRequest()` and `parseLogoutResponse()` parse with the same XML parser as `validate()` (`@xmldom/xmldom`) instead of `xml2js`. They now reject a document with more than one root element, and a namespace prefix that is not declared (other than `xsi` and `xs`). Text and attribute values get the line-ending and whitespace normalization XML requires. A malformed document fails with the parser's message, for example `missing root element` instead of `Non-whitespace before first tag.`

## Tests

```bash
$ npm test            # mocha with coverage
$ npm run typecheck   # type-checks lib/ and test/
$ npm run lint
```

Fixtures live in `test/assets`. Tests that need a fresh validity window, or a shape the fixtures do not have, build and sign their own documents with the helpers in `test/helpers/fixtures.ts`.

## Contributing

Thanks for taking the time to contribute! Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make will benefit everybody and are appreciated.

Report bugs in [GitHub issues](https://github.com/ory/saml20/issues). Please try to create bug reports that are:

- _Reproducible._ Include steps to reproduce the problem.
- _Specific._ Include as much detail as possible: which version, what environment, etc.
- _Unique._ Do not duplicate existing opened issues.
- _Scoped to a Single Bug._ One bug per report.

## Reporting Security Issues

[Responsible Disclosure](SECURITY.md)

## License

MIT
