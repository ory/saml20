SAML 2.0 & 1.1 Assertion Parser & Validator

![Build Status](https://github.com/boxyhq/saml20/actions/workflows/node.js.yml/badge.svg)

=============

boxyhq/saml20 is a fork of a fork of [saml20](https://github.com/leandrob/saml20). It now has extended functionality and diverges from the original unmaintained library. The new package is published here - https://www.npmjs.com/package/@boxyhq/saml20

## Installation

```bash
$ npm install @boxyhq/saml20
```

## Usage

### [DEPRECATED] saml.parse(rawAssertion, cb)

`rawAssertion` is the SAML Assertion in string format.

Parses the `rawAssertion` without validating signature, expiration and audience. It allows you to get information from the token like the Issuer name in order to obtain the right public key to validate the token in a multi-providers scenario.

```javascript
var saml = require('@boxyhq/saml20').default;

saml.parse(rawAssertion, function (err, profile) {
  // err

  var claims = profile.claims; // Array of user attributes;
  var issuer = profile.issuer; // String Issuer name.
});
```

### saml.parseIssuer(rawAssertion)

`rawAssertion` is the SAML Assertion in string format.

Parses the `rawAssertion` without validating signature, expiration and audience. It allows you to get information from the token like the Issuer name.

```javascript
const issuer = saml.parseIssuer(rawResponse);
```

### saml.validate(rawAssertion, options, cb)

`rawAssertion` is the SAML Assertion in string format.

`options`:

- `thumbprint` is the thumbprint of the trusted public key (uses the public key that comes in the assertion).
- `publicKey` is the trusted public key.
- `audience` (optional). If it is included audience validation will take place.
- `bypassExpiration` (optional). This flag indicates expiration validation bypass (useful for testing, not recommended in production environments);

You can use either `thumbprint` or `publicKey` but you should use at least one.

```javascript
var saml = require('@boxyhq/saml20').default;

var options = {
  thumbprint: '1aeabdfa4473ecc7efc5947b18436c575574baf8',
  audience: 'http://myservice.com/',
};

saml.validate(rawAssertion, options, function (err, profile) {
  // err

  var claims = profile.claims; // Array of user attributes;
  var issuer = profile.issuer; // String Issuer name.
});
```

or using publicKey:

```javascript
var saml = require('@boxyhq/saml20').default;

var options = {
  publicKey: 'MIICDzCCAXygAwIBAgIQVWXAvbbQyI5Bc...',
  audience: 'http://myservice.com/',
};

saml.validate(rawAssertion, options, function (err, profile) {
  // err

  var claims = profile.claims; // Array of user attributes;
  var issuer = profile.issuer; // String Issuer name.
});
```

### saml.validateSignature(xml, publicKey, thumbprint, options?)

Verifies the XML signature on `xml` and returns the signed XML, or throws / returns `null` when the signature is invalid. Pass either `publicKey` (one certificate, or several separated by commas for key rotation) or `thumbprint`, not both.

`options` (optional) restricts which algorithms are accepted:

- `allowedSignatureAlgorithms` — accepted `SignatureMethod` URIs.
- `allowedHashAlgorithms` — accepted `DigestMethod` URIs.

When an allowlist is omitted, the default set from `xml-crypto` applies (RSA-SHA1, RSA-SHA256, RSA-SHA512 and SHA-1, SHA-256, SHA-512 digests). When one is given, a document using any other algorithm is rejected; an empty list rejects everything.

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

## Tests

### Configure test/lib.index.js

In order to run the tests you must configure `lib.index.js` with these variables:

```javascript
var issuerName = 'https://your-issuer.com';
var thumbprint = '1aeabdfa4473ecc7efc5947b19436c575574baf8';
var certificate = 'MIICDzCCAXygAwIBAgIQVWXAvbbQyI5BcFe0ssmeKTAJBgU...';
var audience = 'http://your-service.com/';
```

You also need to include a valid and an invalid SAML 2.0 token on `test/assets/invalidToken.xml` and test/assets/validToken.xml`

```xml

<Assertion ID="_1308c268-38e2-4849-9957-b7babd4a0659" IssueInstant="2014-03-01T04:04:52.919Z" Version="2.0" xmlns="urn:oasis:names:tc:SAML:2.0:assertion"><Issuer>https://your-issuer.com/</Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" /><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" /><ds:Reference URI="#_1308c268-38e2-4849-9957-b7babd4a0659"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" /><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" /></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" /><ds:DigestValue>qJQjAuaj7adyLkl6m3T1oRhtYytu4bebq9JcQObZIu8=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>amPTOSqkEq5ppbCyUgGgm....</Assertion>

```

To run the tests use:

```bash
$ npm test
```

## Contributing

Thanks for taking the time to contribute! Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make will benefit everybody and are appreciated.

Please try to create bug reports that are:

- _Reproducible._ Include steps to reproduce the problem.
- _Specific._ Include as much detail as possible: which version, what environment, etc.
- _Unique._ Do not duplicate existing opened issues.
- _Scoped to a Single Bug._ One bug per report.

## Community

- [Discord](https://discord.gg/uyb7pYt4Pa) (For live discussion with the Community and BoxyHQ team)
- [Twitter](https://twitter.com/BoxyHQ) (Get the news fast)

## Reporting Security Issues

[Responsible Disclosure](SECURITY.md)

## License

MIT
