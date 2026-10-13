import type { ValidateSignatureOptions } from './validateSignature';

export interface SAMLReq {
  ssoUrl?: string;
  entityID: string;
  callbackUrl: string;
  isPassive?: boolean;
  forceAuthn?: boolean;
  identifierFormat?: string;
  providerName?: string;
  signingKey: string;
  publicKey: string;
}

export interface AssertedNameID {
  value: string;
  format?: string;
  nameQualifier?: string;
  spNameQualifier?: string;
}

export interface SAMLProfile {
  // The first <Audience> in document order, or undefined when there is none.
  audience?: string;
  // Every <Audience> of every <AudienceRestriction>, in document order.
  audiences: string[];
  claims: Record<string, any>;
  issuer: string;
  sessionIndex: string;
  // The assertion's Subject NameID exactly as asserted (not trimmed), with its
  // attributes, so a service provider can name the same subject in a
  // LogoutRequest. Undefined when the assertion has no NameID.
  nameId?: AssertedNameID;
  // Signed assertion identifier and validity bound, exposed so callers can
  // implement one-time replay protection keyed by assertionId until notOnOrAfter.
  assertionId?: string;
  notOnOrAfter?: string;
}

// Identifiers from the signed assertion passed to a caller-supplied replay
// validator. The validator returns true when the assertion has already been
// used (a replay) and must be rejected.
export interface AssertionReplayInfo {
  assertionId?: string;
  sessionIndex?: string;
  // The assertion's effective NotOnOrAfter (the absolute Conditions bound when
  // present, otherwise the latest bearer SubjectConfirmationData bound). This is
  // the raw value from the assertion. validateExpiration accepts up to a
  // 10-minute clock-skew tolerance beyond it, so a replay cache should keep the
  // entry until at least notOnOrAfter + 10 minutes to cover the full window in
  // which the assertion can still validate.
  notOnOrAfter?: string;
  inResponseTo?: string;
}

// Options for validate(). Exactly one of publicKey and thumbprint is
// required. The algorithm allowlists and maxSignatureReferences come from
// ValidateSignatureOptions and are passed through to signature verification.
export interface ValidateOptions extends ValidateSignatureOptions {
  // Trusted IdP signing certificate(s): base64 DER or PEM. Several
  // certificates, for rotation, are separated by commas.
  publicKey?: string;
  // Trusted SHA-1 thumbprint(s) of the certificate embedded in the signature's
  // KeyInfo, comma-separated.
  thumbprint?: string;
  // Private key that decrypts an EncryptedAssertion.
  privateKey?: string;
  // Expected audience, or several accepted audiences.
  audience?: string | string[];
  // Require an exact audience match instead of a prefix match.
  strictAudienceValidation?: boolean;
  // ID of the AuthnRequest this response answers (SP-initiated flows). When
  // set, the signed content must carry the same InResponseTo.
  inResponseTo?: string;
  // ACS URL the response was posted to. When set, the signed content must
  // name it (see validateRecipient).
  recipient?: string;
  // Skip the NotBefore/NotOnOrAfter checks.
  bypassExpiration?: boolean;
  // One-time-use check: return true when the assertion was already used.
  assertionReplayValidator?: (info: AssertionReplayInfo) => boolean | Promise<boolean>;
}
