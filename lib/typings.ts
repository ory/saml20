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

export interface SAMLProfile {
  audience: string;
  claims: Record<string, any>;
  issuer: string;
  sessionIndex: string;
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
