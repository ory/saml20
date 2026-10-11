import { select } from 'xpath';
import * as xmlenc from 'xml-encryption';
import { parseFromString, WrapError } from './utils';

const assertion = (xml: Document, encryptedAssertions: Node[], options) => {
  if (!Array.isArray(encryptedAssertions)) {
    throw new Error('Undefined Encrypted Assertion.');
  }
  if (encryptedAssertions.length !== 1) {
    throw new Error('Multiple Assertion.');
  }

  // xml-encryption invokes the callback synchronously, but from inside its own
  // try/catch: anything thrown in the callback is caught and fed back into the
  // callback as a decryption error. So only record the outcome here and do the
  // follow-up work outside, where its errors reach the caller unchanged.
  let decryptError: Error | null | undefined;
  let decrypted: string | undefined;
  let called = false;
  xmlenc.decrypt(
    encryptedAssertions[0].toString(),
    { key: options.privateKey, disallowDecryptionWithInsecureAlgorithm: false },
    (err, res) => {
      called = true;
      decryptError = err;
      decrypted = res;
    }
  );

  if (!called) {
    throw new Error('Exception of Assertion Decryption.');
  }
  if (decryptError) {
    const error = new WrapError('Exception of Assertion Decryption.');
    error.inner = decryptError;
    throw error;
  }
  if (!decrypted) {
    throw new Error('Undefined Encryption Assertion.');
  }

  const assertionNode = parseFromString(decrypted);
  xml.documentElement.removeChild(encryptedAssertions[0]);
  // @ts-expect-error missing Node properties are not needed
  xml.documentElement.appendChild(assertionNode!.childNodes[0]);

  return { assertion: xml.toString(), decrypted: true };
};
const decryptXml = (entireXML: string, options): { assertion: string; decrypted: boolean } => {
  if (!entireXML) {
    throw new Error('Undefined Assertion.');
  }

  const xml = parseFromString(entireXML);

  const encryptedAssertions = select(
    "/*[contains(local-name(), 'Response')]/*[local-name(.)='EncryptedAssertion']",
    // @ts-expect-error missing Node properties are not needed
    xml!
  ) as Node[];

  if (encryptedAssertions.length >= 1) {
    // @ts-expect-error missing Node properties are not needed
    return assertion(xml!, encryptedAssertions, options);
  }

  return { assertion: entireXML, decrypted: false };
};

export { decryptXml };
