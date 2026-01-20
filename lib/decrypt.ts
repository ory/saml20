import { select } from 'xpath';
import * as xmlenc from 'xml-encryption';
import { parseFromString } from './utils';

const decryptAssertions = (xml: Document, encryptedAssertions: Node[], options) => {
  if (!Array.isArray(encryptedAssertions)) {
    throw new Error('Undefined Encrypted Assertion.');
  }
  if (encryptedAssertions.length !== 1) {
    throw new Error('Multiple Assertion.');
  }

  return xmlenc.decrypt(
    (encryptedAssertions[0] as Node).toString(),
    { key: options.privateKey },
    (err, res) => {
      if (err) {
        throw new Error('Exception of Assertion Decryption.');
      }
      if (!res) {
        throw new Error('Undefined Encryption Assertion.');
      }

      const assertionNode = parseFromString(res);
      xml.documentElement.removeChild(encryptedAssertions[0]);
      // @ts-expect-error missing Node properties are not needed
      xml.documentElement.appendChild(assertionNode!.childNodes[0]);

      return { assertion: xml.toString(), decrypted: true };
    }
  );
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
    return decryptAssertions(xml!, encryptedAssertions, options);
  }

  return { assertion: entireXML, decrypted: false };
};

export { decryptXml };
