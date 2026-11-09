import { select } from 'xpath';
import * as xmlenc from 'xml-encryption';
import { parseFromString, WrapError } from './utils';

type DecryptOptions = { privateKey?: string; reportEncryption?: boolean };

// What the encrypted response shows before decryption, and how many
// assertions it holds once decrypted.
export type EncryptedResponse = {
  dataAlgorithm?: string;
  keyTransportAlgorithm?: string;
  // The root element's ID, and whether it carries a signature itself.
  responseId?: string;
  responseSigned: boolean;
  assertionCount: number;
};

// These lookups mirror xml-encryption's (lib/dom-select.js), so the algorithms
// reported are those of the EncryptedData and EncryptedKey it decrypted with.
const elementChildren = (node: Node | null | undefined, localName: string): Element[] => {
  const found: Element[] = [];
  for (let n = node?.firstChild; n; n = n.nextSibling) {
    if (n.nodeType === n.ELEMENT_NODE && (n as Element).localName === localName) {
      found.push(n as Element);
    }
  }
  return found;
};

// Every element of root's subtree, root included, in document order.
const subtree = (root: Element): Element[] => {
  const found: Element[] = [];
  const stack = [root];
  while (stack.length) {
    const node = stack.pop()!;
    found.push(node);
    const kids: Element[] = [];
    for (let n = node.firstChild; n; n = n.nextSibling) {
      if (n.nodeType === n.ELEMENT_NODE) {
        kids.push(n as Element);
      }
    }
    stack.push(...kids.reverse());
  }
  return found;
};

const encryptedKeyOf = (encryptedData: Element): Element | undefined => {
  const [keyInfo] = elementChildren(encryptedData, 'KeyInfo');
  const [nested] = elementChildren(keyInfo, 'EncryptedKey');
  if (nested) {
    return nested;
  }
  const uri = elementChildren(keyInfo, 'RetrievalMethod')[0]?.getAttribute('URI');
  if (!uri || uri.charAt(0) !== '#' || uri.length < 2) {
    return undefined;
  }
  const parent = encryptedData.parentNode;
  const scope = parent && parent.nodeType === parent.ELEMENT_NODE ? (parent as Element) : encryptedData;
  const matches = subtree(scope).filter(
    (node) => node.localName === 'EncryptedKey' && node.getAttribute('Id') === uri.substring(1)
  );
  return matches.length === 1 ? matches[0] : undefined;
};

const methodOf = (element: Element | undefined): string | undefined =>
  elementChildren(element, 'EncryptionMethod')[0]?.getAttribute('Algorithm') ?? undefined;

const describe = (xml: Document, encryptedAssertion: Element): Omit<EncryptedResponse, 'assertionCount'> => {
  const encryptedData = subtree(encryptedAssertion).find((node) => node.localName === 'EncryptedData');
  return {
    dataAlgorithm: methodOf(encryptedData),
    keyTransportAlgorithm: encryptedData ? methodOf(encryptedKeyOf(encryptedData)) : undefined,
    responseId: xml.documentElement.getAttribute('ID') ?? undefined,
    responseSigned: elementChildren(xml.documentElement, 'Signature').length > 0,
  };
};

const assertion = (xml: Document, encryptedAssertions: Node[], options: DecryptOptions) => {
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
    // A missing key is passed through on purpose: xml-encryption rejects it
    // with "key option is mandatory ...", which becomes the WrapError's inner.
    { key: options.privateKey as string, disallowDecryptionWithInsecureAlgorithm: false },
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

  const described = options.reportEncryption ? describe(xml, encryptedAssertions[0] as Element) : undefined;
  const assertionNode = parseFromString(decrypted);
  xml.documentElement.removeChild(encryptedAssertions[0]);
  // @ts-expect-error missing Node properties are not needed
  xml.documentElement.appendChild(assertionNode!.childNodes[0]);

  const encrypted = described && {
    ...described,
    assertionCount: subtree(xml.documentElement).filter((node) => node.localName === 'Assertion').length,
  };
  return { assertion: xml.toString(), decrypted: true, encrypted };
};
const decryptXml = (
  entireXML: string,
  options: DecryptOptions
): { assertion: string; decrypted: boolean; encrypted?: EncryptedResponse } => {
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
