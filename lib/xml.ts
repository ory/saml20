import { parseFromString, setOwn } from './utils';

// What xmlToObject produces: attributes under `attrkey` (a map of strings),
// text under `_`, and child elements under their names as lists, or as single
// values with `collapse`. An element that holds only text is the string.
type XmlValue = string | XmlNode | XmlValue[];
interface XmlNode {
  [name: string]: XmlValue | undefined;
}

type XmlObjectOptions = {
  // Key that holds an element's attributes.
  attrkey: '@' | '$';
  // Store a child element that occurs once as the value itself rather than a
  // one-element list. A single empty child element stays a list ([''])
  // because callers rely on that shape.
  collapse?: boolean;
};

const ELEMENT_NODE = 1;
const TEXT_NODE = 3;
const CDATA_SECTION_NODE = 4;

const prefix = /(?!xmlns)^.*:/;
const stripPrefix = (name: string) => name.replace(prefix, '');

// Namespaces play no part in the result (prefixes are stripped), so a prefix
// the document uses without declaring it is bound to a placeholder rather than
// rejected: producers write xsi:type="xs:string" without declaring either
// prefix, and metadata pasted out of a larger document arrives with md:/ds:
// prefixes and no xmlns attributes at all.
const prefixInUse = /<\/?([A-Za-z_][\w.-]*):|\s([A-Za-z_][\w.-]*):[A-Za-z_][\w.-]*\s*=/g;
const prefixDeclared = /\sxmlns:([A-Za-z_][\w.-]*)\s*=/g;
const undeclaredPrefixes = (xml: string): Record<string, string> => {
  const declared = new Set<string>();
  for (const m of xml.matchAll(prefixDeclared)) {
    declared.add(m[1]);
  }
  const bindings: Record<string, string> = {};
  for (const m of xml.matchAll(prefixInUse)) {
    const name = m[1] ?? m[2];
    // xml: is bound by the XML specification itself and must not be rebound.
    if (name !== 'xml' && name !== 'xmlns' && !declared.has(name)) {
      bindings[name] = `urn:undeclared-prefix:${name}`;
    }
  }
  return bindings;
};

const toObject = (element: Element, options: XmlObjectOptions): XmlValue => {
  const obj: XmlNode = {};
  let text = '';
  let cdata = false;

  if (element.attributes.length > 0) {
    const attrs: Record<string, string> = {};
    for (let i = 0; i < element.attributes.length; i++) {
      const attr = element.attributes[i];
      setOwn(attrs, attr.name, attr.value);
    }
    obj[options.attrkey] = attrs;
  }

  const children = new Map<string, XmlValue[]>();
  for (let node = element.firstChild; node; node = node.nextSibling) {
    if (node.nodeType === ELEMENT_NODE) {
      const name = stripPrefix((node as Element).tagName);
      const values = children.get(name);
      if (values) {
        values.push(toObject(node as Element, options));
      } else {
        children.set(name, [toObject(node as Element, options)]);
      }
    } else if (node.nodeType === TEXT_NODE) {
      text += (node as Text).data;
    } else if (node.nodeType === CDATA_SECTION_NODE) {
      text += (node as CDATASection).data;
      cdata = true;
    }
  }

  const keepText = cdata || !/^\s*$/.test(text);
  if (keepText && Object.keys(obj).length === 0 && children.size === 0) {
    return text;
  }
  if (keepText) {
    obj._ = text;
  }
  for (const [name, values] of children) {
    setOwn(obj, name, options.collapse && values.length === 1 && values[0] ? values[0] : values);
  }
  return Object.keys(obj).length === 0 ? text : obj;
};

// An XML declaration is only allowed as the very first thing in a document,
// but hand-edited metadata often has a newline or a comment before it.
const misplacedDeclaration = /^((?:\s|<!--(?:(?!-->)[\s\S])*-->)+)<\?xml(?=\s)[\s\S]*?\?>/;

// Parses XML with parseFromString, which rejects DTDs and multiple roots, into
// plain objects: tag names without their namespace prefix, attributes under
// `attrkey`, text under `_`, child elements in lists under their name, and a
// string for an element that has only text. Returns null for an empty document.
// The document without its CDATA sections and comments, in a single pass:
// each opener is looked up once, and an unterminated one is left in place for
// the parser to reject.
const withoutCdataAndComments = (xml: string): string => {
  let kept = '';
  let at = 0;
  for (;;) {
    const open = xml.indexOf('<!', at);
    if (open === -1) {
      return kept + xml.slice(at);
    }
    const close = xml.startsWith('<!--', open) ? '-->' : xml.startsWith('<![CDATA[', open) ? ']]>' : '';
    if (close === '') {
      kept += xml.slice(at, open + 2);
      at = open + 2;
      continue;
    }
    const end = xml.indexOf(close, open + 4);
    if (end === -1) {
      return kept + xml.slice(at);
    }
    kept += xml.slice(at, open);
    at = end + close.length;
  }
};

// An & that does not start an entity or character reference. @xmldom/xmldom
// tolerates most of these; the XML specification does not.
const bareAmpersand = /&(?!(?:[A-Za-z_:][\w.:-]*|#\d+|#x[0-9A-Fa-f]+);)/;

const xmlToObject = (xml: string, options: XmlObjectOptions): XmlNode | null => {
  xml = xml.replace(/^\uFEFF/, '').replace(misplacedDeclaration, '$1');
  if (xml.trim() === '') {
    return null;
  }
  if (bareAmpersand.test(withoutCdataAndComments(xml))) {
    throw new Error('Invalid XML.');
  }
  const root = parseFromString(xml, undeclaredPrefixes(xml)).documentElement as unknown as Element;
  const result: XmlNode = {};
  setOwn(result, stripPrefix(root.tagName), toObject(root, options));
  return result;
};

export { xmlToObject };
export type { XmlObjectOptions, XmlNode, XmlValue };
