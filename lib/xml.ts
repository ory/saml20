import { create } from 'xmlbuilder2';
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
// An & that does not start an entity or character reference, outside CDATA
// sections and comments. @xmldom/xmldom tolerates most of these; the XML
// specification does not.
const cdataOrComment = /<!\[CDATA\[[\s\S]*?\]\]>|<!--[\s\S]*?-->/g;
const bareAmpersand = /&(?!(?:[A-Za-z_:][\w.:-]*|#\d+|#x[0-9A-Fa-f]+);)/;

const xmlToObject = (xml: string, options: XmlObjectOptions): XmlNode | null => {
  xml = xml.replace(/^\uFEFF/, '').replace(misplacedDeclaration, '$1');
  if (xml.trim() === '') {
    return null;
  }
  if (bareAmpersand.test(xml.replace(cdataOrComment, ''))) {
    throw new Error('Invalid XML.');
  }
  const root = parseFromString(xml, undeclaredPrefixes(xml)).documentElement as unknown as Element;
  const result: XmlNode = {};
  setOwn(result, stripPrefix(root.tagName), toObject(root, options));
  return result;
};

type BuildOptions = {
  encoding?: string;
  standalone?: boolean;
  pretty?: boolean;
};

// Characters XML 1.0 cannot carry, including a lone surrogate half.
const illegalChar =
  // oxlint-disable-next-line no-control-regex -- the control characters are the point
  /[\0-\x08\x0B\f\x0E-\x1F\uFFFE\uFFFF]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?:[^\uD800-\uDBFF]|^)[\uDC00-\uDFFF]/;

// Serializes nodes in the xmlbuilder2 object convention (`@name` attributes,
// `#text`, lists for repeated elements) with an XML declaration. A carriage
// return, and a tab or line feed in an attribute value, are written as
// character references: a receiving parser normalizes the literal characters
// to a line feed or a space.
const buildXml = (nodes: object, { pretty, ...declaration }: BuildOptions = {}): string => {
  const xml = create({ version: '1.0', ...declaration }, nodes).end({ prettyPrint: pretty });
  if (illegalChar.test(xml)) {
    throw new Error('Invalid character in XML.');
  }
  // Within a tag, whitespace other than the single space between attributes
  // can only come from an attribute value; xmlbuilder2 escapes > there.
  return xml
    .replace(/<[^>]*>/g, (tag) => tag.replace(/\t/g, '&#x9;').replace(/\n/g, '&#xA;'))
    .replace(/\r/g, '&#xD;');
};

export { xmlToObject, buildXml };
export type { XmlObjectOptions, XmlNode, XmlValue };
