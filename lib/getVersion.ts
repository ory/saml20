import { getAttribute } from './utils';
import type { XmlValue } from './xml';

const getVersion = (assertion: XmlValue | undefined) => {
  if (!assertion) {
    return null;
  }

  if (getAttribute(assertion, '@.Version') === '2.0') {
    return '2.0';
  }

  return null;
};

export { getVersion };
