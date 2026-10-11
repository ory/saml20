const escapeHtml = (unsafeHtml: string) => {
  return unsafeHtml
    ? unsafeHtml
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;')
    : unsafeHtml;
};

// The form auto-submits on load, so its action must not be a script URL:
// `javascript:` (or `data:`/`vbscript:`) would run in the page's origin. The
// postUrl usually comes from SP or IdP metadata, which a tenant can control.
// Parse it the way a browser would (WHATWG URL, which also strips the leading
// whitespace and embedded tabs/newlines used to disguise a scheme), resolving
// relative URLs against a dummy http base so they stay allowed.
const assertHttpUrl = (postUrl: string) => {
  let protocol: string;
  try {
    protocol = new URL(postUrl, 'http://relative.invalid').protocol;
  } catch {
    throw new Error('Invalid postUrl: not a valid URL.');
  }
  if (protocol !== 'http:' && protocol !== 'https:') {
    throw new Error('Invalid postUrl: only http and https URLs are allowed.');
  }
};

const createPostForm = (postUrl: string, params: { name: string; value: string }[]) => {
  assertHttpUrl(postUrl);

  const parr = (params || []).map(({ name, value }) => {
    return `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}"/>`;
  });

  const formElements = [
    '<!DOCTYPE html>',
    '<html>',
    '<head>',
    '<meta charset="utf-8">',
    '<meta http-equiv="x-ua-compatible" content="ie=edge">',
    '</head>',
    '<body onload="document.forms[0].submit()">',
    '<noscript>',
    '<p>Note: Since your browser does not support JavaScript, you must press the Continue button once to proceed.</p>',
    '</noscript>',
    `<form method="post" action="${encodeURI(postUrl)}">`,
  ]
    .concat(...parr)
    .concat(
      ...[
        '<input type="submit" value="Continue" />',
        '</form>',
        '<script>document.forms[0].style.display="none";</script>',
        '</body>',
        '</html>',
      ]
    );

  return formElements.join('\r\n');
};

export { createPostForm };
