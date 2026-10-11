import assert from 'assert';
import * as saml from '../../lib/post';

describe('post.ts', function () {
  it('Should validate creation of post form', function (done) {
    const relayState = 'boxyhq_jackson_17b723c56a2fdc4e94f5e5fa792f89e3';
    const samlRequest =
      'PHNhbWxwOkxvZ291dFJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6c';
    const postUrl = 'https://auth0.com/samlp';

    const form = saml.createPostForm(postUrl, [
      { name: 'RelayState', value: relayState },
      {
        name: 'SAMLRequest',
        value: samlRequest,
      },
    ]);

    assert.strictEqual(form.includes(`<form method="post" action="${encodeURI(postUrl)}">`), true);
    assert.strictEqual(form.includes(`<input type="hidden" name="RelayState" value="${relayState}"/>`), true);
    assert.strictEqual(
      form.includes(`<input type="hidden" name="SAMLRequest" value="${samlRequest}"/>`),
      true
    );
    assert.strictEqual(form.includes(`<input type="submit" value="Continue" />`), true);
    done();
  });
});

describe('createPostForm escaping and structure', function () {
  it('HTML-escapes field values', function () {
    const form = saml.createPostForm('https://sp.example.com/acs', [
      { name: 'RelayState', value: `"><script>alert('x')</script>&` },
    ]);
    assert(
      form.includes(
        '<input type="hidden" name="RelayState" value="&quot;&gt;&lt;script&gt;alert(&#039;x&#039;)&lt;/script&gt;&amp;"/>'
      )
    );
    assert(!form.includes('<script>alert'));
  });

  it('percent-encodes characters in the action URL that would break the attribute', function () {
    const form = saml.createPostForm('https://sp.example.com/acs?a="b"&c=<d>', []);
    assert(form.includes('<form method="post" action="https://sp.example.com/acs?a=%22b%22&c=%3Cd%3E">'));
  });

  it('renders a form with only the submit button when there are no params', function () {
    for (const params of [[], undefined as unknown as { name: string; value: string }[]]) {
      const form = saml.createPostForm('https://sp.example.com/acs', params);
      assert(!form.includes('type="hidden"'));
      assert(form.includes('<input type="submit" value="Continue" />'));
    }
  });

  it('keeps an empty value empty', function () {
    const form = saml.createPostForm('https://sp.example.com/acs', [{ name: 'RelayState', value: '' }]);
    assert(form.includes('<input type="hidden" name="RelayState" value=""/>'));
  });
});

describe('createPostForm only posts to http(s) URLs', function () {
  const params = [{ name: 'SAMLResponse', value: 'PHNhbWw+' }];

  for (const postUrl of [
    'javascript:alert(document.domain)',
    'JavaScript:alert(1)',
    '  javascript:alert(1)',
    'java\tscript:alert(1)',
    'java\nscript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'vbscript:msgbox(1)',
    'file:///etc/passwd',
  ]) {
    it(`rejects ${JSON.stringify(postUrl)}`, function () {
      assert.throws(() => saml.createPostForm(postUrl, params), {
        message: 'Invalid postUrl: only http and https URLs are allowed.',
      });
    });
  }

  for (const postUrl of [
    'https://sp.example.com/acs',
    'http://localhost:5225/api/oauth/saml',
    'HTTPS://SP.EXAMPLE.COM/acs?x=1',
    '/api/oauth/saml',
    '//sp.example.com/acs',
  ]) {
    it(`accepts ${JSON.stringify(postUrl)}`, function () {
      assert(saml.createPostForm(postUrl, params).includes(`action="${encodeURI(postUrl)}"`));
    });
  }

  it('rejects a postUrl that is not a URL at all', function () {
    assert.throws(() => saml.createPostForm('http://[invalid', params), {
      message: 'Invalid postUrl: not a valid URL.',
    });
  });
});

describe('createPostForm escapes field names', function () {
  it('HTML-escapes the name attribute', function () {
    const form = saml.createPostForm('https://sp.example.com/acs', [
      { name: '"><script>alert(1)</script>', value: 'v' },
    ]);
    assert(form.includes('name="&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;"'));
    assert(!form.includes('<script>alert(1)'));
  });
});
