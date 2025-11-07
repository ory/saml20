import { certToPEM, hasValidSignature, validateSignature } from '../../lib/validateSignature';
import xmlbuilder from 'xmlbuilder';

import crypto from 'crypto';
import fs from 'fs';
import { sign } from '../../lib/sign';
import assert from 'assert';

const ssoUrl =
  'https://dev-20901260.okta.com/app/dev-20901260_jacksondemo5225_1/exk3wth7ss1TKnAN15d7/sso/saml';
const entityID = 'https://saml.boxyhq.com';
const callbackUrl = 'http://localhost:5225/api/oauth/saml';

const signingKey =
  '-----BEGIN RSA PRIVATE KEY-----\r\nMIIEogIBAAKCAQEA9Zc8/xenV4a6pnwMpdHbb1DEluFMh1bBdKWw1YFWzV1mxKsl\r\n6zcXY5MubZI1c5583eAq1M7axJVE+9J+h5m6HxwyY0K0qAypnxeLrXZj4t7dMrNL\r\nVk92PUWoUJMBTK02TqnjkpR7Ki8bWHCHYSjwuQfUiTNajFOEHqsdEABSJ9iWzWtZ\r\n3qpd3ORpm35zLqAQGkoyU2Y/ky7dQdklbCFvrDFjgsRx5gEtsUolgag5wprEyOXj\r\n2np7/ypN7FdKaLxXoYB3C5iEC7MIVLGQu/pOLxFPfN0F6edBUPTKUvN9H7iZCaaP\r\n53/276a3XWRJaLmRnl2vsxsV9aHDHFbP8Uq8OwIDAQABAoIBAAg4RyTclE/EJSQk\r\nW8IDC56mq+XG5apT94ahcxE6Un7uJN3pQowkXGaLSw8EyUA06kX81kIoKD9TJatu\r\nCKkeNpIK/g6/cU98mQLHpXepUj+KKQok4R0i7LixR6hmuzDnTT2FxyWlTZgEWpxz\r\nq7xPQ/tVbUIoU1wGAZKLNJ5P/G/z6ZJ6vin72FR/IQamVPq0bpPsXfzOGZVcrd2h\r\nOT25+s466rCjCxRclS2O0Vz+9U5LsfauSeTNPZS/sIeX32GPXxpiej3742sUE1kF\r\n0NyrFjaFRo0IGE5LfNq9Bm8D4z141AV2UBic+r9X/TwPy0WgA2AAh/VM93PV2/fS\r\nu4rgIkUCgYEA/8mgsFXaDoq1P7MQ8OuAMtA2bzYZOsS8szzkEcgqDaEiLZ/s0J/S\r\nbOm09jssfWvKI4peEvNrBqOUR0z4XSfrgiaDwghqQnmfzrzEP/J7irUBwe+gkVFM\r\n0KboFyrFA+Uip+By+dF/eKq0IF9F8B6ldGcz8eAh4tO53rNCLAUE13UCgYEA9ctx\r\nbACsF/YbJUPxm5VqDtlX3ziZtZDaAhGrCk9Ewccq4TU2FIjrwf0YFRiUU3JqmK4/\r\n20dyJiwcyqjk2kvBwm1Spec2upnlMS3R5w0TSfiEBQZ6rhZ/WKd+/uVjBVqOTGSg\r\nHksYb0r9JI3Xd8J9CPb7/xVymve82YkJCyOSfu8CgYBpQDctt/XlG/BeyLkE2XLD\r\n9ecgNduF0iRvgHO8WWfsecxNh8vzQIBern/2/fxdk3f2zd3N4Hm+nprKCAL+mgmP\r\nYXe/5KSMu+0lLYl3YrixJ7AUdBzXDuQTy0ofFktBQgzTlUjaQPk51swNsgZeOs4M\r\nKtc2BOsMoeCOoaZt5JbMbQKBgELg4DOq2yiJ5kj1e8ABn6H6sVYjaG9mwmrds9RS\r\nTTsMnjY47EYaG0vlObBDx9gMwcRZZTac8gpA5nSeD+b1xfrJFDvf9ZxAU4RWG07q\r\n19zAqetUH/1OUcgliwCAGblTMnTGzGpxtGxT0x0nGwGTAcJ2sYpuo4hW8COgjb1i\r\nKHIxAoGAM9hBQv0POGsfvj7zuoqbpMbIJDmjV8Vb/l1jOTd6JlBQKlB82Xg174Ig\r\nQUvbmVy76hnIlToipX6XfEYmwCOLcYCDCQXRvBIWWdtUcxN3OBZ4DjgRNiZqxdSS\r\nf1kqjFv27Y49yzyNFQQ4OaVzZkFvGuiO8glLr8MtViFh55DhPTI=\r\n-----END RSA PRIVATE KEY-----\r\n';
const publicKey =
  '-----BEGIN CERTIFICATE-----\r\nMIICvzCCAaegAwIBAgIBATANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDEwlPcnkg\r\nUG9saXMwIBcNMjUxMDI0MTMyNDI5WhgPMjA1NTEwMjQxMzI0MjlaMBQxEjAQBgNV\r\nBAMTCU9yeSBQb2xpczCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPWX\r\nPP8Xp1eGuqZ8DKXR229QxJbhTIdWwXSlsNWBVs1dZsSrJes3F2OTLm2SNXOefN3g\r\nKtTO2sSVRPvSfoeZuh8cMmNCtKgMqZ8Xi612Y+Le3TKzS1ZPdj1FqFCTAUytNk6p\r\n45KUeyovG1hwh2Eo8LkH1IkzWoxThB6rHRAAUifYls1rWd6qXdzkaZt+cy6gEBpK\r\nMlNmP5Mu3UHZJWwhb6wxY4LEceYBLbFKJYGoOcKaxMjl49p6e/8qTexXSmi8V6GA\r\ndwuYhAuzCFSxkLv6Ti8RT3zdBennQVD0ylLzfR+4mQmmj+d/9u+mt11kSWi5kZ5d\r\nr7MbFfWhwxxWz/FKvDsCAwEAAaMaMBgwCQYDVR0TBAIwADALBgNVHQ8EBAMCB4Aw\r\nDQYJKoZIhvcNAQELBQADggEBAO69pv9kFbYZEIsWy+Ze2oQ4eZ9O+R9i/rjTEAJ0\r\nmFyNYIBva/9nZsWV8NH5TRCyrnn/PQwHoQRD9LrcmGAOJbiF6J600GNGgMjwaS2T\r\n0e0Nn7BN/XkeLrEhwRC1uo/TWCgtAws5G3l9deSkdRT/PetVeXxpu4X+D3vnO+3c\r\n/aSDlkbce0gbYjhjCpKpckjMXrZm5HQIr8ZwuJsKAtVzo0YkvZDoU5luIjuvvpkG\r\nYqaSa3mnOw6T1usN2APQl7ahRZKuBszNszunKoWMv7+bYB18Me8myesl3ylsw2SJ\r\n6jjHwmySQ5yZlDrhlqCSRlyyYsyzkFxOXimmRW+l/Ta6zkw=\r\n-----END CERTIFICATE-----\r\n';
const idPrefix = '_';
const authnXPath =
  '/*[local-name(.)="AuthnRequest" and namespace-uri(.)="urn:oasis:names:tc:SAML:2.0:protocol"]';
const identifierFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';
const providerName = 'BoxyHQ';

const validResponseSigned_noX509 = fs
  .readFileSync('./test/assets/saml20.validResponseSigned-noX509.xml')
  .toString();

const singlePublicKey = `MIIDczCCAlugAwIBAgIUE4RU7Pwiw58ZifnjQOXVg6ytNWowDQYJKoZIhvcNAQEL
  BQAwSDELMAkGA1UEBhMCSU4xEzARBgNVBAgMClNvbWUtU3RhdGUxDzANBgNVBAoM
  BkJveHlIUTETMBEGA1UEAwwKYm94eWhxLmNvbTAgFw0yMzExMTIxMDQ1MzdaGA8z
  MDIzMDMxNTEwNDUzN1owSDELMAkGA1UEBhMCSU4xEzARBgNVBAgMClNvbWUtU3Rh
  dGUxDzANBgNVBAoMBkJveHlIUTETMBEGA1UEAwwKYm94eWhxLmNvbTCCASIwDQYJ
  KoZIhvcNAQEBBQADggEPADCCAQoCggEBAMkwF6oPPd3Fn3AXC8K8h+q0uRgRoJim
  HASKmwzXZZjqb2DN0isLNvbLlcB3mTmfQMhKH4yLPE5PHoDJ83olgILkB6Y3txgG
  QJ48sIEeYiGCs+le4UnD44oL04fQCpkIImcFiHM/tr9kSnQsjF7tLn6GVZJKUU56
  84mrOACHr3LDZkypLxjiYMoM9aojS3yw97AIJSyhmkpowuqdtmK/T5o4pnTNgXTB
  XYPoGx/6aqoFVxAjh7ZuUzeHAMGHZlxT0e6K7nKSPoFKDbfDQoAwbq6B1BRNklSX
  4dz6MkmQAGqMnKBWNbiF2MAnt5dvIXInlafQ3Ypbw/bJ4uHw6L+RjGcCAwEAAaNT
  MFEwHQYDVR0OBBYEFHyOsXZSwmNqljrM6LmWFWr0nUsvMB8GA1UdIwQYMBaAFHyO
  sXZSwmNqljrM6LmWFWr0nUsvMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
  BQADggEBALFfujo7fMqszjEg7Gla3FthO82/D+7mFKSGt04ZJfxlwuujTpI8u04g
  LWNFV6uHLNNlxesdd1r9JtlXAHN4pDk06TEidz1oOO1rBWVDBajrO1wME99EqOAj
  Q64SOFhkpw9Yd5L47SnxC3rQPsgeol+BJwosXcPG4OXjK5JisQGdakEJh8GLnE5u
  7QK5eFf84Qro6HthD+YsA0pPFDzh4TtSpm/yYDYRvKAfqh4a2uqwJDHJ8oxz5d37
  4eXJ/Zy78JiYM4PUnPMKABsqcUZv5vsuV5HPO4ODtcGFRY1EoSXcMxz0jkUipe+Z
  wmF8r5aO5sSGd+KOi2O/ja9VV4UzGD8=`;

const singlePublicKeyNotUsedToSign = `MIIDczCCAlugAwIBAgIUOJZExQRTahl1DA9raMp0G6vCkHwwDQYJKoZIhvcNAQEL
BQAwSDELMAkGA1UEBhMCSU4xEzARBgNVBAgMClNvbWUtU3RhdGUxDzANBgNVBAoM
BkJveHlIUTETMBEGA1UEAwwKYm94eWhxLmNvbTAgFw0yMzExMTIxMTEwMDNaGA8z
MDIzMDMxNTExMTAwM1owSDELMAkGA1UEBhMCSU4xEzARBgNVBAgMClNvbWUtU3Rh
dGUxDzANBgNVBAoMBkJveHlIUTETMBEGA1UEAwwKYm94eWhxLmNvbTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAMWZyyDK9/I3Pic2TCnckbdVG/PIknyk
YszbA+87q/MWlBA/vX2DogUw6UapZ07r6kxYRyMg/7VlJNP5rZXowv0LEpfpdAth
8O7TomyEbwhl4u/8CcCbRvihkQtr1DFlHBYVSC7znkpeS1iYwfsDKhZc5NHmplG5
+dERS71rtWqxb9hySPcX2CUJOvLjeC6uhTux5ers33963qnQzEsOuBRvcUT6TU7Y
4WjzMycAjtsfT9r5y5Lhv9DpsIpVSRQ1MCLHCAeD1BerUZaebTonbsEA1EHk4vux
FmjvlrNp4hh2zrtGt7yZO2cAzcNmloq+JmZ/7Yeb5CAhCaXIXFBBsh0CAwEAAaNT
MFEwHQYDVR0OBBYEFLb5bLFbrOVXMAT5YnsQLSkPL3AyMB8GA1UdIwQYMBaAFLb5
bLFbrOVXMAT5YnsQLSkPL3AyMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBAKJFOBEouNp2AJicbA3Lmb4vVJfwP9h8LGqHV3TZHhlEblmBQNEoLyLO
z7XhIy1/5LyGb7b/o0LAoC1RxH/6GiHcIKt4/DS7dOfrpcNkHXAUHVFZ1LfFtBHc
zIZTXKWNiFLqz3nTaKS3dqmnZMsoWDuRpE4kwR5tT+zB492nnfH7XGICQDojQ1DN
NDvfSxFNmjcEuabxM9VGdsX6xOiClZBJwJBixj74EYPeeVOPbOEQfQZchX8xB3u5
2knHSNiamr0NJ4GA44hIoCADW2G6W2+A4gFNnA6UYFlaijMWqb/XSNlbkYZD6OkG
9Xa5bTycscrxF6+S3n5z2yGft52wBe4=`;

const multiPublicKey = `MIIDczCCAlugAwIBAgIUE4RU7Pwiw58ZifnjQOXVg6ytNWowDQYJKoZIhvcNAQEL
BQAwSDELMAkGA1UEBhMCSU4xEzARBgNVBAgMClNvbWUtU3RhdGUxDzANBgNVBAoM
BkJveHlIUTETMBEGA1UEAwwKYm94eWhxLmNvbTAgFw0yMzExMTIxMDQ1MzdaGA8z
MDIzMDMxNTEwNDUzN1owSDELMAkGA1UEBhMCSU4xEzARBgNVBAgMClNvbWUtU3Rh
dGUxDzANBgNVBAoMBkJveHlIUTETMBEGA1UEAwwKYm94eWhxLmNvbTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAMkwF6oPPd3Fn3AXC8K8h+q0uRgRoJim
HASKmwzXZZjqb2DN0isLNvbLlcB3mTmfQMhKH4yLPE5PHoDJ83olgILkB6Y3txgG
QJ48sIEeYiGCs+le4UnD44oL04fQCpkIImcFiHM/tr9kSnQsjF7tLn6GVZJKUU56
84mrOACHr3LDZkypLxjiYMoM9aojS3yw97AIJSyhmkpowuqdtmK/T5o4pnTNgXTB
XYPoGx/6aqoFVxAjh7ZuUzeHAMGHZlxT0e6K7nKSPoFKDbfDQoAwbq6B1BRNklSX
4dz6MkmQAGqMnKBWNbiF2MAnt5dvIXInlafQ3Ypbw/bJ4uHw6L+RjGcCAwEAAaNT
MFEwHQYDVR0OBBYEFHyOsXZSwmNqljrM6LmWFWr0nUsvMB8GA1UdIwQYMBaAFHyO
sXZSwmNqljrM6LmWFWr0nUsvMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBALFfujo7fMqszjEg7Gla3FthO82/D+7mFKSGt04ZJfxlwuujTpI8u04g
LWNFV6uHLNNlxesdd1r9JtlXAHN4pDk06TEidz1oOO1rBWVDBajrO1wME99EqOAj
Q64SOFhkpw9Yd5L47SnxC3rQPsgeol+BJwosXcPG4OXjK5JisQGdakEJh8GLnE5u
7QK5eFf84Qro6HthD+YsA0pPFDzh4TtSpm/yYDYRvKAfqh4a2uqwJDHJ8oxz5d37
4eXJ/Zy78JiYM4PUnPMKABsqcUZv5vsuV5HPO4ODtcGFRY1EoSXcMxz0jkUipe+Z
wmF8r5aO5sSGd+KOi2O/ja9VV4UzGD8=,MIIDczCCAlugAwIBAgIUOJZExQRTahl1DA9raMp0G6vCkHwwDQYJKoZIhvcNAQEL
BQAwSDELMAkGA1UEBhMCSU4xEzARBgNVBAgMClNvbWUtU3RhdGUxDzANBgNVBAoM
BkJveHlIUTETMBEGA1UEAwwKYm94eWhxLmNvbTAgFw0yMzExMTIxMTEwMDNaGA8z
MDIzMDMxNTExMTAwM1owSDELMAkGA1UEBhMCSU4xEzARBgNVBAgMClNvbWUtU3Rh
dGUxDzANBgNVBAoMBkJveHlIUTETMBEGA1UEAwwKYm94eWhxLmNvbTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAMWZyyDK9/I3Pic2TCnckbdVG/PIknyk
YszbA+87q/MWlBA/vX2DogUw6UapZ07r6kxYRyMg/7VlJNP5rZXowv0LEpfpdAth
8O7TomyEbwhl4u/8CcCbRvihkQtr1DFlHBYVSC7znkpeS1iYwfsDKhZc5NHmplG5
+dERS71rtWqxb9hySPcX2CUJOvLjeC6uhTux5ers33963qnQzEsOuBRvcUT6TU7Y
4WjzMycAjtsfT9r5y5Lhv9DpsIpVSRQ1MCLHCAeD1BerUZaebTonbsEA1EHk4vux
FmjvlrNp4hh2zrtGt7yZO2cAzcNmloq+JmZ/7Yeb5CAhCaXIXFBBsh0CAwEAAaNT
MFEwHQYDVR0OBBYEFLb5bLFbrOVXMAT5YnsQLSkPL3AyMB8GA1UdIwQYMBaAFLb5
bLFbrOVXMAT5YnsQLSkPL3AyMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBAKJFOBEouNp2AJicbA3Lmb4vVJfwP9h8LGqHV3TZHhlEblmBQNEoLyLO
z7XhIy1/5LyGb7b/o0LAoC1RxH/6GiHcIKt4/DS7dOfrpcNkHXAUHVFZ1LfFtBHc
zIZTXKWNiFLqz3nTaKS3dqmnZMsoWDuRpE4kwR5tT+zB492nnfH7XGICQDojQ1DN
NDvfSxFNmjcEuabxM9VGdsX6xOiClZBJwJBixj74EYPeeVOPbOEQfQZchX8xB3u5
2knHSNiamr0NJ4GA44hIoCADW2G6W2+A4gFNnA6UYFlaijMWqb/XSNlbkYZD6OkG
9Xa5bTycscrxF6+S3n5z2yGft52wBe4=`;

const multiPublicKeyOrderChanged = `MIIDczCCAlugAwIBAgIUOJZExQRTahl1DA9raMp0G6vCkHwwDQYJKoZIhvcNAQEL
BQAwSDELMAkGA1UEBhMCSU4xEzARBgNVBAgMClNvbWUtU3RhdGUxDzANBgNVBAoM
BkJveHlIUTETMBEGA1UEAwwKYm94eWhxLmNvbTAgFw0yMzExMTIxMTEwMDNaGA8z
MDIzMDMxNTExMTAwM1owSDELMAkGA1UEBhMCSU4xEzARBgNVBAgMClNvbWUtU3Rh
dGUxDzANBgNVBAoMBkJveHlIUTETMBEGA1UEAwwKYm94eWhxLmNvbTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAMWZyyDK9/I3Pic2TCnckbdVG/PIknyk
YszbA+87q/MWlBA/vX2DogUw6UapZ07r6kxYRyMg/7VlJNP5rZXowv0LEpfpdAth
8O7TomyEbwhl4u/8CcCbRvihkQtr1DFlHBYVSC7znkpeS1iYwfsDKhZc5NHmplG5
+dERS71rtWqxb9hySPcX2CUJOvLjeC6uhTux5ers33963qnQzEsOuBRvcUT6TU7Y
4WjzMycAjtsfT9r5y5Lhv9DpsIpVSRQ1MCLHCAeD1BerUZaebTonbsEA1EHk4vux
FmjvlrNp4hh2zrtGt7yZO2cAzcNmloq+JmZ/7Yeb5CAhCaXIXFBBsh0CAwEAAaNT
MFEwHQYDVR0OBBYEFLb5bLFbrOVXMAT5YnsQLSkPL3AyMB8GA1UdIwQYMBaAFLb5
bLFbrOVXMAT5YnsQLSkPL3AyMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBAKJFOBEouNp2AJicbA3Lmb4vVJfwP9h8LGqHV3TZHhlEblmBQNEoLyLO
z7XhIy1/5LyGb7b/o0LAoC1RxH/6GiHcIKt4/DS7dOfrpcNkHXAUHVFZ1LfFtBHc
zIZTXKWNiFLqz3nTaKS3dqmnZMsoWDuRpE4kwR5tT+zB492nnfH7XGICQDojQ1DN
NDvfSxFNmjcEuabxM9VGdsX6xOiClZBJwJBixj74EYPeeVOPbOEQfQZchX8xB3u5
2knHSNiamr0NJ4GA44hIoCADW2G6W2+A4gFNnA6UYFlaijMWqb/XSNlbkYZD6OkG
9Xa5bTycscrxF6+S3n5z2yGft52wBe4=,MIIDczCCAlugAwIBAgIUE4RU7Pwiw58ZifnjQOXVg6ytNWowDQYJKoZIhvcNAQEL
BQAwSDELMAkGA1UEBhMCSU4xEzARBgNVBAgMClNvbWUtU3RhdGUxDzANBgNVBAoM
BkJveHlIUTETMBEGA1UEAwwKYm94eWhxLmNvbTAgFw0yMzExMTIxMDQ1MzdaGA8z
MDIzMDMxNTEwNDUzN1owSDELMAkGA1UEBhMCSU4xEzARBgNVBAgMClNvbWUtU3Rh
dGUxDzANBgNVBAoMBkJveHlIUTETMBEGA1UEAwwKYm94eWhxLmNvbTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAMkwF6oPPd3Fn3AXC8K8h+q0uRgRoJim
HASKmwzXZZjqb2DN0isLNvbLlcB3mTmfQMhKH4yLPE5PHoDJ83olgILkB6Y3txgG
QJ48sIEeYiGCs+le4UnD44oL04fQCpkIImcFiHM/tr9kSnQsjF7tLn6GVZJKUU56
84mrOACHr3LDZkypLxjiYMoM9aojS3yw97AIJSyhmkpowuqdtmK/T5o4pnTNgXTB
XYPoGx/6aqoFVxAjh7ZuUzeHAMGHZlxT0e6K7nKSPoFKDbfDQoAwbq6B1BRNklSX
4dz6MkmQAGqMnKBWNbiF2MAnt5dvIXInlafQ3Ypbw/bJ4uHw6L+RjGcCAwEAAaNT
MFEwHQYDVR0OBBYEFHyOsXZSwmNqljrM6LmWFWr0nUsvMB8GA1UdIwQYMBaAFHyO
sXZSwmNqljrM6LmWFWr0nUsvMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBALFfujo7fMqszjEg7Gla3FthO82/D+7mFKSGt04ZJfxlwuujTpI8u04g
LWNFV6uHLNNlxesdd1r9JtlXAHN4pDk06TEidz1oOO1rBWVDBajrO1wME99EqOAj
Q64SOFhkpw9Yd5L47SnxC3rQPsgeol+BJwosXcPG4OXjK5JisQGdakEJh8GLnE5u
7QK5eFf84Qro6HthD+YsA0pPFDzh4TtSpm/yYDYRvKAfqh4a2uqwJDHJ8oxz5d37
4eXJ/Zy78JiYM4PUnPMKABsqcUZv5vsuV5HPO4ODtcGFRY1EoSXcMxz0jkUipe+Z
wmF8r5aO5sSGd+KOi2O/ja9VV4UzGD8=`;

const wrongMultiPublicKey = `MIIDczCCAlugAwIBAgIUOJZExQRTahl1DA9raMp0G6vCkHwwDQYJKoZIhvcNAQEL
BQAwSDELMAkGA1UEBhMCSU4xEzARBgNVBAgMClNvbWUtU3RhdGUxDzANBgNVBAoM
BkJveHlIUTETMBEGA1UEAwwKYm94eWhxLmNvbTAgFw0yMzExMTIxMTEwMDNaGA8z
MDIzMDMxNTExMTAwM1owSDELMAkGA1UEBhMCSU4xEzARBgNVBAgMClNvbWUtU3Rh
dGUxDzANBgNVBAoMBkJveHlIUTETMBEGA1UEAwwKYm94eWhxLmNvbTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAMWZyyDK9/I3Pic2TCnckbdVG/PIknyk
YszbA+87q/MWlBA/vX2DogUw6UapZ07r6kxYRyMg/7VlJNP5rZXowv0LEpfpdAth
8O7TomyEbwhl4u/8CcCbRvihkQtr1DFlHBYVSC7znkpeS1iYwfsDKhZc5NHmplG5
+dERS71rtWqxb9hySPcX2CUJOvLjeC6uhTux5ers33963qnQzEsOuBRvcUT6TU7Y
4WjzMycAjtsfT9r5y5Lhv9DpsIpVSRQ1MCLHCAeD1BerUZaebTonbsEA1EHk4vux
FmjvlrNp4hh2zrtGt7yZO2cAzcNmloq+JmZ/7Yeb5CAhCaXIXFBBsh0CAwEAAaNT
MFEwHQYDVR0OBBYEFLb5bLFbrOVXMAT5YnsQLSkPL3AyMB8GA1UdIwQYMBaAFLb5
bLFbrOVXMAT5YnsQLSkPL3AyMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBAKJFOBEouNp2AJicbA3Lmb4vVJfwP9h8LGqHV3TZHhlEblmBQNEoLyLO
z7XhIy1/5LyGb7b/o0LAoC1RxH/6GiHcIKt4/DS7dOfrpcNkHXAUHVFZ1LfFtBHc
zIZTXKWNiFLqz3nTaKS3dqmnZMsoWDuRpE4kwR5tT+zB492nnfH7XGICQDojQ1DN
NDvfSxFNmjcEuabxM9VGdsX6xOiClZBJwJBixj74EYPeeVOPbOEQfQZchX8xB3u5
2knHSNiamr0NJ4GA44hIoCADW2G6W2+A4gFNnA6UYFlaijMWqb/XSNlbkYZD6OkG
9Xa5bTycscrxF6+S3n5z2yGft52wBe4=,MIIDczCCAlugAwIBAgIUOJZExQRTahl1DA9raMp0G6vCkHwwDQYJKoZIhvcNAQEL
BQAwSDELMAkGA1UEBhMCSU4xEzARBgNVBAgMClNvbWUtU3RhdGUxDzANBgNVBAoM
BkJveHlIUTETMBEGA1UEAwwKYm94eWhxLmNvbTAgFw0yMzExMTIxMTEwMDNaGA8z
MDIzMDMxNTExMTAwM1owSDELMAkGA1UEBhMCSU4xEzARBgNVBAgMClNvbWUtU3Rh
dGUxDzANBgNVBAoMBkJveHlIUTETMBEGA1UEAwwKYm94eWhxLmNvbTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAMWZyyDK9/I3Pic2TCnckbdVG/PIknyk
YszbA+87q/MWlBA/vX2DogUw6UapZ07r6kxYRyMg/7VlJNP5rZXowv0LEpfpdAth
8O7TomyEbwhl4u/8CcCbRvihkQtr1DFlHBYVSC7znkpeS1iYwfsDKhZc5NHmplG5
+dERS71rtWqxb9hySPcX2CUJOvLjeC6uhTux5ers33963qnQzEsOuBRvcUT6TU7Y
4WjzMycAjtsfT9r5y5Lhv9DpsIpVSRQ1MCLHCAeD1BerUZaebTonbsEA1EHk4vux
FmjvlrNp4hh2zrtGt7yZO2cAzcNmloq+JmZ/7Yeb5CAhCaXIXFBBsh0CAwEAAaNT
MFEwHQYDVR0OBBYEFLb5bLFbrOVXMAT5YnsQLSkPL3AyMB8GA1UdIwQYMBaAFLb5
bLFbrOVXMAT5YnsQLSkPL3AyMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBAKJFOBEouNp2AJicbA3Lmb4vVJfwP9h8LGqHV3TZHhlEblmBQNEoLyLO
z7XhIy1/5LyGb7b/o0LAoC1RxH/6GiHcIKt4/DS7dOfrpcNkHXAUHVFZ1LfFtBHc
zIZTXKWNiFLqz3nTaKS3dqmnZMsoWDuRpE4kwR5tT+zB492nnfH7XGICQDojQ1DN
NDvfSxFNmjcEuabxM9VGdsX6xOiClZBJwJBixj74EYPeeVOPbOEQfQZchX8xB3u5
2knHSNiamr0NJ4GA44hIoCADW2G6W2+A4gFNnA6UYFlaijMWqb/XSNlbkYZD6OkG
9Xa5bTycscrxF6+S3n5z2yGft52wBe4=`;

function generateXML() {
  const id = idPrefix + crypto.randomBytes(10).toString('hex');
  const date = new Date().toISOString();

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const samlReq: Record<string, any> = {
    'samlp:AuthnRequest': {
      '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
      '@ID': id,
      '@Version': '2.0',
      '@IssueInstant': date,
      '@ProtocolBinding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
      '@Destination': ssoUrl,
      'saml:Issuer': {
        '@xmlns:saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
        '#text': entityID,
      },
    },
  };

  // if (isPassive) samlReq['samlp:AuthnRequest']['@IsPassive'] = true;

  // if (forceAuthn) {
  //   samlReq['samlp:AuthnRequest']['@ForceAuthn'] = true;
  // }

  samlReq['samlp:AuthnRequest']['@AssertionConsumerServiceURL'] = callbackUrl;

  samlReq['samlp:AuthnRequest']['samlp:NameIDPolicy'] = {
    '@xmlns:samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
    '@Format': identifierFormat,
    '@AllowCreate': 'true',
  };

  if (providerName != null) {
    samlReq['samlp:AuthnRequest']['@ProviderName'] = providerName;
  }

  let xml = xmlbuilder.create(samlReq).end({});
  if (signingKey) {
    xml = sign(xml, signingKey, publicKey, authnXPath);
  }
  return xml;
}

describe('validateSignature.ts', function () {
  it('certToPEM ok', function () {
    const value = certToPEM(publicKey);
    assert.strictEqual(value, publicKey);
  });

  it('hasValidSignature ok ', function () {
    const value = hasValidSignature(generateXML(), publicKey, null);
    assert(value);
  });

  it('validateSignature ok ', function () {
    assert(validateSignature(generateXML(), publicKey, null));
  });

  it('validate response signature - no embedded cert, use single cert to validate', function () {
    const value = validateSignature(validResponseSigned_noX509, singlePublicKey, null);
    assert(value);
  });

  it('validate response signature - no embedded cert, use different cert, should fail validate', function () {
    try {
      validateSignature(validResponseSigned_noX509, singlePublicKeyNotUsedToSign, null);
    } catch (error) {
      assert(error);
    }
  });

  it('validate response signature - no embedded cert, use multikey cert to validate', function () {
    const value = validateSignature(validResponseSigned_noX509, multiPublicKey, null);
    assert(value);
  });

  it('validate response signature - no embedded cert, use multikey cert (order changed) to validate', function () {
    const value = validateSignature(validResponseSigned_noX509, multiPublicKeyOrderChanged, null);
    assert(value);
  });

  it('validate response signature - no embedded cert, use multikey cert (wrong ones) should not pass', function () {
    try {
      validateSignature(validResponseSigned_noX509, wrongMultiPublicKey, null);
    } catch (error: any) {
      assert.equal(
        error.message,
        'invalid signature: Failed to verify signature against all the certificates provided.'
      );
    }
  });

  it('validateSignature public key not ok ', function () {
    try {
      const value = validateSignature(generateXML(), undefined, 'null');
      assert.strictEqual(value, undefined);
    } catch (error) {
      assert(error);
    }
  });

  it('must not validateSignature ok if cert and thumbprints provided and if key info has unknown cert', function () {
    const SAML_RESPONSE_WITH_UNKOWN_CERT_AT_KEY_INFO = `
<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_1" Version="2.0" IssueInstant="1900-01-01T01:01:00Z" Destination="https://acs-endpoint" InResponseTo="in_response_to">
    <saml:Issuer>issuer</saml:Issuer>
    <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
        <SignedInfo>
            <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <Reference URI="#_1">
                <Transforms>
                    <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                    <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                </Transforms>
                <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <DigestValue>5pCdjXFqMlPhoJATgpr2JIOrgxozccaZ0Zadp+nTwNU=</DigestValue>
            </Reference>
        </SignedInfo>
        <SignatureValue>AitFP4fhZVPMeJhnpCGLUiURGfBPiCVGPBT8G0UFRsBJ92nuqZIVvYeKqp8K2jsM
EaSKMhVGEHw31emtYnpfupRrJLEyhGgowJTNxjxDKHp8Q7coVdfM+zXAwiLtUlsg
X/bcWnef6z80FNy7cB0T7/S4CN/YQfDq6WFPePyx8q8=</SignatureValue>
        <KeyInfo>
            <X509Data>
                <X509Certificate>MIIBxDCCAW6gAwIBAgIQxUSXFzWJYYtOZnmmuOMKkjANBgkqhkiG9w0BAQQFADAW
MRQwEgYDVQQDEwtSb290IEFnZW5jeTAeFw0wMzA3MDgxODQ3NTlaFw0zOTEyMzEy
MzU5NTlaMB8xHTAbBgNVBAMTFFdTRTJRdWlja1N0YXJ0Q2xpZW50MIGfMA0GCSqG
SIb3DQEBAQUAA4GNADCBiQKBgQC+L6aB9x928noY4+0QBsXnxkQE4quJl7c3PUPd
Vu7k9A02hRG481XIfWhrDY5i7OEB7KGW7qFJotLLeMec/UkKUwCgv3VvJrs2nE9x
O3SSWIdNzADukYh+Cxt+FUU6tUkDeqg7dqwivOXhuOTRyOI3HqbWTbumaLdc8juf
z2LhaQIDAQABo0swSTBHBgNVHQEEQDA+gBAS5AktBh0dTwCNYSHcFmRjoRgwFjEU
MBIGA1UEAxMLUm9vdCBBZ2VuY3mCEAY3bACqAGSKEc+41KpcNfQwDQYJKoZIhvcN
AQEEBQADQQAfIbnMPVYkNNfX1tG1F+qfLhHwJdfDUZuPyRPucWF5qkh6sSdWVBY5
sT/txBnVJGziyO8DPYdu2fPMER8ajJfl</X509Certificate>
            </X509Data>
        </KeyInfo>
    </Signature>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_2" Version="2.0" IssueInstant="1900-01-01T01:01:00Z">
        <saml:Issuer>issuer</saml:Issuer>
        <saml:Subject>
            <saml:NameID SPNameQualifier="audience" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">some_name_id</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData NotOnOrAfter="8980-01-01T01:01:00Z" Recipient="https://acs-endpoint" InResponseTo="in_response_to"/>
            </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="1900-01-01T01:00:00Z" NotOnOrAfter="8980-01-01T01:01:00Z">
            <saml:AudienceRestriction>
                <saml:Audience>audience</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="1900-01-01T01:01:00Z" SessionNotOnOrAfter="8980-01-01T01:01:00Z" SessionIndex="session_index">
            <saml:AuthnContext>
                <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
            </saml:AuthnContext>
        </saml:AuthnStatement>
    </saml:Assertion>
</samlp:Response>
`;
    // NOTE: validateSignature's publicKey and certThumbprint are both provided
    // NOTE2: response is signed with
    // https://raw.githubusercontent.com/node-saml/xml-crypto/v4.1.0/test/static/client.pem
    // which cert is
    // https://raw.githubusercontent.com/node-saml/xml-crypto/v4.1.0/test/static/client_public.pem
    // i.e. validateSignature SHOULD NOT return id value because it is signed with unknown
    // key
    try {
      validateSignature(
        SAML_RESPONSE_WITH_UNKOWN_CERT_AT_KEY_INFO,
        publicKey,
        'd730fc9342107b05032393d21cd5ef550150e06b'
      );
    } catch (error) {
      assert(error);
    }
  });
});
