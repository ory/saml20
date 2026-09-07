import { certToPEM, hasValidSignature, validateSignature } from '../../lib/validateSignature';
import xmlbuilder from 'xmlbuilder';

import crypto from 'crypto';
import fs from 'fs';
import { sign } from '../../lib/sign';
import { SignedXml } from 'xml-crypto';
import { PubKeyInfo } from '../../lib/cert';
import { thumbprint } from '../../lib/utils';
import assert from 'assert';

const ssoUrl =
  'https://dev-20901260.okta.com/app/dev-20901260_jacksondemo5225_1/exk3wth7ss1TKnAN15d7/sso/saml';
const entityID = 'https://saml.boxyhq.com';
const callbackUrl = 'http://localhost:5225/api/oauth/saml';

const signingKey =
  '-----BEGIN RSA PRIVATE KEY-----\r\nMIIEpAIBAAKCAQEA0hA92pnznEYdnRGcYQ5ONb88xpVdCfgxSkDCIEbyGGsEH4qW\r\nnLo2wM/I2hFiwoqrv/o1PBE7W0sroYM5OVMf1dtOnS1Ubl5214KuWl1fq7/mTsvP\r\nV03i6gbEeTFmiVTDjOp+c7kcGWb5vmHP6VIzcXPIdUSXROeHwU40FVBfZ3ZA5uRO\r\nXcYNOUBtunYxZJYQuXCg4dew2gOjxNieyxDuVOKq0QD5Y9dB29lgeY6h2PXNsewA\r\ncLNf0zJnQoRQaFXIjdW/QoGxrERF9JqcGMB6mGtE/5hfrm8524eHqTavkgLrARlk\r\nS36e6uVdX2fxTAXqGpVwQtGczezuWede0ZE23wIDAQABAoIBAAlS1jlR1E8PNPjy\r\nk1Mi0ZQvdkZG0o0tj8aAxFJZbnJorD4C0TeInliFgHU0CK2jflxe1yZg32u9v48u\r\nJgfmKXISXKq7nH/qP8fF/EYfgdkQ2JXjvu1cPszuBaIZcA3QDik+2Tj6sjAVyCeh\r\nQMYAM4SpbnAiCL1ysgMBnRcwbOOdy/SoBgx8BpdNd4e02JOWHEHyEyKpgspfC6Bp\r\n4w0jgbq0A9rKVpL81UdTT34wsN1asb1EUcTUgFUaLe1iDmW0hTxMoFjdcnuO0vZx\r\n5cp8XF3XL7khTluunMVCQPj0IigidlomyLp9Jv90c0fhqUmPO2jDpxCRVZoMlQ6Y\r\nTACFnAkCgYEA8GX4Mgh0qtTMMGI1Bidf/C+NjgimGeOpl0oyAT2Z4HfTXHTNy5eQ\r\nsKOkq9ATZVDOLrAncMTVCxA9kPJY56u4HXUiqCrHtFajQyJjG/SfJwUyTMQuyCUf\r\nkJxHR5dRy+kj9rlp0ulqsmPhJhDcQehrrYCYq6xC+f6OBMG1N13LQCkCgYEA37JI\r\nJhY1swIKpR65GT9Z2r3t1TFZl+lTjQ/lbT+s/DbSJnc7DYdyce75vecdW00gLR0T\r\nC93VSAVIrTkCowiaatKZTkJ475cUarDQwpFkppe8UNA7J3liZXLKxNN4+2XuNcby\r\noDA7XgTIvvxSdxayVsT9CEarbc9tirEdbzWOf8cCgYEA3TxqitkfTWwjMk/fDnfE\r\nLRkyQ8mP23maRKJCnMOtTlfYS1kvX7NvtDAVxwzqHK6d4Xe6BF0Q12qtzixKR4LQ\r\nIUQAjhU4zq2A+LK31S1uHoH4xY8yon0PrI02SBtpaqh3sYL3cePgjqW+ucKAgaM9\r\nHWKgnjUdOmbbGmOOu5J1D+kCgYEAuI2I0steEEqt556aTYcjpcEul8Y4SYl5ohas\r\nTN7M4+SCqrORp87Ij9D+gDtN0Aaodi/Xh+HD1cBuPmObllBBvcH0M0nKJrj5YjBw\r\neyWi6YKkHfQ96YpOsK3tNkfWN2rYBcwWXiyMvjuqN09K5e92wPmSXKKZSmZo1JTd\r\nWOPRpf8CgYBeKPj/K3gKoPz9CYO5t3SypBGfYfmH9rZ2d2LQqnYW00bGb84NMeg8\r\nbSYo1BSWKwbNJdDZgZTJEDa4hxfBR7rWO5ZsWtxfFknKvi4jvhq2HR56dDt28zyr\r\nB/fBNVFXJJAheF2tTi0B1i0P2gGp71ae8qj7zBJnfTa4/obtXjR1CQ==\r\n-----END RSA PRIVATE KEY-----\r\n';
const publicKey =
  '-----BEGIN CERTIFICATE-----\r\nMIICvzCCAaegAwIBAgIBATANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDEwlPcnkg\r\nUG9saXMwIBcNMjUxMTA3MTAwMDE2WhgPMjA1NTExMDcxMDAwMTZaMBQxEjAQBgNV\r\nBAMTCU9yeSBQb2xpczCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANIQ\r\nPdqZ85xGHZ0RnGEOTjW/PMaVXQn4MUpAwiBG8hhrBB+Klpy6NsDPyNoRYsKKq7/6\r\nNTwRO1tLK6GDOTlTH9XbTp0tVG5edteCrlpdX6u/5k7Lz1dN4uoGxHkxZolUw4zq\r\nfnO5HBlm+b5hz+lSM3FzyHVEl0Tnh8FONBVQX2d2QObkTl3GDTlAbbp2MWSWELlw\r\noOHXsNoDo8TYnssQ7lTiqtEA+WPXQdvZYHmOodj1zbHsAHCzX9MyZ0KEUGhVyI3V\r\nv0KBsaxERfSanBjAephrRP+YX65vOduHh6k2r5IC6wEZZEt+nurlXV9n8UwF6hqV\r\ncELRnM3s7lnnXtGRNt8CAwEAAaMaMBgwCQYDVR0TBAIwADALBgNVHQ8EBAMCB4Aw\r\nDQYJKoZIhvcNAQELBQADggEBAEw8fZm9qj00gZ1lsbFyJYU7vaaKf+6Zt6iQ3fjz\r\nQPt6lAJLorAYgmbRmPKZ3HS40Ud4UL4dBEjy03RJKejAUiF6NEPgo0bb2GIG5U1J\r\nDryYilUQTRC1lIdeFI5E67iqzON16iahiqWc+yLk+SEKK9wIczGbsy3vezaO8v5G\r\n6ONoNy3syPtcjP/ujy0aKLoIjZtVG0AzxOfHO3f0WH+HTbpHyZtDWZj3uKIVwpGp\r\naLe2D8PsEEiJhVSgchNq0Xxi5DvN+ljbYOkO8j76zjWyVERM1fxa74YyYgljYvqS\r\nEx/0oIxL1FpSidigLFuiVwV4zGusNEyfwAlSVjjmepbAw2Q=\r\n-----END CERTIFICATE-----\r\n';
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

const RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
const RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
const SHA1 = 'http://www.w3.org/2000/09/xmldsig#sha1';
const SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';

// Build the same AuthnRequest as generateXML() but sign it with RSA-SHA1 and a
// SHA-1 digest, so the SHA-1 fixture carries a genuine signature rather than a
// SHA-256 document with its algorithm URIs edited.
function generateSha1SignedXML() {
  const unsigned = generateXML({ sign: false });
  const sig = new SignedXml({
    privateKey: signingKey,
    signatureAlgorithm: RSA_SHA1,
    getKeyInfoContent: PubKeyInfo(publicKey),
    canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
  });
  sig.addReference({
    xpath: authnXPath,
    transforms: [
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
      'http://www.w3.org/2001/10/xml-exc-c14n#',
    ],
    digestAlgorithm: SHA1,
  });
  sig.computeSignature(unsigned, {
    location: {
      reference:
        authnXPath +
        '/*[local-name(.)="Issuer" and namespace-uri(.)="urn:oasis:names:tc:SAML:2.0:assertion"]',
      action: 'after',
    },
  });
  return sig.getSignedXml();
}

function generateXML({ sign: shouldSign = true } = {}) {
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
  if (shouldSign && signingKey) {
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

describe('validateSignature.ts - algorithm allowlists', function () {
  const sha2Only = { allowedSignatureAlgorithms: [RSA_SHA256], allowedHashAlgorithms: [SHA256] };

  it('fixtures use the algorithms the tests assume', function () {
    const sha256Doc = generateXML();
    assert(sha256Doc.includes(`SignatureMethod Algorithm="${RSA_SHA256}"`));
    assert(sha256Doc.includes(`DigestMethod Algorithm="${SHA256}"`));
    const sha1Doc = generateSha1SignedXML();
    assert(sha1Doc.includes(`SignatureMethod Algorithm="${RSA_SHA1}"`));
    assert(sha1Doc.includes(`DigestMethod Algorithm="${SHA1}"`));
  });

  it('accepts a SHA-256 signed document when the allowlist includes SHA-256', function () {
    assert(validateSignature(generateXML(), publicKey, null, sha2Only));
    assert(hasValidSignature(generateXML(), publicKey, null, sha2Only));
  });

  it('accepts a SHA-256 signed document with a wider allowlist', function () {
    assert(
      validateSignature(generateXML(), publicKey, null, {
        allowedSignatureAlgorithms: [RSA_SHA1, RSA_SHA256],
        allowedHashAlgorithms: [SHA1, SHA256],
      })
    );
  });

  it('rejects a SHA-256 signed document when the signature algorithm allowlist excludes it', function () {
    assert.throws(
      () => validateSignature(generateXML(), publicKey, null, { allowedSignatureAlgorithms: [RSA_SHA1] }),
      /signature algorithm '.*rsa-sha256' is not allowed/
    );
  });

  it('rejects a SHA-256 signed document when the digest algorithm allowlist excludes it', function () {
    assert.throws(
      () => validateSignature(generateXML(), publicKey, null, { allowedHashAlgorithms: [SHA1] }),
      /digest algorithm '.*sha256' is not allowed/
    );
  });

  it('accepts a SHA-1 signed document when no options are passed (compatibility)', function () {
    assert(validateSignature(generateSha1SignedXML(), publicKey, null));
    assert(validateSignature(generateSha1SignedXML(), publicKey, null, {}));
    assert(
      validateSignature(generateSha1SignedXML(), publicKey, null, { allowedSignatureAlgorithms: [RSA_SHA1] })
    );
  });

  it('rejects a SHA-1 signed document under a SHA-2-only allowlist', function () {
    assert.throws(
      () => validateSignature(generateSha1SignedXML(), publicKey, null, sha2Only),
      /signature algorithm '.*rsa-sha1' is not allowed/
    );
    // digest constrained on its own: signature method passes, digest does not
    assert.throws(
      () => validateSignature(generateSha1SignedXML(), publicKey, null, { allowedHashAlgorithms: [SHA256] }),
      /digest algorithm '.*sha1' is not allowed/
    );
  });

  it('fails closed on an empty allowlist', function () {
    assert.throws(
      () => validateSignature(generateXML(), publicKey, null, { allowedSignatureAlgorithms: [] }),
      /signature algorithm .* is not allowed/
    );
    assert.throws(
      () => validateSignature(generateXML(), publicKey, null, { allowedHashAlgorithms: [] }),
      /digest algorithm .* is not allowed/
    );
  });

  it('fails closed on an allowlist naming only unknown algorithms', function () {
    assert.throws(
      () =>
        validateSignature(generateXML(), publicKey, null, {
          allowedSignatureAlgorithms: ['http://example.com/not-an-algorithm'],
        }),
      /signature algorithm .* is not allowed/
    );
  });

  it('narrowed registries enforce the allowlist independently of the early check', function () {
    // Sanity check on the mechanism itself: a SignedXml whose registry has been
    // reduced the way validateSignature reduces it refuses to verify, so an
    // excluded algorithm can never verify even without the explicit pre-check.
    const doc = generateXML();
    const signed = new SignedXml({ publicCert: publicKey });
    signed.loadSignature(doc.match(/<Signature[\s\S]*<\/Signature>/)![0]);
    signed.SignatureAlgorithms = {} as typeof signed.SignatureAlgorithms;
    assert.throws(() => signed.checkSignature(doc), /signature algorithm .* is not supported/);
  });

  it('digest allowlist ignores DigestMethods outside SignedInfo (unsigned ds:Object/Manifest)', function () {
    // A ds:Object is not covered by the enveloped signature, so anyone can
    // append one. Its Manifest DigestMethod must not be able to reject a valid
    // SHA-256 document under a SHA-2-only allowlist.
    const doc = generateXML();
    const manifest =
      '<Object xmlns="http://www.w3.org/2000/09/xmldsig#"><Manifest><Reference URI="#nothing">' +
      `<DigestMethod Algorithm="${SHA1}"/><DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAA=</DigestValue>` +
      '</Reference></Manifest></Object>';
    const tampered = doc.replace('</Signature>', manifest + '</Signature>');
    assert.notStrictEqual(tampered, doc);
    assert(validateSignature(tampered, publicKey, null, sha2Only));
    // and the real SignedInfo digest is still enforced on the same document
    assert.throws(
      () => validateSignature(tampered, publicKey, null, { allowedHashAlgorithms: [SHA1] }),
      /digest algorithm '.*sha256' is not allowed/
    );
  });

  it('multi-certificate rotation: SHA-256 document accepted under a SHA-2-only allowlist', function () {
    const rotated = `${singlePublicKeyNotUsedToSign},${publicKey}`;
    assert(validateSignature(generateXML(), rotated, null, sha2Only));
    assert(validateSignature(validResponseSigned_noX509, multiPublicKey, null, sha2Only));
    assert(validateSignature(validResponseSigned_noX509, multiPublicKeyOrderChanged, null, sha2Only));
  });

  it('multi-certificate rotation: SHA-1 document rejected under a SHA-2-only allowlist', function () {
    const rotated = `${singlePublicKeyNotUsedToSign},${publicKey}`;
    // no options: still accepted through the rotation path
    assert(validateSignature(generateSha1SignedXML(), rotated, null));
    assert.throws(
      () => validateSignature(generateSha1SignedXML(), rotated, null, sha2Only),
      /signature algorithm '.*rsa-sha1' is not allowed/
    );
  });

  it('multi-certificate rotation: wrong certificates still fail with the existing error', function () {
    assert.throws(
      () => validateSignature(validResponseSigned_noX509, wrongMultiPublicKey, null, sha2Only),
      /Failed to verify signature against all the certificates provided/
    );
  });

  it('thumbprint branch honours the allowlist', function () {
    const sha1Doc = generateSha1SignedXML();
    const embedded = sha1Doc.match(/<X509Certificate>([^<]+)<\/X509Certificate>/)![1];
    const fp = thumbprint(embedded);
    assert(validateSignature(sha1Doc, null, fp));
    assert.throws(() => validateSignature(sha1Doc, null, fp, sha2Only), /rsa-sha1' is not allowed/);
    assert(validateSignature(generateXML(), null, fp, sha2Only));
  });
});
