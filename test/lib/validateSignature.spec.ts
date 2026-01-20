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
    xml = sign(xml,{privateKey: signingKey, publicKey, sigLocation: authnXPath});
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
