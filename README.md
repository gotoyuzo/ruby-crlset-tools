# CRL Set Tools for Ruby

crlset.rb is a utility program for downloading and dumping the
current Chrome CRLSet.
This program is tepid copy of https://github.com/agl/crlset-tools.

First you need to download the current CRL set:

```
% ruby crlset.rb fetch crl-set
Downloading CRLSet version 1933
```

Then you can dump everything in the CRL set:

```
% ruby crlset dump crl-set
Sequence: 1933
Parents: 54

019406d575cf285a3c2d8bbf8133e0cfae4839c99cc1815b....
  1127055c3ee9304...
  11270b1308d3897...
```

Revocations are grouped by the SHA-256 hash of the issuing certificate's
and listed as serial numbers.

## See ALSO

CRLSet data structure is commented in:
https://github.com/adobe/chromium/blob/master/net/base/crl_set.cc
