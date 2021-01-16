# SSLTest [![Build Status](https://travis-ci.com/jarthod/ssl-test.svg?branch=master)](https://travis-ci.com/jarthod/ssl-test)

A small ruby gem (with no dependencies) to help you test a website's SSL certificate.

```ruby
gem 'ssl-test'
```

## Usage

Simply call the `SSLTest.test` method and it'll return 3 values:

1. the validity of the certificate
2. the error message (if any)
3. the certificate itself

Example with good cert:
```ruby
valid, error, cert = SSLTest.test "https://google.com"
valid # => true
error # => nil
cert # => #<OpenSSL::X509::Certificate...>
```

Example with bad certificate:
```ruby
valid, error, cert = SSLTest.test "https://testssl-expire.disig.sk"
valid # => false
error # => "error code 10: certificate has expired"
cert # => #<OpenSSL::X509::Certificate...>
```

If the request fails and we're unable to detemine the validity, here are the returned values:
```ruby
valid, error, cert = SSLTest.test "https://thisisdefinitelynotawebsite.com"
valid # => nil
error # => "SSL certificate test failed: getaddrinfo: Name or service not known"
cert # => nil
```

You can also pass custom timeout values:
```ruby
valid, error, cert = SSLTest.test "https://slowebsite.com", open_timeout: 2, read_timeout: 2
valid # => nil
error # => "SSL certificate test failed: execution expired"
cert # => nil
```
Default timeout values are 5 seconds each (open and read)

Revoked certificates are detected using [OCSP](https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol) endpoint by default:
```ruby
valid, error, cert = SSLTest.test "https://revoked.badssl.com"
valid # => false
error # => "SSL certificate revoked: The certificate was revoked for an unknown reason (revocation date: 2019-10-07 20:30:39 UTC)"
cert # => #<OpenSSL::X509::Certificate...>
```

If the OCSP endpoint is missing, invalid or unreachable the certificate revocation will be tested using [CRL](https://en.wikipedia.org/wiki/Certificate_revocation_list).

If both OCSP and CRL tests are impossible, the certificate will still be considered valid but with an error message:
```ruby
valid, error, cert = SSLTest.test "https://sitewithnoOCSPorCRL.com"
valid # => true
error # => "Revocation test couldn't be performed: OCSP: Missing OCSP URI in authorityInfoAccess extension, CRL: Missing crlDistributionPoints extension"
cert # => #<OpenSSL::X509::Certificate...>
```

## How it works

SSLTester connects as an HTTPS client (without issuing any requests) and then closes the connection. It does so using ruby `net/https` library and verifies the SSL status. It also hooks into the validation process to intercept the raw certificate for you.

After that it queries the [OCSP](https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol) endpoint to verify if the certificate has been revoked. If OCSP is not available it'll fetch the [CRL](https://en.wikipedia.org/wiki/Certificate_revocation_list) instead. It does this for every certificates in the chain (except the root which is trusted by your Operating System). It is possible the first one will be validated with OCSP and the intermediate with CRL depending on what they offer.

### Caching

OCSP and CRL responses are cached in memory, which makes subsequent testing faster and more robust (avoids network error and throttling) but be careful about memory usage if you try to validate millions of certificates in a row.

About the caching duration:
- OCSP responses are cached until their "next_update" indicated inside the repsonse
- OCSP errors are cached for 5 minutes
- CRL responses are cached for 1 hour

CRL responses can be big so when they expires they are re-validated with the server using HTTP caching headers when available (`Etag` & `Last-Modified`) to avoid downloading the list again if it didn't change.

You can check the size of the cache with `SSLTest.cache_size`, which returns:

```ruby
{
  crl: {
    lists: 5,
    bytes: 5123456
  },
  ocsp: {
    responses: 350,
    errors: 2,
    bytes: 45876
  }
}
```

You can also flush the cache using `SSLTest.flush_cache` if you want (not recommended)

### Logging

You can enable logging by setting `SSLTest.logger`, for example:

```ruby
SSLTest.logger = Rails.logger
```

SSLTest will log various messages depending on the log level you specify, example:

```
 INFO -- : SSLTest https://www.anonymisation.gov.pf started
DEBUG -- : SSLTest + test_chain_revocation: www.anonymisation.gov.pf
DEBUG -- : SSLTest   + OCSP: fetch URI http://servicesca.ocsp.certigna.fr
DEBUG -- : SSLTest   + OCSP: 200 OK (4661 bytes)
DEBUG -- : SSLTest   + OCSP: ocsp_ok
DEBUG -- : SSLTest + test_chain_revocation: Certigna Services CA
DEBUG -- : SSLTest   + OCSP: [false, "Missing OCSP URI in authorityInfoAccess extension", nil]
DEBUG -- : SSLTest   + CRL: fetch URI http://crl.certigna.fr/certigna.crl
DEBUG -- : SSLTest   + CRL: 200 OK (1152 bytes)
DEBUG -- : SSLTest   + CRL: crl_ok
 INFO -- : SSLTest https://www.anonymisation.gov.pf finished: revoked=false
```

### What kind of errors will SSLTest detect

Pretty much the same errors `curl` will:
- Expired certificates
- Incomplete certificate chain (missing intermediary)
- Self signed certificates
- Valid certs used with incorect hostname
- Untrusted root (if your system is up-to-date)
- And more...

But also **revoked certs** like most browsers (not handled by `curl`)

## Changelog

See also github releases: https://github.com/jarthod/ssl-test/releases

* 1.4.0 - 2021-01-16: Implemented CRL as fallback to OCSP + expose cache metrics + add logger support
* 1.3.1 - 2020-04-25: Improved caching of failed OCSP responses (#5)
* 1.3.0 - 2020-04-25: Added revoked cert detection using OCSP (#3)
* 1.2.0 - 2018-03-04: Better support for wrong hostname across ruby versions
* 1.1.0 - 2017-01-13: Removed HTTP call, Net::HTTP#start is enough to open the connection and get cert details and validation

## Contributing

1. Fork it ( https://github.com/[my-github-username]/ssl-test/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Make sure the tests are passing (`rspec`)
4. Commit your changes (`git commit -am 'Add some feature'`)
5. Push to the branch (`git push origin my-new-feature`)
6. Create a new Pull Request
