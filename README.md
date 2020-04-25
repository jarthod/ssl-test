# SSLTest [![Build Status](https://travis-ci.org/jarthod/ssl-test.svg?branch=master)](https://travis-ci.org/jarthod/ssl-test) [![Depfu](https://badges.depfu.com/badges/0d732c9cbec3fdaaac7c5ba5583269db/overview.svg)](https://depfu.com/github/jarthod/ssl-test)

A small ruby gem to help you test a website's SSL certificate.

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

Revoked certificates are detected using [OCSP](https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol) endpoint:
```ruby
valid, error, cert = SSLTest.test "https://revoked.badssl.com"
valid # => false
error # => "SSL certificate revoked: The certificate was revoked for an unknown reason (revocation date: 2019-10-07 20:30:39 UTC)"
cert # => #<OpenSSL::X509::Certificate...>
```

If the OCSP endpoint is invalid or unreachable the certificate may still be considered valid but with an error message:
```ruby
valid, error, cert = SSLTest.test "https://sitewithnoOCSP.com"
valid # => true
error # => "OCSP test couldn't be performed: Missing OCSP URI in authorityInfoAccess extension"
cert # => #<OpenSSL::X509::Certificate...>
```

## How it works

SSLTester performs a HEAD request using ruby `net/https` library and verifies the SSL status. It also hooks into the validation process to intercept the raw certificate for you.

After that it queries the [OCSP](https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol) endpoint to verify if the certificate has been revoked. OCSP responses are cached in memory so be careful if you try to validate millions of certificates.

### What kind of errors will SSLTest detect

Pretty much the same errors `curl` will:
- Expired certificates
- Incomplete certificate chain (missing intermediary)
- Self signed certificates
- Valid certs used with incorect hostname
- Untrusted root (if your system is up-to-date)
- And more...

But also *revoked certs* like most browsers (not handled by `curl`)

## Changelog

* 1.3.0 - 2020-04-25: Added revoked cert detection using OCSP (#3)

## Contributing

1. Fork it ( https://github.com/[my-github-username]/ssl-test/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request
