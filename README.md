# SSLTest

A small ruby gem (with no dependencies) to help you test a website's SSL certificate.

```ruby
gem 'ssl-test'
```

## Usage

Simply call the `SSLTest.test_url` method and it'll return 3 values:

1. the validity of the certificate
2. the error message (if any)
3. the certificate itself

Example with good cert:

```ruby
valid, error, cert = SSLTest.test_url "https://google.com"
valid # => true
error # => nil
cert # => #<OpenSSL::X509::Certificate...>
```

Example with bad certificate:

```ruby
valid, error, cert = SSLTest.test_url "https://testssl-expire.disig.sk"
valid # => false
error # => "error code 10: certificate has expired"
cert # => #<OpenSSL::X509::Certificate...>
```

If the request fails and we're unable to detemine the validity, here are the returned values:

```ruby
valid, error, cert = SSLTest.test_url "https://thisisdefinitelynotawebsite.com"
valid # => nil
error # => "SSL certificate test failed: getaddrinfo: Name or service not known"
cert # => nil
```

You can also pass custom timeout values (defaults to 5 seconds for open and read):

```ruby
valid, error, cert = SSLTest.test_url "https://slowebsite.com", open_timeout: 2, read_timeout: 2
valid # => nil
error # => "SSL certificate test failed: execution expired"
cert # => nil
```

Or a proxy host and port to use for the http requests:

```ruby
valid, error, cert = SSLTest.test_url "https://slowebsite.com", proxy_host: 'localhost', proxy_port: 8080
valid # => true
error # => nil
cert # => #<OpenSSL::X509::Certificate...>
```

Revoked certificates are detected using [OCSP](https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol) by default:

```ruby
valid, error, cert = SSLTest.test_url "https://revoked.badssl.com"
valid # => false
error # => "SSL certificate revoked: Key Compromise (revocation date: 2019-10-07 20:30:39 UTC)"
cert # => #<OpenSSL::X509::Certificate...>
```

If the OCSP endpoint is missing, invalid or unreachable the certificate revocation will be tested using the [CRL](https://en.wikipedia.org/wiki/Certificate_revocation_list).

You can swap the order if you'd rather check CRL first and only fall back to OCSP on error (the default is OCSP first, since 2.1, because CRLs can be large and checking them is significantly more memory- and CPU-intensive):

```ruby
SSLTest.revocation_order = %i[crl ocsp]   # CRL first, OCSP fallback
SSLTest.revocation_order = %i[ocsp crl]   # the default: OCSP first, CRL fallback
```

If both CRL and OCSP tests are impossible, the certificate will still be considered valid but with an error message:

```ruby
valid, error, cert = SSLTest.test_url "https://sitewithnoOCSPorCRL.com"
valid # => true
error # => "Revocation test couldn't be performed: CRL: Missing crlDistributionPoints extension, OCSP: Missing OCSP URI in authorityInfoAccess extension"
cert # => #<OpenSSL::X509::Certificate...>
```

### Testing when you have the client certificate and Certificate Authority Bundle

If you already have access to the client certificate and the CA certificate bundle to check against, you can call `test_cert` which takes a certificate and ca bundle certificate instead of a URL. it has all the same options as `test_url`

```ruby
cert = OpenSSL::X509::Certificate.new(File.read('path/to/certificate')))
ca_bundle = OpenSSL::X509::Certificate.load(File.read('path/to/ca-bundle-certificate'))

valid, error, cert = SSLTest.test_cert(cert, ca_bundle)
```

This check will pass for self-signed certificates if the certificate is signed by the ca certificate provided.

## How it works

SSLTester connects as an HTTPS client (without issuing any requests) and then closes the connection. It does so using ruby `net/https` library and verifies the SSL status. It also hooks into the validation process to intercept the raw certificate for you.

After that it queries the [OCSP](https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol) endpoint to verify if the certificate has been revoked. If the OCSP endpoint is not available it'll fetch the [CRL](https://en.wikipedia.org/wiki/Certificate_revocation_list) instead. It does this for every certificates in the chain (except the root which is trusted by your Operating System). It is possible the first one will be validated with OCSP and the intermediate with CRL depending on what they offer.

### Caching

OCSP and CRL responses are cached, which makes subsequent testing faster and more robust (avoids network error and throttling).

About the caching duration:
- OCSP responses are cached until their "next_update" indicated inside the repsonse
- OCSP errors are cached for 5 minutes
- CRL responses are cached for 1 hour

CRL responses can be big so when they expires they are re-validated with the server using HTTP caching headers when available (`Etag` & `Last-Modified`) to avoid downloading the list again if it didn't change. The cached body is therefore kept in the backend for a longer retention period (~4 days, refreshed on each use) so it's still around to revalidate against; unused lists are dropped after that.

#### Cache backend

The cache backend is configurable. By default SSLTest uses a simple in-process store (`SSLTest::MemoryStore`). To share the cache across processes and get compression, assign any object implementing the `Rails.cache`-style API (`read`, `write(key, value, expires_in:)`, `delete`):

```ruby
SSLTest.cache = Rails.cache          # shared + compressed (e.g. memcache via Dalli)
SSLTest.cache = SSLTest::MemoryStore.new  # the default in-process store
SSLTest.cache = MyCustomStore.new    # anything responding to read/write/delete
```

The default in-process store is per-process and unbounded, so be careful about memory usage if you try to validate millions of certificates in a row (the OCSP cache is keyed by certificate serial). Using a shared store like `Rails.cache` with memcache avoids this and shares the cache across processes.

If you want a bounded/compressed in-process cache without pulling in `Rails.cache`, the API is intentionally compatible with `ActiveSupport::Cache::MemoryStore`, which you can drop in directly:

```ruby
require "active_support/cache"
SSLTest.cache = ActiveSupport::Cache::MemoryStore.new(size: 64.megabytes, compress: true)
```

(It auto-prunes when it exceeds `size`, unlike the built-in store. Note the introspection helpers below are specific to `SSLTest::MemoryStore`.)

> **Using memcached (Dalli)?** CRL lists can be large (commonly several MB, up to ~20MB for busy CAs). memcached rejects values over its max item size — 1MB by default — which Dalli surfaces as `Dalli::ValueOverMaxSize` (logged and skipped by `ActiveSupport::Cache::MemCacheStore`, so the test still passes but the list isn't cached and gets re-downloaded every time). To actually cache big CRLs, raise the limit on **both** sides to at least 64MB:
>
> - memcached server: start it with `-I 64m`
> - Dalli client: `Dalli::Client.new(servers, value_max_bytes: 64 * 1024 * 1024)`, or via Rails: `config.cache_store = :mem_cache_store, servers, { value_max_bytes: 64.megabytes }`

You can check the size of the **built-in** store with `SSLTest.cache.size`, which returns:

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

You can also flush it using `SSLTest.cache.clear` if you want (not recommended).

`size` is specific to the built-in `MemoryStore`; other backends won't respond to it. (The module-level `SSLTest.cache_size` and `SSLTest.flush_cache` from previous versions were **removed in 2.0** — use `SSLTest.cache.size` / `SSLTest.cache.clear` instead.)

### Logging

You can enable logging by setting `SSLTest.logger`, for example:

```ruby
SSLTest.logger = Rails.logger
```

SSLTest will log various messages depending on the log level you specify, example:

```
 INFO -- : SSLTest https://www.anonymisation.gov.pf started
DEBUG -- : SSLTest + test_chain_revocation: www.anonymisation.gov.pf
DEBUG -- : SSLTest   + CRL: [false, "Missing crlDistributionPoints extension", nil]
DEBUG -- : SSLTest   + OCSP: fetch URI http://servicesca.ocsp.certigna.fr
DEBUG -- : SSLTest   + OCSP: 200 OK (4661 bytes)
DEBUG -- : SSLTest   + OCSP: ocsp_ok
DEBUG -- : SSLTest + test_chain_revocation: Certigna Services CA
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

* 2.1.0 - 2026-06-20: Check revocation with OCSP first and fall back to CRL (was CRL first since 1.6) because CRLs can be large and checking them is significantly more memory- and CPU-intensive. Set `SSLTest.revocation_order = %i[crl ocsp]` to restore the previous order.
* 2.0.1 - 2026-06-19: Speed up and shrink the memory use of CRL checks with a fast path that scans the raw CRL for the certificate's serial before parsing, avoiding instantiating the entire revocation list (>1M Ruby objects for busy CAs) when the cert isn't revoked. Send both `If-None-Match` and `If-Modified-Since` on CRL revalidation so CDN-backed CAs that don't honor their own ETag (e.g. DigiCert) still return a `304` instead of re-downloading the whole list.
* 2.0.0 - 2026-06-16: Make the revocation check order configurable via `SSLTest.revocation_order` (`%i[crl ocsp]` by default, set `%i[ocsp crl]` to check OCSP first). Make the cache backend configurable. The default stays an in-process `SSLTest::MemoryStore`, but you can now assign any object responding to the `Rails.cache`-style API (`read`/`write`/`delete`) with `SSLTest.cache = Rails.cache` to share responses across processes and get compression (e.g. memcache via Dalli — see the memcached note in the Caching section about raising the max value size for large CRLs). **Breaking:** the module-level `SSLTest.cache_size` and `SSLTest.flush_cache` were removed — use `SSLTest.cache.size` and `SSLTest.cache.clear` instead (these only work with the built-in `MemoryStore`; shared backends like `Rails.cache` can't be enumerated and shouldn't be wholesale-cleared)
* 1.6.0 - 2026-06-16: Check revocation with CRL first and fall back to OCSP (was OCSP first) to reduce revocation detection delay
* 1.5.0 - 2025-11-28: Add support for local certificates testing and HTTP proxies (#8), changed `#test` method into `#test_url` and `#test_cert` (`#test` remains as an alias for `#test_url` for backward-compatibility)
* 1.4.1 - 2022-10-24: Add support for "tcps://" scheme
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
