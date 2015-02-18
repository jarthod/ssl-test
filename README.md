# SSLTest

A small tool to help you test a website's SSL certificate.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'ssl-test'
```

Or install it yourself as:

    $ gem install ssl-test

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

## How it works

SSLTester simply performs a HEAD request using ruby `net/https` library and verifies the SSL status. It also hooks into the validation process to intercept the raw certificate for you.

### What kind of errors will SSLTest detect

Pretty much the same errors `curl` will:
- Expired certificates
- Incomplete certificate chain (missing intermediary)
- Self signed certificates
- Valid certs used with incorect hostname

### GOTCHA: errors SSLTest will NOT detect

There is a spefic kind or error this code will *NOT* detect: *revoked certificates*. This is much more complex to handle because it needs an up to date database of revoked certs to check with. This is implemented in most modern browsers but the results vary greatly (chrome ignores this for example).

Here is an example of website with a revoked certificate: https://revoked.grc.com/

Any contribution to add this feature is greatly appreciated :)

## Contributing

1. Fork it ( https://github.com/[my-github-username]/ssl-test/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request
