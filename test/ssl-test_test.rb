require "ssl-test"
require "minitest/autorun"

describe SSLTest do

  describe '.test' do
    it "returns no error on valid SNI website" do
      valid, error, cert = SSLTest.test("https://www.mycs.com")
      error.must_be_nil
      valid.must_equal true
      cert.must_be_instance_of OpenSSL::X509::Certificate
    end

    it "returns no error on valid SAN" do
      valid, error, cert = SSLTest.test("https://1000-sans.badssl.com/")
      error.must_be_nil
      valid.must_equal true
      cert.must_be_instance_of OpenSSL::X509::Certificate
    end

    it "returns no error when no CN" do
      valid, error, cert = SSLTest.test("https://no-common-name.badssl.com/")
      error.must_be_nil
      valid.must_equal true
      cert.must_be_instance_of OpenSSL::X509::Certificate
    end

    it "works with websites blocking http requests" do
      valid, error, cert = SSLTest.test("https://obyava.ua")
      error.must_be_nil
      valid.must_equal true
      cert.must_be_instance_of OpenSSL::X509::Certificate
    end

    it "returns error on self signed certificate" do
      valid, error, cert = SSLTest.test("https://self-signed.badssl.com/")
      error.must_equal "error code 18: self signed certificate"
      valid.must_equal false
      cert.must_be_instance_of OpenSSL::X509::Certificate
    end

    it "returns error on untrusted root" do
      valid, error, cert = SSLTest.test("https://untrusted-root.badssl.com/")
      error.must_equal "error code 20: unable to get local issuer certificate"
      valid.must_equal false
      cert.must_be_instance_of OpenSSL::X509::Certificate
    end

    it "returns error on invalid host" do
      valid, error, cert = SSLTest.test("https://wrong.host.badssl.com/")
      error.must_equal 'hostname "wrong.host.badssl.com" does not match the server certificate (*.badssl.com, badssl.com)'
      valid.must_equal false
      cert.must_be_instance_of OpenSSL::X509::Certificate
    end

    it "returns error on expired cert" do
      valid, error, cert = SSLTest.test("https://expired.badssl.com/")
      error.must_equal "error code 10: certificate has expired"
      valid.must_equal false
      cert.must_be_instance_of OpenSSL::X509::Certificate
    end

    it "returns undetermined state on unhandled error" do
      valid, error, cert = SSLTest.test("https://pijoinlrfgind.com")
      error.must_equal "SSL certificate test failed: Failed to open TCP connection to pijoinlrfgind.com:443 (getaddrinfo: Name or service not known)"
      valid.must_be_nil
      cert.must_be_nil
    end

    it "stops on timeouts" do
      valid, error, cert = SSLTest.test("https://updown.io", open_timeout: 0)
      error.must_equal "SSL certificate test failed: Net::OpenTimeout"
      valid.must_be_nil
      cert.must_be_nil
    end

    # Not implemented yet
    # it "returns error on revoked cert" do
    #   valid, error, cert = SSLTest.test("https://revoked.badssl.com/")
    #   error.must_equal "error code XX: certificate has been revoked"
    #   valid.must_equal false
    #   cert.must_be_instance_of OpenSSL::X509::Certificate
    # end
  end
end