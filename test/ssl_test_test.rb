require "ssl_test"
require "minitest/autorun"

describe SSLTest do

  describe '.test' do
    it "returns no error on valid SNI website" do
      valid, error, cert = SSLTest.test("https://www.mycs.com")
      valid.must_equal true
      error.must_be_nil
      cert.must_be_instance_of OpenSSL::X509::Certificate
    end

    it "returns error on self signed certificate" do
      valid, error, cert = SSLTest.test("https://kernelcoffee.org")
      valid.must_equal false
      error.must_equal "error code 18: self signed certificate"
      cert.must_be_instance_of OpenSSL::X509::Certificate
    end

    it "returns error on invalid host" do
      valid, error, cert = SSLTest.test("https://staging.updown.io")
      valid.must_equal false
      error.must_equal 'hostname "staging.updown.io" does not match the server certificate'
      cert.must_be_instance_of OpenSSL::X509::Certificate
    end

    it "returns error on expired cert" do
      valid, error, cert = SSLTest.test("https://testssl-expire.disig.sk")
      valid.must_equal false
      error.must_equal "error code 10: certificate has expired"
      cert.must_be_instance_of OpenSSL::X509::Certificate
    end

    it "returns undetermined state on unhandled error" do
      valid, error, cert = SSLTest.test("https://pijoinlrfgind.com")
      valid.must_be_nil
      error.must_equal "SSL certificate test failed: getaddrinfo: Name or service not known"
      cert.must_be_nil
    end

    # Not implemented yet
    # it "returns error on revoked cert" do
    #   valid, error, cert = SSLTest.test("https://revoked.grc.com")
    #   valid.must_equal false
    #   error.must_equal "error code XX: certificate has been revoked"
    #   cert.must_be_instance_of OpenSSL::X509::Certificate
    # end
  end
end