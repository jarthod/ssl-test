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

    it "works with websites blocking http requests" do
      valid, error, cert = SSLTest.test("https://obyava.ua")
      error.must_be_nil
      valid.must_equal true
      cert.must_be_instance_of OpenSSL::X509::Certificate
    end

    it "returns error on self signed certificate" do
      valid, error, cert = SSLTest.test("https://kernelcoffee.org")
      error.must_equal "error code 18: self signed certificate"
      valid.must_equal false
      cert.must_be_instance_of OpenSSL::X509::Certificate
    end

    it "returns error on invalid host" do
      valid, error, cert = SSLTest.test("https://web1.updn.io")
      error.must_equal 'hostname "web1.updn.io" does not match the server certificate'
      valid.must_equal false
      cert.must_be_instance_of OpenSSL::X509::Certificate
    end

    it "returns error on expired cert" do
      valid, error, cert = SSLTest.test("https://testssl-expire.disig.sk")
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
    #   valid, error, cert = SSLTest.test("https://revoked.grc.com")
    #   valid.must_equal false
    #   error.must_equal "error code XX: certificate has been revoked"
    #   cert.must_be_instance_of OpenSSL::X509::Certificate
    # end
  end
end