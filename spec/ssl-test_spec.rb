require "ssl-test"
require "benchmark"

# Uncomment for debug logging:
# require "logger"
# SSLTest.logger = Logger.new(STDOUT)

describe SSLTest do
  describe '.test' do
    it "returns no error on valid SNI website" do
      valid, error, cert = SSLTest.test("https://www.mycs.com")
      expect(error).to be_nil
      expect(valid).to eq(true)
      expect(cert).to be_a OpenSSL::X509::Certificate
    end

    it "returns no error on valid SAN" do
      valid, error, cert = SSLTest.test("https://1000-sans.badssl.com/")
      expect(error).to be_nil
      expect(valid).to eq(true)
      expect(cert).to be_a OpenSSL::X509::Certificate
    end

    it "returns no error when no CN" do
      skip "Expired for the moment https://github.com/chromium/badssl.com/issues/447"
      valid, error, cert = SSLTest.test("https://no-common-name.badssl.com/")
      expect(error).to be_nil
      expect(valid).to eq(true)
      expect(cert).to be_a OpenSSL::X509::Certificate
    end

    it "works with websites blocking http requests" do
      valid, error, cert = SSLTest.test("https://obyava.ua")
      expect(error).to be_nil
      expect(valid).to eq(true)
      expect(cert).to be_a OpenSSL::X509::Certificate
    end

    it "returns error on self signed certificate" do
      valid, error, cert = SSLTest.test("https://self-signed.badssl.com/")
      expect(error).to eq ("error code 18: self signed certificate")
      expect(valid).to eq(false)
      expect(cert).to be_a OpenSSL::X509::Certificate
    end

    it "returns error on incomplete chain" do
      valid, error, cert = SSLTest.test("https://incomplete-chain.badssl.com/")
      expect(error).to eq ("error code 20: unable to get local issuer certificate")
      expect(valid).to eq(false)
      expect(cert).to be_a OpenSSL::X509::Certificate
    end

    it "returns error on untrusted root" do
      valid, error, cert = SSLTest.test("https://untrusted-root.badssl.com/")
      expect(error).to eq ("error code 19: self signed certificate in certificate chain")
      expect(valid).to eq(false)
      expect(cert).to be_a OpenSSL::X509::Certificate
    end

    it "returns error on invalid host" do
      valid, error, cert = SSLTest.test("https://wrong.host.badssl.com/")
      expect(error).to include('hostname "wrong.host.badssl.com" does not match the server certificate')
      expect(valid).to eq(false)
      expect(cert).to be_a OpenSSL::X509::Certificate
    end

    it "returns error on expired cert" do
      valid, error, cert = SSLTest.test("https://expired.badssl.com/")
      expect(error).to eq ("error code 10: certificate has expired")
      expect(valid).to eq(false)
      expect(cert).to be_a OpenSSL::X509::Certificate
    end

    it "returns undetermined state on unhandled error" do
      valid, error, cert = SSLTest.test("https://pijoinlrfgind.com")
      expect(error).to eq ("SSL certificate test failed: Failed to open TCP connection to pijoinlrfgind.com:443 (getaddrinfo: Name or service not known)")
      expect(valid).to be_nil
      expect(cert).to be_nil
    end

    it "stops on timeouts" do
      valid, error, cert = SSLTest.test("https://updown.io", open_timeout: 0)
      expect(error).to eq ("SSL certificate test failed: Net::OpenTimeout")
      expect(valid).to be_nil
      expect(cert).to be_nil
    end

    it "reports revocation exceptions" do
      expect(SSLTest).to receive(:follow_ocsp_redirects).and_raise(ArgumentError.new("test"))
      valid, error, cert = SSLTest.test("https://updown.io")
      expect(error).to eq ("SSL certificate test failed: test")
      expect(valid).to be_nil
      expect(cert).to be_a OpenSSL::X509::Certificate
    end

    it "returns error on revoked cert (OCSP)" do
      expect(SSLTest).to receive(:follow_ocsp_redirects).once.and_call_original
      expect(SSLTest).not_to receive(:follow_crl_redirects)
      valid, error, cert = SSLTest.test("https://revoked.badssl.com/")
      expect(error).to eq ("SSL certificate revoked: The certificate was revoked for an unknown reason (revocation date: 2019-10-07 20:30:39 UTC)")
      expect(valid).to eq(false)
      expect(cert).to be_a OpenSSL::X509::Certificate
    end

    it "returns error on revoked cert (CRL)" do
      expect(SSLTest).to receive(:test_ocsp_revocation).once.and_return([false, "skip OCSP", nil])
      expect(SSLTest).to receive(:follow_crl_redirects).once.and_call_original
      valid, error, cert = SSLTest.test("https://revoked.badssl.com/")
      expect(error).to eq ("SSL certificate revoked: Unknown reason (revocation date: 2019-10-07 20:30:39 UTC)")
      expect(valid).to eq(false)
      expect(cert).to be_a OpenSSL::X509::Certificate
    end

    it "stops following redirection after the limit for the revoked certs check" do
      valid, error, cert = SSLTest.test("https://github.com/", redirection_limit: 0)
      expect(error).to eq ("Revocation test couldn't be performed: OCSP: Request failed (URI: http://ocsp.digicert.com): Too many redirections (> 0), CRL: Request failed (URI: http://crl3.digicert.com/sha2-ha-server-g6.crl): Too many redirections (> 0)")
      expect(valid).to eq(true)
      expect(cert).to be_a OpenSSL::X509::Certificate
    end

    it "warns when the OCSP URI is missing" do
      # Disable CRL fallback to see error message
      expect(SSLTest).to receive(:test_crl_revocation).once.and_return([false, "skip CRL", nil])
      expect(SSLTest).to receive(:follow_ocsp_redirects).once.and_call_original
      valid, error, cert = SSLTest.test("https://www.demarches-simplifiees.fr")
      expect(error).to eq ("Revocation test couldn't be performed: OCSP: Missing OCSP URI in authorityInfoAccess extension, CRL: skip CRL")
      expect(valid).to eq(true)
      expect(cert).to be_a OpenSSL::X509::Certificate
    end

    it "works with CRL only" do
      # Disable OCSP
      expect(SSLTest).to receive(:test_ocsp_revocation).twice.and_return([false, "skip OCSP", nil])
      expect(SSLTest).to receive(:follow_crl_redirects).twice.and_call_original
      valid, error, cert = SSLTest.test("https://www.demarches-simplifiees.fr")
      expect(error).to be_nil
      expect(valid).to eq(true)
      expect(cert).to be_a OpenSSL::X509::Certificate
    end

    it "warns when the CRL URI is missing" do
      # Disable OCSP to see error message
      expect(SSLTest).to receive(:test_ocsp_revocation).once.and_return([false, "skip OCSP", nil])
      expect(SSLTest).not_to receive(:follow_crl_redirects)
      valid, error, cert = SSLTest.test("https://meta.updown.io")
      expect(error).to eq ("Revocation test couldn't be performed: OCSP: skip OCSP, CRL: Missing crlDistributionPoints extension")
      expect(valid).to eq(true)
      expect(cert).to be_a OpenSSL::X509::Certificate
    end

    it "works with OCSP for first cert and CRL for intermediate (Let's Encrypt R3 intermediate)" do
      expect(SSLTest).to receive(:follow_ocsp_redirects).once.and_call_original
      expect(SSLTest).to receive(:follow_crl_redirects).once.and_call_original
      valid, error, cert = SSLTest.test("https://meta.updown.io/")
      expect(error).to be_nil
      expect(valid).to eq(true)
      expect(cert).to be_a OpenSSL::X509::Certificate
    end

    it "works with OCSP for first cert and CRL for intermediate (Certigna Services CA)" do
      expect(SSLTest).to receive(:follow_ocsp_redirects).once.and_call_original
      expect(SSLTest).to receive(:follow_crl_redirects).once.and_call_original
      # Similar chain: https://www.demarches-simplifiees.fr
      valid, error, cert = SSLTest.test("https://www.anonymisation.gov.pf")
      expect(error).to be_nil
      expect(valid).to eq(true)
      expect(cert).to be_a OpenSSL::X509::Certificate
    end
  end

  describe '.cache_size' do
    before { SSLTest.flush_cache }

    it "returns 0 by default" do
      expect(SSLTest.cache_size).to eq({
        crl:  { bytes: 0,  lists: 0 },
        ocsp: { bytes: 0, errors: 0, responses: 0 }
      })
    end

    it "returns CRL cache size properly" do
      SSLTest.send(:follow_crl_redirects, URI("http://crl.certigna.fr/certigna.crl")) # 1.3k
      SSLTest.send(:follow_crl_redirects, URI("http://crl3.digicert.com/ssca-sha2-g6.crl")) # 19M
      expect(SSLTest.cache_size[:crl][:lists]).to eq(2)
      expect(SSLTest.cache_size[:crl][:bytes]).to be > 19_000_000
    end

    it "returns OCSP cache size properly" do
      SSLTest.test("https://updown.io")
      expect(SSLTest.cache_size[:ocsp][:responses]).to eq(2)
      expect(SSLTest.cache_size[:ocsp][:errors]).to eq(0)
      expect(SSLTest.cache_size[:ocsp][:bytes]).to be > 200
    end
  end

  describe '.follow_crl_redirects' do
    before { SSLTest.flush_cache }
    # 19MB: http://crl3.digicert.com/ssca-sha2-g6.crl
    it "fetch CRL list and updates cache" do
      uri = URI("http://crl.certigna.fr/certigna.crl")
      body, error = SSLTest.send(:follow_crl_redirects, uri)
      expect(body.bytesize).to equal 1152
      expect(error).to be_nil

      # Check cache status
      cache = SSLTest.instance_variable_get('@crl_response_cache')
      expect(cache.size).to equal 1
      expect(cache.keys).to match_array [uri]
      expect(cache[uri].keys).to match_array [:body, :expires, :etag, :last_mod]
      expect(cache[uri][:expires]).to be > (Time.now + 3590)

      # Make sure we return value from cache
      body2, error2 = nil, nil
      time = Benchmark.realtime { body2, error2 = SSLTest.send(:follow_crl_redirects, uri) }
      expect(time).to be < 0.001 # no request
      expect(body2).to be(body) # using cache

      # Make sure we return cached value in case of 304
      cache[uri][:expires] = Time.now # cache is now expired
      body2, error2 = nil, nil
      time = Benchmark.realtime { body2, error2 = SSLTest.send(:follow_crl_redirects, uri) }
      expect(time).to be > 0.001 # a request is made
      expect(body2).to be(body) # but we're still using cache because it's a 304
    end
  end
end