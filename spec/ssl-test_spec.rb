require "ssl-test"
require "benchmark"
require 'webrick'
require 'webrick/httpproxy'

# Uncomment for debug logging:
# require "logger"
# SSLTest.logger = Logger.new(STDOUT)

describe SSLTest do
  before { SSLTest.flush_cache }

  let(:proxy_thread) { nil }


  after(:each) do
    if proxy_thread
      proxy_thread.kill
    end
  end

  describe '.test_url' do
    it "returns no error on valid SNI website" do
      valid, error, cert = SSLTest.test("https://www.mycs.com")
      expect(error).to be_nil
      expect(valid).to eq(true)
      expect(cert).to be_a OpenSSL::X509::Certificate
    end

    it "returns no error on valid SAN" do
      # CN is updown.io, www.updown.io is an Alternative Name
      valid, error, cert = SSLTest.test("https://www.updown.io/")
      expect(error).to be_nil
      expect(valid).to eq(true)
      expect(cert).to be_a OpenSSL::X509::Certificate
    end

    # Disabled: unlikely to be repaired anytime soon: https://github.com/chromium/badssl.com/issues/447
    # Couldn't find a good alternative
    # it "returns no error when no CN" do
    #   pending "Expired for the moment https://github.com/chromium/badssl.com/issues/447"
    #   valid, error, cert = SSLTest.test("https://no-common-name.badssl.com/")
    #   expect(error).to be_nil
    #   expect(valid).to eq(true)
    #   expect(cert).to be_a OpenSSL::X509::Certificate
    # end

    it "works with websites blocking http requests" do
      valid, error, cert = SSLTest.test("https://obyava.ua")
      expect(error).to be_nil
      expect(valid).to eq(true)
      expect(cert).to be_a OpenSSL::X509::Certificate
    end

    it "returns error on self signed certificate" do
      valid, error, cert = SSLTest.test("https://self-signed.badssl.com/")
      expect(error).to eq ("error code 18: self-signed certificate")
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
      expect(error).to eq ("error code 19: self-signed certificate in certificate chain")
      expect(valid).to eq(false)
      expect(cert).to be_a OpenSSL::X509::Certificate
    end

    it "returns error on invalid host" do
      valid, error, cert = SSLTest.test("https://wrong.host.badssl.com/")
      expect(error).to include('error code 62: hostname mismatch')
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
      expect(error).to include("SSL certificate test failed: Failed to open TCP connection to pijoinlrfgind.com:443")
      expect(error).to include(/name.*not known/i)
      expect(valid).to be_nil
      expect(cert).to be_nil
    end

    it "stops on timeouts" do
      valid, error, cert = SSLTest.test("https://updown.io", open_timeout: 0)
      expect(error).to include("SSL certificate test failed")
      expect(error).to include(/timeout/i)
      expect(valid).to be_nil
      expect(cert).to be_nil
    end

    it "reports revocation exceptions" do
      expect(SSLTest).to receive(:follow_ocsp_redirects).and_raise(ArgumentError.new("test"))
      valid, error, cert = SSLTest.test("https://digicert.com")
      expect(error).to eq ("SSL certificate test failed: test")
      expect(valid).to be_nil
      expect(cert).to be_a OpenSSL::X509::Certificate
    end

    it "returns error on revoked cert (OCSP)" do
      expect(SSLTest).to receive(:follow_ocsp_redirects).once.and_call_original
      expect(SSLTest).not_to receive(:follow_crl_redirects)
      valid, error, cert = SSLTest.test("https://revoked-rsa-dv.ssl.com/")
      expect(error).to eq ("SSL certificate revoked: The certificate was revoked for an unknown reason (revocation date: 2025-06-09 15:07:39 UTC)")
      expect(valid).to eq(false)
      expect(cert).to be_a OpenSSL::X509::Certificate
    end

    it "returns error on revoked cert (CRL)" do
      expect(SSLTest).to receive(:test_ocsp_revocation).once.and_return([false, "skip OCSP", nil])
      expect(SSLTest).to receive(:follow_crl_redirects).once.and_call_original
      valid, error, cert = SSLTest.test("https://revoked.badssl.com/")
      expect(error).to eq ("SSL certificate revoked: Key Compromise (revocation date: 2025-11-04 21:01:29 UTC)")
      expect(valid).to eq(false)
      expect(cert).to be_a OpenSSL::X509::Certificate
    end

    it "stops following redirection after the limit for the revoked certs check" do
      valid, error, cert = SSLTest.test("https://github.com/", redirection_limit: 0)
      expect(error).to include("Revocation test couldn't be performed: OCSP: Request failed")
      expect(error).to include("Too many redirections (> 0)")
      expect(valid).to eq(true)
      expect(cert).to be_a OpenSSL::X509::Certificate
    end

    it "warns when the OCSP URI is missing" do
      # Disable CRL fallback to see error message
      expect(SSLTest).to receive(:test_crl_revocation).once.and_return([false, "skip CRL", nil])
      expect(SSLTest).to receive(:follow_ocsp_redirects).once.and_call_original
      valid, error, cert = SSLTest.test("https://google.com")
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
      valid, error, cert = SSLTest.test("https://github.com")
      expect(error).to eq ("Revocation test couldn't be performed: OCSP: skip OCSP, CRL: Missing crlDistributionPoints extension")
      expect(valid).to eq(true)
      expect(cert).to be_a OpenSSL::X509::Certificate
    end

    it "works with OCSP for first cert and CRL for intermediate (Google)" do
      expect(SSLTest).to receive(:follow_ocsp_redirects).once.and_call_original
      expect(SSLTest).to receive(:follow_crl_redirects).once.and_call_original
      valid, error, cert = SSLTest.test("https://google.com")
      expect(error).to be_nil
      expect(valid).to eq(true)
      expect(cert).to be_a OpenSSL::X509::Certificate
      # make sure both were used
      expect(SSLTest.cache_size).to match({
        crl:  hash_including(lists: 1),
        ocsp: hash_including(responses: 1, errors: 0)
      })
    end

    it "accepts tcps scheme" do
      valid, error, cert = SSLTest.test("tcps://updown.io:443")
      expect(error).to be_nil
      expect(valid).to eq(true)
      expect(cert).to be_a OpenSSL::X509::Certificate
    end

    context 'when specifying a proxy' do
      let(:proxy_thread) do
        Thread.new do
          dev_null = WEBrick::Log::new("/dev/null", 7)
          proxy = WEBrick::HTTPProxyServer.new Port: 8080,  :Logger => dev_null, :AccessLog => []
          proxy.start
        end
      end

      context 'when the proxy is active' do
        it 'uses the provided http proxy' do
          proxy_thread
          sleep 0.1 # wait for the proxy to start!

          valid, error, cert = SSLTest.test("https://updown.io", proxy_host: '127.0.0.1', proxy_port: 8080)
          expect(error).to be_nil
          expect(valid).to eq(true)
          expect(cert).to be_a OpenSSL::X509::Certificate
        end
      end

      context 'when the proxy is not reachable' do
        it 'returns a http error' do
          valid, error, cert = SSLTest.test("https://updown.io", proxy_host: '127.0.0.1', proxy_port: 55000)
          expect(error).to include('(Connection refused - connect(2) for "127.0.0.1" port 55000)')
          expect(valid).to be_nil
          expect(cert).to be_nil
        end
      end
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
      SSLTest.send(:follow_crl_redirects, URI("http://crl.certigna.fr/certigna.crl")) # 1.1k
      SSLTest.send(:follow_crl_redirects, URI("http://crl3.digicert.com/DigiCertTLSHybridECCSHA3842020CA1-1.crl")) # 26k
      expect(SSLTest.cache_size[:crl][:lists]).to eq(2)
      expect(SSLTest.cache_size[:crl][:bytes]).to be > 6000
    end

    it "returns OCSP cache size properly" do
      SSLTest.test("https://google.com")
      expect(SSLTest.cache_size[:ocsp][:responses]).to eq(1)
      expect(SSLTest.cache_size[:ocsp][:errors]).to eq(0)
      expect(SSLTest.cache_size[:ocsp][:bytes]).to be > 150
      expect(SSLTest.cache_size[:crl][:lists]).to eq(1)
      expect(SSLTest.cache_size[:crl][:bytes]).to be > 500
    end
  end

  describe '.follow_crl_redirects' do
    before { SSLTest.flush_cache }
    # 19MB: http://crl3.digicert.com/ssca-sha2-g6.crl
    it "fetch CRL list and updates cache" do
      uri = URI("http://crl.certigna.fr/certigna.crl")
      body, error = SSLTest.send(:follow_crl_redirects, uri)
      expect(body.bytesize).to equal 1417
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

  describe '.test_cert' do
    it "returns no error on valid SNI website" do
      cert = OpenSSL::X509::Certificate.new(File.read(File.join(__dir__, 'fixtures/www_mycs_com_client.pem')))
      ca_bundle = OpenSSL::X509::Certificate.load(File.read(File.join(__dir__, 'fixtures/www_mycs_com_ca_bundle.pem')))

      valid, error, cert = SSLTest.test_cert(cert, ca_bundle)
      expect(error).to be_nil
      expect(valid).to eq(true)
      expect(cert).to eq(cert)
    end

    it "returns no error on self signed certificates" do
      cert = OpenSSL::X509::Certificate.new(File.read(File.join(__dir__, 'fixtures/self_signed_client.pem')))
      ca_bundle = OpenSSL::X509::Certificate.load(File.read(File.join(__dir__, 'fixtures/self_signed_ca_bundle.pem')))

      valid, error, cert = SSLTest.test_cert(cert, ca_bundle)
      expect(error).to be_nil
      expect(valid).to eq(true)
      expect(cert).to eq(cert)
    end

    it "returns error on expired cert" do
      cert = OpenSSL::X509::Certificate.new(File.read(File.join(__dir__, 'fixtures/expired_cert_client.pem')))
      ca_bundle = OpenSSL::X509::Certificate.load(File.read(File.join(__dir__, 'fixtures/expired_cert_ca_bundle.pem')))

      valid, error, cert = SSLTest.test_cert(cert, ca_bundle)
      expect(error).to eq ("error code 10: certificate has expired")
      expect(valid).to eq(false)
      expect(cert).to be_a OpenSSL::X509::Certificate
    end

    it "stops following redirection after the limit for the revoked certs check" do
      cert = OpenSSL::X509::Certificate.new(File.read(File.join(__dir__, 'fixtures/www_github_com_client.pem')))
      ca_bundle = OpenSSL::X509::Certificate.load(File.read(File.join(__dir__, 'fixtures/www_github_com_ca_bundle.pem')))

      valid, error, cert = SSLTest.test_cert(cert, ca_bundle, redirection_limit: 0)
      expect(error).to include("Revocation test couldn't be performed: OCSP: Request failed")
      expect(error).to include("Too many redirections (> 0)")
      expect(valid).to eq(true)
      expect(cert).to be_a OpenSSL::X509::Certificate
    end


    it "works with OCSP for first cert and CRL for intermediate (Google)" do
      expect(SSLTest).to receive(:follow_ocsp_redirects).once.and_call_original
      expect(SSLTest).to receive(:follow_crl_redirects).once.and_call_original

      cert = OpenSSL::X509::Certificate.new(File.read(File.join(__dir__, 'fixtures/google_com_client.pem')))
      ca_bundle = OpenSSL::X509::Certificate.load(File.read(File.join(__dir__, 'fixtures/google_com_ca_bundle.pem')))

      valid, error, cert = SSLTest.test_cert(cert, ca_bundle)
      expect(error).to be_nil
      expect(valid).to eq(true)
      expect(cert).to be_a OpenSSL::X509::Certificate
      # make sure both were used
      expect(SSLTest.cache_size).to match({
        crl:  hash_including(lists: 1),
        ocsp: hash_including(responses: 1, errors: 0)
      })
    end

    context 'when specifying a proxy' do
      let(:proxy_thread) do
        Thread.new do
          dev_null = WEBrick::Log::new("/dev/null", 7)
          proxy = WEBrick::HTTPProxyServer.new Port: 8080,  :Logger => dev_null, :AccessLog => []
          proxy.start
        end
      end

      context 'when the proxy is active' do
        it 'uses the provided http proxy' do
          proxy_thread
          sleep 0.1 # wait for the proxy to start!

          cert = OpenSSL::X509::Certificate.new(File.read(File.join(__dir__, 'fixtures/google_com_client.pem')))
          ca_bundle = OpenSSL::X509::Certificate.load(File.read(File.join(__dir__, 'fixtures/google_com_ca_bundle.pem')))

          valid, error, cert = SSLTest.test_cert(cert, ca_bundle, proxy_host: '127.0.0.1', proxy_port: 8080)
          expect(error).to be_nil
          expect(valid).to eq(true)
          expect(cert).to eq(cert)
        end
      end

      context 'when the proxy is not reachable' do
        it 'returns a http error' do
          cert = OpenSSL::X509::Certificate.new(File.read(File.join(__dir__, 'fixtures/google_com_client.pem')))
          ca_bundle = OpenSSL::X509::Certificate.load(File.read(File.join(__dir__, 'fixtures/google_com_ca_bundle.pem')))

          valid, error, cert = SSLTest.test_cert(cert, ca_bundle, proxy_host: '127.0.0.1', proxy_port: 55000)
          expect(error).to include('(Connection refused - connect(2) for "127.0.0.1" port 55000)')
          expect(valid).to be_nil
          expect(cert).to eq(cert)
        end
      end
      end

    end
end
