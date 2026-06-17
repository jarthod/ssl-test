require "ssl-test"
require "benchmark"
require 'webrick'
require 'webrick/httpproxy'
require 'rspec/retry'

# Uncomment for debug logging:
# require "logger"
# SSLTest.logger = Logger.new(STDOUT)

RSpec.configure do |config|
  # The error/revocation examples below hit several public TLS test endpoints
  # (badssl.com, testserver.host, ssl.com) which intermittently reset connections
  # under load. They're spread across a few providers to avoid hammering a single
  # one, and the network-hitting describe blocks are tagged `retry: 5` (via
  # rspec-retry) so transient network blips don't fail the suite.
  config.verbose_retry = true
  config.default_sleep_interval = 1
end

describe SSLTest do
  before { SSLTest.cache.clear }

  let(:proxy_thread) { nil }


  after(:each) { proxy_thread&.kill }

  describe '.test_url', retry: 5 do # examples hit live TLS/CRL/OCSP endpoints
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
      valid, error, cert = SSLTest.test("https://self-signed.testserver.host/")
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
      valid, error, cert = SSLTest.test("https://untrusted-root.testserver.host/")
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
      valid, error, cert = SSLTest.test("https://expired-rsa-dv.ssl.com/")
      expect(error).to eq ("error code 10: certificate has expired")
      expect(valid).to eq(false)
      expect(cert).to be_a OpenSSL::X509::Certificate
    end

    it "returns undetermined state on unhandled error" do
      valid, error, cert = SSLTest.test("https://pijoinlrfgind.com")
      expect(error).to include("SSL certificate test failed: Failed to open TCP connection to pijoinlrfgind.com:443")
      expect(error).to match(/name.*not known/i)
      expect(valid).to be_nil
      expect(cert).to be_nil
    end

    it "stops on timeouts" do
      valid, error, cert = SSLTest.test("https://updown.io", open_timeout: 0)
      expect(error).to include("SSL certificate test failed")
      expect(error).to match(/timeout/i)
      expect(valid).to be_nil
      expect(cert).to be_nil
    end

    it "reports revocation exceptions" do
      expect(SSLTest).to receive(:follow_crl_redirects).and_raise(ArgumentError.new("test"))
      valid, error, cert = SSLTest.test("https://digicert.com")
      expect(error).to eq ("SSL certificate test failed: test")
      expect(valid).to be_nil
      expect(cert).to be_a OpenSSL::X509::Certificate
    end

    it "returns error on revoked cert (OCSP)" do
      # CRL is tried first; disable it so OCSP performs the revocation check
      expect(SSLTest).to receive(:test_crl_revocation).once.and_return([false, "skip CRL", nil])
      expect(SSLTest).to receive(:follow_ocsp_redirects).once.and_call_original
      valid, error, cert = SSLTest.test("https://revoked-rsa-dv.ssl.com/")
      expect(error).to eq ("SSL certificate revoked: The certificate was revoked for an unspecified reason (revocation date: 2026-06-09 14:37:38 UTC)")
      expect(valid).to eq(false)
      expect(cert).to be_a OpenSSL::X509::Certificate
    end

    it "returns error on revoked cert (CRL)" do
      # CRL is tried first and detects the revocation, so OCSP is never used
      expect(SSLTest).to receive(:follow_crl_redirects).once.and_call_original
      expect(SSLTest).not_to receive(:test_ocsp_revocation)
      valid, error, cert = SSLTest.test("https://revoked.badssl.com/")
      expect(error).to eq ("SSL certificate revoked: Key Compromise (revocation date: 2026-05-12 21:01:31 UTC)")
      expect(valid).to eq(false)
      expect(cert).to be_a OpenSSL::X509::Certificate
    end

    it "stops following redirection after the limit for the revoked certs check" do
      valid, error, cert = SSLTest.test("https://github.com/", redirection_limit: 0)
      expect(error).to include("Revocation test couldn't be performed: CRL: Missing crlDistributionPoints extension")
      expect(error).to include("OCSP: Request failed")
      expect(error).to include("Too many redirections (> 0)")
      expect(valid).to eq(true)
      expect(cert).to be_a OpenSSL::X509::Certificate
    end

    it "warns when the OCSP URI is missing" do
      # Disable CRL (tried first) to see the OCSP error message
      expect(SSLTest).to receive(:test_crl_revocation).twice.and_return([false, "skip CRL", nil])
      expect(SSLTest).to receive(:follow_ocsp_redirects).once.and_call_original
      valid, error, cert = SSLTest.test("https://google.com")
      expect(error).to eq ("Revocation test couldn't be performed: CRL: skip CRL, OCSP: Missing OCSP URI in authorityInfoAccess extension")
      expect(valid).to eq(true)
      expect(cert).to be_a OpenSSL::X509::Certificate
    end

    it "works with CRL only" do
      # CRL is tried first and succeeds for both certs, so OCSP is never used
      expect(SSLTest).to receive(:follow_crl_redirects).twice.and_call_original
      expect(SSLTest).not_to receive(:test_ocsp_revocation)
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
      expect(error).to eq ("Revocation test couldn't be performed: CRL: Missing crlDistributionPoints extension, OCSP: skip OCSP")
      expect(valid).to eq(true)
      expect(cert).to be_a OpenSSL::X509::Certificate
    end

    it "works with OCSP for first cert and CRL for intermediate (GitHub)" do
      expect(SSLTest).to receive(:follow_ocsp_redirects).once.and_call_original
      expect(SSLTest).to receive(:follow_crl_redirects).once.and_call_original
      valid, error, cert = SSLTest.test("https://github.com")
      expect(error).to be_nil
      expect(valid).to eq(true)
      expect(cert).to be_a OpenSSL::X509::Certificate
      # make sure both were used
      expect(SSLTest.cache.size).to match({
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
      context 'when the proxy is active' do
        let(:proxy_thread) do
          thread = Thread.new do
            dev_null = WEBrick::Log::new("/dev/null", 7)
            $proxy = WEBrick::HTTPProxyServer.new Port: 8080,  :Logger => dev_null, :AccessLog => []
            $proxy.start
          end

          sleep 0.1 # wait for the proxy to start!
          allow($proxy).to receive(:do_GET).and_call_original

          thread
        end

        it 'uses the provided http proxy' do
          proxy_thread

          valid, error, cert = SSLTest.test("https://updown.io", proxy_host: '127.0.0.1', proxy_port: 8080)
          expect(error).to be_nil
          expect(valid).to eq(true)
          expect(cert).to be_a OpenSSL::X509::Certificate

          expect($proxy).to have_received(:do_GET).twice
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

  describe '.follow_crl_redirects', retry: 5 do # fetches a live CRL
    before { SSLTest.cache.clear }
    # 19MB: http://crl3.digicert.com/ssca-sha2-g6.crl
    it "fetch CRL list and updates cache" do
      uri = URI("http://crl.certigna.fr/certigna.crl")
      body, error = SSLTest.send(:follow_crl_redirects, uri)
      expect(body.bytesize).to equal 1417
      expect(error).to be_nil

      # Check cache status
      cache_key = "ssl-test/crl/#{uri}"
      entry = SSLTest.cache.read(cache_key)
      expect(entry).not_to be_nil
      expect(entry.keys).to match_array [:body, :expires, :etag, :last_mod]
      expect(entry[:expires]).to be > (Time.now + 3590)

      # Make sure we return value from cache
      body2, error2 = nil, nil
      time = Benchmark.realtime { body2, error2 = SSLTest.send(:follow_crl_redirects, uri) }
      expect(time).to be < 0.001 # no request
      expect(body2).to be(body) # using cache

      # Make sure we return cached value in case of 304
      SSLTest.cache.write(cache_key, entry.merge(expires: Time.now), expires_in: nil) # cache is now expired
      body2, error2 = nil, nil
      time = Benchmark.realtime { body2, error2 = SSLTest.send(:follow_crl_redirects, uri) }
      expect(time).to be > 0.001 # a request is made
      expect(body2).to be(body) # but we're still using cache because it's a 304
    end
  end

  describe '.cache', retry: 5 do # some examples hit live CRL/OCSP endpoints
    # Restore the default in-process store after tests that swap the backend so
    # global state doesn't leak between examples.
    after { SSLTest.cache = SSLTest::MemoryStore.new }

    it "defaults to an in-process MemoryStore" do
      SSLTest.instance_variable_set(:@cache, nil) # reset memoized default
      expect(SSLTest.cache).to be_a SSLTest::MemoryStore
    end

    it "uses the configured backend for CRL and OCSP" do
      store = SSLTest::MemoryStore.new
      SSLTest.cache = store
      expect(store).to receive(:write).at_least(:once).and_call_original
      expect(store).to receive(:read).at_least(:once).and_call_original
      SSLTest.test("https://github.com")
    end

    it "cache_size (removed in 2.0) raises pointing to cache.size" do
      expect { SSLTest.cache_size }.to raise_error(NoMethodError, /SSLTest\.cache\.size/)
    end

    it "flush_cache (removed in 2.0) raises pointing to cache.clear" do
      expect { SSLTest.flush_cache }.to raise_error(NoMethodError, /SSLTest\.cache\.clear/)
    end
  end

  describe '.test_cert', retry: 5 do # revocation checks hit live CRL/OCSP endpoints
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
      expect(cert).to eq(cert)
    end

    it "returns error on incomplete chain" do
      cert = OpenSSL::X509::Certificate.new(File.read(File.join(__dir__, 'fixtures/incomplete_chain_client.pem')))
      ca_bundle = OpenSSL::X509::Certificate.load(File.read(File.join(__dir__, 'fixtures/incomplete_chain_ca_bundle.pem')))
      valid, error, cert = SSLTest.test_cert(cert, ca_bundle)
      expect(error).to eq ("error code 20: unable to get local issuer certificate")
      expect(valid).to eq(false)
      expect(cert).to eq(cert)
    end

    it "reports revocation exceptions" do
      cert = OpenSSL::X509::Certificate.new(File.read(File.join(__dir__, 'fixtures/digicert_com_client.pem')))
      ca_bundle = OpenSSL::X509::Certificate.load(File.read(File.join(__dir__, 'fixtures/digicert_com_ca_bundle.pem')))
      expect(SSLTest).to receive(:follow_crl_redirects).and_raise(ArgumentError.new("test"))
      valid, error, cert = SSLTest.test_cert(cert, ca_bundle)
      expect(error).to eq("SSL certificate test failed: test")
      expect(valid).to be_nil
      expect(cert).to eq(cert)
    end

    it "returns error on revoked cert (OCSP)" do
      cert = OpenSSL::X509::Certificate.new(File.read(File.join(__dir__, 'fixtures/revoked_rsa_dv_client.pem')))
      ca_bundle = OpenSSL::X509::Certificate.load(File.read(File.join(__dir__, 'fixtures/revoked_rsa_dv_ca_bundle.pem')))

      # CRL is tried first; disable it so OCSP performs the revocation check
      expect(SSLTest).to receive(:test_crl_revocation).once.and_return([false, "skip CRL", nil])
      expect(SSLTest).to receive(:follow_ocsp_redirects).once.and_call_original

      valid, error, cert = SSLTest.test_cert(cert, ca_bundle)
      expect(error).to eq ("SSL certificate revoked: The certificate was revoked for an unknown reason (revocation date: 2025-06-09 15:07:39 UTC)")
      expect(valid).to eq(false)
      expect(cert).to eq(cert)
    end

    it "returns error on revoked cert (CRL)" do
      cert = OpenSSL::X509::Certificate.new(File.read(File.join(__dir__, 'fixtures/revoked_badssl_client.pem')))
      ca_bundle = OpenSSL::X509::Certificate.load(File.read(File.join(__dir__, 'fixtures/revoked_badssl_ca_bundle.pem')))

      # CRL is tried first and detects the revocation, so OCSP is never used
      expect(SSLTest).to receive(:follow_crl_redirects).once.and_call_original
      expect(SSLTest).not_to receive(:test_ocsp_revocation)
      valid, error, cert = SSLTest.test_cert(cert, ca_bundle)
      expect(error).to eq ("SSL certificate revoked: Key Compromise (revocation date: 2026-05-12 21:01:31 UTC)")
      expect(valid).to eq(false)
      expect(cert).to eq(cert)
    end

    it "stops following redirection after the limit for the revoked certs check" do
      cert = OpenSSL::X509::Certificate.new(File.read(File.join(__dir__, 'fixtures/www_github_com_client.pem')))
      ca_bundle = OpenSSL::X509::Certificate.load(File.read(File.join(__dir__, 'fixtures/www_github_com_ca_bundle.pem')))

      valid, error, cert = SSLTest.test_cert(cert, ca_bundle, redirection_limit: 0)
      expect(error).to include("Revocation test couldn't be performed: CRL: Missing crlDistributionPoints extension")
      expect(error).to include("OCSP: Request failed")
      expect(error).to include("Too many redirections (> 0)")
      expect(valid).to eq(true)
      expect(cert).to eq(cert)
    end

    it "warns when the OCSP URI is missing" do
      cert = OpenSSL::X509::Certificate.new(File.read(File.join(__dir__, 'fixtures/google_com_client.pem')))
      ca_bundle = OpenSSL::X509::Certificate.load(File.read(File.join(__dir__, 'fixtures/google_com_ca_bundle.pem')))

      # Disable CRL (tried first) to see the OCSP error message
      expect(SSLTest).to receive(:test_crl_revocation).twice.and_return([false, "skip CRL", nil])
      expect(SSLTest).to receive(:follow_ocsp_redirects).once.and_call_original

      valid, error, cert = SSLTest.test_cert(cert, ca_bundle)
      expect(error).to eq ("Revocation test couldn't be performed: CRL: skip CRL, OCSP: Missing OCSP URI in authorityInfoAccess extension")
      expect(valid).to eq(true)
      expect(cert).to eq(cert)
    end

    it "works with CRL only" do
      cert = OpenSSL::X509::Certificate.new(File.read(File.join(__dir__, 'fixtures/www_demarches-simplifiees_fr_client.pem')))
      ca_bundle = OpenSSL::X509::Certificate.load(File.read(File.join(__dir__, 'fixtures/www_demarches-simplifiees_fr_ca_bundle.pem')))

      # CRL is tried first and succeeds for both certs, so OCSP is never used
      expect(SSLTest).to receive(:follow_crl_redirects).twice.and_call_original
      expect(SSLTest).not_to receive(:test_ocsp_revocation)

      valid, error, cert = SSLTest.test_cert(cert, ca_bundle)
      expect(error).to be_nil
      expect(valid).to eq(true)
      expect(cert).to eq(cert)
    end

    it "warns when the CRL URI is missing" do
      cert = OpenSSL::X509::Certificate.new(File.read(File.join(__dir__, 'fixtures/www_github_com_client.pem')))
      ca_bundle = OpenSSL::X509::Certificate.load(File.read(File.join(__dir__, 'fixtures/www_github_com_ca_bundle.pem')))

      # Disable OCSP to see error message
      expect(SSLTest).to receive(:test_ocsp_revocation).once.and_return([false, "skip OCSP", nil])
      expect(SSLTest).not_to receive(:follow_crl_redirects)

      valid, error, cert = SSLTest.test_cert(cert, ca_bundle)
      expect(error).to eq ("Revocation test couldn't be performed: CRL: Missing crlDistributionPoints extension, OCSP: skip OCSP")
      expect(valid).to eq(true)
      expect(cert).to eq(cert)

    end

    it "works with OCSP for first cert and CRL for intermediate (GitHub)" do
      expect(SSLTest).to receive(:follow_ocsp_redirects).once.and_call_original
      expect(SSLTest).to receive(:follow_crl_redirects).once.and_call_original

      cert = OpenSSL::X509::Certificate.new(File.read(File.join(__dir__, 'fixtures/www_github_com_client.pem')))
      ca_bundle = OpenSSL::X509::Certificate.load(File.read(File.join(__dir__, 'fixtures/www_github_com_ca_bundle.pem')))

      valid, error, cert = SSLTest.test_cert(cert, ca_bundle)
      expect(error).to be_nil
      expect(valid).to eq(true)
      expect(cert).to eq(cert)
      # make sure both were used
      expect(SSLTest.cache.size).to match({
        crl:  hash_including(lists: 1),
        ocsp: hash_including(responses: 1, errors: 0)
      })
    end

    context 'when specifying a proxy' do
      context 'when the proxy is active' do
        let(:proxy_thread) do
          thread = Thread.new do
            dev_null = WEBrick::Log::new("/dev/null", 7)
            $proxy = WEBrick::HTTPProxyServer.new Port: 8080,  :Logger => dev_null, :AccessLog => []
            $proxy.start
          end

          sleep 0.1 # wait for the proxy to start!
          allow($proxy).to receive(:do_GET).and_call_original

          thread
        end

        it 'uses the provided http proxy' do
          proxy_thread

          cert = OpenSSL::X509::Certificate.new(File.read(File.join(__dir__, 'fixtures/google_com_client.pem')))
          ca_bundle = OpenSSL::X509::Certificate.load(File.read(File.join(__dir__, 'fixtures/google_com_ca_bundle.pem')))

          valid, error, cert = SSLTest.test_cert(cert, ca_bundle, proxy_host: '127.0.0.1', proxy_port: 8080)
          expect(error).to be_nil
          expect(valid).to eq(true)
          expect(cert).to eq(cert)

          # CRL is tried first, so both certs are checked via CRL (GET) through the proxy
          expect($proxy).to have_received(:do_GET).twice
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
