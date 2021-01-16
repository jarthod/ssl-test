require "net/http"
require "net/https"
require "openssl"
require "uri"
require "ssl-test/object_size"
require "ssl-test/ocsp"
require "ssl-test/crl"

module SSLTest
  extend OCSP
  extend CRL

  VERSION = -"1.4.0"

  class << self
    def test url, open_timeout: 5, read_timeout: 5, redirection_limit: 5
      uri = URI.parse(url)
      return if uri.scheme != 'https'
      cert = failed_cert_reason = chain = nil

      @logger&.info { "SSLTest #{url} started" }
      http = Net::HTTP.new(uri.host, uri.port)
      http.open_timeout = open_timeout
      http.read_timeout = read_timeout
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_PEER
      http.verify_callback = -> (verify_ok, store_context) {
        cert = store_context.current_cert
        chain = store_context.chain
        failed_cert_reason = [store_context.error, store_context.error_string] if store_context.error != 0
        verify_ok
      }

      begin
        http.start { }
        revoked, message, revocation_date = test_chain_revocation(chain, open_timeout: open_timeout, read_timeout: read_timeout, redirection_limit: redirection_limit)
        @logger&.info { "SSLTest #{url} finished: revoked=#{revoked} #{message}" }
        return [false, "SSL certificate revoked: #{message} (revocation date: #{revocation_date})", cert] if revoked
        return [true, "Revocation test couldn't be performed: #{message}", cert] if message
        return [true, nil, cert]
      rescue OpenSSL::SSL::SSLError => e
        error = e.message
        error = "error code %d: %s" % failed_cert_reason if failed_cert_reason
        if error =~ /certificate verify failed/
          domains = cert_domains(cert)
          if matching_domains(domains, uri.host).none?
            error = "hostname \"#{uri.host}\" does not match the server certificate (#{domains.join(', ')})"
          end
        end
        @logger&.info { "SSLTest #{url} finished: #{error}" }
        return [false, error, cert]
      rescue => e
        @logger&.error { "SSLTest #{url} failed: #{e.message}" }
        return [nil, "SSL certificate test failed: #{e.message}", cert]
      end
    end

    def cache_size
      {
        crl: {
          lists: @crl_response_cache&.size || 0,
          bytes: ObjectSize.size(@crl_response_cache)
        },
        ocsp: {
          responses: @ocsp_response_cache&.size || 0,
          errors: @ocsp_request_error_cache&.size || 0,
          bytes: ObjectSize.size(@ocsp_response_cache) + ObjectSize.size(@ocsp_request_error_cache)
        }
      }
    end

    def flush_cache
      @crl_response_cache = {}
      @ocsp_response_cache = {}
      @ocsp_request_error_cache = {}
    end

    def logger= logger
      @logger = logger
    end

    private

    # https://docs.ruby-lang.org/en/2.2.0/OpenSSL/OCSP.html
    # https://stackoverflow.com/questions/16244084/how-to-programmatically-check-if-a-certificate-has-been-revoked#answer-16257470
    # Returns an array with [certificate_revoked?, error_reason, revocation_date]
    def test_chain_revocation chain, **options
      # Test each certificates in the chain except the last one (root cert),
      # which can only be revoked by removing it from the OS.
      chain[0..-2].each_with_index do |cert, i|
        @logger&.debug { "SSLTest + test_chain_revocation: #{cert_field_to_hash(cert.subject)['CN']}" }

        # Try with OCSP first
        ocsp_result = test_ocsp_revocation(cert, issuer: chain[i + 1], chain: chain, **options)
        @logger&.debug { "SSLTest   + OCSP: #{ocsp_result}" }
        next if ocsp_result == :ocsp_ok # passed, go to next cert
        return ocsp_result if ocsp_result[0] == true # revoked

        # Otherwise it means there was an error so let's try with CRL instead
        crl_result = test_crl_revocation(cert, issuer: chain[i + 1], chain: chain, **options)
        @logger&.debug { "SSLTest   + CRL: #{crl_result}" }
        next if crl_result == :crl_ok # passed, go to next cert
        return crl_result if crl_result[0] == true # revoked

        # If both method failed, return a soft fail with a combination of both error messages
        return [false, "OCSP: #{ocsp_result[1]}, CRL: #{crl_result[1]}", nil]
      end

      # If all test passed, the certificate is not revoked
      [false, nil, nil]
    end

    def cert_field_to_hash field
      field.to_a.each.with_object({}) do |v, h|
        v = v.to_a
        h[v[0]] = v[1].encode('UTF-8', undef: :replace, invalid: :replace)
      end
    end

    def cert_domains cert
      (Array(cert_field_to_hash(cert.subject)['CN']) +
        cert_field_to_hash(cert.extensions)['subjectAltName'].split(/\s*,\s*/))
        .compact
        .map {|s| s.gsub(/^DNS:/, '') }
        .uniq
    end

    def matching_domains domains, hostname
      domains.map {|s| Regexp.new("\A#{Regexp.escape(s).gsub('\*', '[^.]+')}\z") }
        .select {|domain| domain.match?(hostname) }
    end
  end
end
