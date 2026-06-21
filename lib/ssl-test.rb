require "net/http"
require "net/https"
require "openssl"
require "uri"
require "ssl-test/object_size"
require "ssl-test/memory_store"
require "ssl-test/ocsp"
require "ssl-test/crl"

module SSLTest
  extend OCSP
  extend CRL

  VERSION = -"2.1.0"

  # Prefix for all cache keys so SSLTest entries coexist cleanly inside a shared
  # cache (e.g. Rails.cache).
  CACHE_NAMESPACE = -"ssl-test"

  class << self
    def test_url url, open_timeout: 5, read_timeout: 5, proxy_host: nil, proxy_port: nil, redirection_limit: 5
      cert = failed_cert_reason = chain = nil

      uri = URI.parse(url)
      return if uri.scheme != 'https' and uri.scheme != 'tcps'

      @logger&.info { "SSLTest #{url} started" }
      http = Net::HTTP.new(uri.host, uri.port, proxy_host, proxy_port)
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

        revoked, message, revocation_date = test_chain_revocation(chain, open_timeout: open_timeout, read_timeout: read_timeout, proxy_host: proxy_host, proxy_port: proxy_port, redirection_limit: redirection_limit)
        @logger&.info { "SSLTest #{url} finished: revoked=#{revoked} #{message}" }
        return [!revoked, revocation_message(revoked, revocation_date, message), cert]
      rescue OpenSSL::SSL::SSLError => error
        error_message = parse_ssl_error(error, cert, failed_cert_reason, uri:)
        @logger&.info { "SSLTest #{url} finished: #{error_message}" }
        return [false, error_message, cert]
      rescue => error
        @logger&.error { "SSLTest #{url} failed: #{error.message}" }
        return [nil, "SSL certificate test failed: #{error.message}", cert]
      end
    end
    alias :test :test_url


    def test_cert client_cert, ca_certs, open_timeout: 5, read_timeout: 5, proxy_host:nil, proxy_port: nil, redirection_limit: 5
      cert = failed_cert_reason = chain = store = nil

      store = OpenSSL::X509::Store.new
      ca_certs.each { store.add_cert(_1) }
      store.verify_callback = -> (verify_ok, store_context) {
        cert = store_context.current_cert
        chain = store_context.chain
        failed_cert_reason = [store_context.error, store_context.error_string] if store_context.error != 0
        verify_ok
      }

      begin
        store.verify(client_cert)

        if failed_cert_reason
          error_message = "error code #{failed_cert_reason[0]}: #{failed_cert_reason[1]}"
          @logger&.info { "SSLTest #{cert.subject.to_s} finished: #{error_message}" }
          return [false, error_message, cert]
        else
          revoked, message, revocation_date = test_chain_revocation(chain, open_timeout: open_timeout, read_timeout: read_timeout, proxy_host: proxy_host, proxy_port: proxy_port, redirection_limit: redirection_limit)
          return [!revoked, revocation_message(revoked, revocation_date, message), cert]
        end
      rescue => error
        @logger&.error { "SSLTest #{cert.subject.to_s} failed: #{error.message}" }
        return [nil, "SSL certificate test failed: #{error.message}", cert]
      end
    end

    # The cache backend used to store CRL and OCSP responses. Defaults to an
    # in-process MemoryStore. To share the cache across processes (and get
    # compression), assign Rails.cache (or any object responding to the
    # Rails.cache-style API: read/write/delete), e.g. `SSLTest.cache = Rails.cache`.
    def cache
      @cache ||= MemoryStore.new
    end

    def cache= store
      @cache = store
    end

    # Removed in 2.0: introspection now lives on the cache store. With the
    # built-in MemoryStore use SSLTest.cache.size; other backends (e.g. memcache)
    # can't be enumerated.
    def cache_size
      raise NoMethodError, "SSLTest.cache_size was removed in 2.0; use SSLTest.cache.size instead (available on the built-in SSLTest::MemoryStore)."
    end

    # Removed in 2.0: clearing now lives on the cache store. With the built-in
    # MemoryStore use SSLTest.cache.clear (note: calling clear on a shared backend
    # like Rails.cache would wipe unrelated entries).
    def flush_cache
      raise NoMethodError, "SSLTest.flush_cache was removed in 2.0; use SSLTest.cache.clear instead."
    end

    def logger= logger
      @logger = logger
    end

    # The order in which revocation check methods are tried for each certificate.
    # The first method to return a conclusive answer (ok or revoked) wins; the
    # next is only tried when the previous one errors out (missing endpoint,
    # network error, etc.). Defaults to OCSP first, since CRLs can be large and
    # checking them is significantly more memory- and CPU-intensive. Set to
    # %i[crl ocsp] to check CRL first (e.g. to reduce revocation propagation delay).
    def revocation_order
      @revocation_order ||= %i[ocsp crl]
    end

    def revocation_order= order
      order = Array(order).map { |m| m.to_sym }
      unless order.sort == %i[crl ocsp]
        raise ArgumentError, "SSLTest.revocation_order must be %i[crl ocsp] or %i[ocsp crl], got #{order.inspect}"
      end
      @revocation_order = order
    end

    private

    def revocation_message(revoked, revocation_date, message)
      if revoked
        "SSL certificate revoked: #{message} (revocation date: #{revocation_date})"
      elsif message
        "Revocation test couldn't be performed: #{message}"
      end
    end

    def parse_ssl_error(error, cert, failed_cert_reason, uri:)
      message = error.message
      message = "error code %d: %s" % failed_cert_reason if failed_cert_reason
      if message =~ /certificate verify failed/
        domains = cert_domains(cert)
        if !uri.nil? && matching_domains(domains, uri.host).none?
          message = "hostname \"#{uri.host}\" does not match the server certificate (#{domains.join(', ')})"
        end
      end

      message
    end


    # https://docs.ruby-lang.org/en/2.2.0/OpenSSL/OCSP.html
    # https://stackoverflow.com/questions/16244084/how-to-programmatically-check-if-a-certificate-has-been-revoked#answer-16257470
    # Returns an array with [certificate_revoked?, error_reason, revocation_date]
    def test_chain_revocation chain, **options
      # Test each certificates in the chain except the last one (root cert),
      # which can only be revoked by removing it from the OS.
      chain[0..-2].each_with_index do |cert, i|
        @logger&.debug { "SSLTest + test_chain_revocation: #{cert_field_to_hash(cert.subject)['CN']}" }

        # Try each revocation method in the configured order, falling back to the
        # next one only when the current method errors out.
        errors = {}
        passed = false
        revocation_order.each do |method|
          result = test_revocation(method, cert, issuer: chain[i + 1], chain: chain, **options)
          @logger&.debug { "SSLTest   + #{method.to_s.upcase}: #{result}" }
          if result == :"#{method}_ok" # passed, go to next cert
            passed = true
            break
          end
          return result if result[0] == true # revoked
          errors[method] = result[1] # errored, try the next method
        end
        next if passed

        # If all methods failed, return a soft fail with a combination of the error messages
        return [false, errors.map { |method, message| "#{method.to_s.upcase}: #{message}" }.join(", "), nil]
      end

      # If all test passed, the certificate is not revoked
      [false, nil, nil]
    end

    def test_revocation method, cert, **options
      case method
      when :crl  then test_crl_revocation(cert, **options)
      when :ocsp then test_ocsp_revocation(cert, **options)
      end
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
