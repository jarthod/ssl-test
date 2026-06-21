module SSLTest
  module CRL
    CRL_CACHE_DURATION = 3600 # 1 hour
    # How long a CRL entry is kept in the backend before being dropped if it's no
    # longer used. This is much longer than CRL_CACHE_DURATION so the cached body
    # and caching headers survive past the revalidation window (for cheap 304s),
    # but bounded so unused lists don't pile up forever in a shared/long-lived
    # backend (e.g. memcache). It's refreshed on every fetch (200/304), so
    # actively-used entries never expire from this.
    CRL_CACHE_RETENTION = 100 * CRL_CACHE_DURATION # ~4 days

    # A note about caching:
    # I choose to only cache the raw HTTP body here (and not the parsed list or better a hash
    # indexed by certificat serial). This is not CPU efficient because it means every time we
    # need to check a cert from a cached CRL we need to read it again, optionally instantiate the list
    # of Revoked certs and then iterate to find it (there's no API to find one cert without
    # generting the list yet: https://github.com/ruby/openssl/pull/1065).
    # I did this because of memory efficiency, because for big 20MB CRL list (so taking 20MB
    # in memory cache), the parsed version takes more than 100M, the list of Revoked certs 120MB,
    # and building a hash with serial, time and reason takes even more.
    # So doing this would be MUCH faster in terms of CPU for subsequent tests on the same CRL
    # but would take a LOT of memory.

    private

    def test_crl_revocation cert, issuer:, chain:, **options
      crl = cert.crl_uris&.first
      return [false, "Missing crlDistributionPoints extension", nil] if crl.nil?

      crl_uri = URI(crl)
      http_response, crl_request_error = follow_crl_redirects(crl_uri, **options)
      return [false, "Request failed (URI: #{crl_uri}): #{crl_request_error}", nil] unless http_response

      response = OpenSSL::X509::CRL.new http_response
      return [false, "Signature verification failed (URI: #{crl_uri})", nil] unless response.verify(issuer.public_key)

      # Fast path: scan the raw response for the cert's serial encoded as DER.
      # In most case (not revoked) this lets us skip response.revoked, which
      # instantiate the *entire* revocation list as Ruby objects (>1M objects for busy CAs)
      serial_der = OpenSSL::ASN1::Integer.new(cert.serial).to_der
      return :crl_ok unless response.to_der.include?(serial_der)

      # The serial's bytes appear (a real hit, or a rare collision):
      # confirm authoritatively and pull the reason/date. The costly revoked-list
      # materialisation only happens here, i.e. for actually-revoked certs.
      revoked = response.revoked.find { |r| r.serial == cert.serial }
      if revoked
        reason = revoked.extensions.find {|e| e.oid == "CRLReason"}&.value
        return [true, reason || "Unknown reason", revoked.time]
      end

      :crl_ok
    end

    # Returns an array with [response, error_message]
    def follow_crl_redirects(uri, open_timeout: 5, read_timeout: 5, redirection_limit: 5, proxy_host: nil, proxy_port: nil)
      return [nil, "Too many redirections (> #{redirection_limit})"] if redirection_limit == 0

      # Return file from cache if not expired.
      # CRL entries are kept in the backend for CRL_CACHE_RETENTION (much longer
      # than CRL_CACHE_DURATION) so the cached body + caching headers survive past
      # the freshness window and can be revalidated cheaply with a conditional
      # request (304). We track our own freshness window with the :expires field.
      cache_key = "#{CACHE_NAMESPACE}/crl/#{uri}"
      cache_entry = cache.read(cache_key)
      return [cache_entry[:body], nil] if cache_entry && cache_entry[:expires] > Time.now

      @logger&.debug { "SSLTest   + CRL: fetch URI #{uri}" }
      path = uri.path == "" ? "/" : uri.path
      http = Net::HTTP.new(uri.hostname, uri.port, proxy_host, proxy_port)
      http.open_timeout = open_timeout
      http.read_timeout = read_timeout

      req = Net::HTTP::Get.new(path)
      # Include conditional caching headers from cache to save bandwidth if the
      # list didn't change (304). Send both validators when present: some
      # CDN-backed CAs (e.g. DigiCert) serve per-node ETags they won't honor via
      # If-None-Match but will revalidate via If-Modified-Since, so sending only
      # the ETag defeats the 304 and re-downloads the whole list every time.
      req["If-None-Match"] = cache_entry[:etag] if cache_entry&.[](:etag)
      req["If-Modified-Since"] = cache_entry[:last_mod] if cache_entry&.[](:last_mod)
      http_response = http.request(req)
      case http_response
      when Net::HTTPNotModified
        # No changes, bump cache expiration time and return cached body
        @logger&.debug { "SSLTest   + CRL: 304 Not Modified" }
        cache.write(cache_key, cache_entry.merge(expires: Time.now + CRL_CACHE_DURATION), expires_in: CRL_CACHE_RETENTION)
        [cache_entry[:body], nil]
      when Net::HTTPSuccess
        # Success, update (or add to) cache and return frech body
        @logger&.debug { "SSLTest   + CRL: 200 OK (#{http_response.body.bytesize} bytes)" }
        @logger&.warn { "SSLTest   + CRL: Warning: massive file size (#{http_response.body.bytesize} bytes)" } if http_response.body.bytesize > 1024**2 # 1MB
        @logger&.warn { "SSLTest   + CRL: Warning: no caching headers on #{uri}" } unless http_response["Etag"] or http_response["Last-Modified"]
        cache.write(cache_key, {
          body: http_response.body,
          expires: Time.now + CRL_CACHE_DURATION,
          etag: http_response["Etag"],
          last_mod: http_response["Last-Modified"]
        }, expires_in: CRL_CACHE_RETENTION)
        [http_response.body, nil]
      when Net::HTTPRedirection
        follow_crl_redirects(URI(http_response["location"]), open_timeout: open_timeout, read_timeout: read_timeout, proxy_host: proxy_host, proxy_port: proxy_port, redirection_limit: redirection_limit - 1)
      else
        @logger&.debug { "SSLTest   + CRL: Error: #{http_response.class}" }
        [nil, "Wrong response type (#{http_response.class})"]
      end
    end
  end
end
