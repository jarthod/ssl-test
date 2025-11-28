module SSLTest
  module CRL
    CRL_CACHE_DURATION = 3600 # 1 hour

    # A note about caching:
    # I choose to only cache the raw HTTP body here (and not the parsed list or better a hash
    # indexed by certificat serial). This is not CPU efficient because it means every time we
    # need to check a cert from a cached CRL we need to parse it again, instantiate the list
    # of Revoked certs and then iterate to find it (there's no API to find one cert without
    # generting the list unfortuantely).
    # I did this because of memory efficiency, because for big 20MB CRL list (so taking 20MB
    # in memory cache), the parsed version takes more than 100M, the list of Revoked certs 120MB,
    # and building a hash with serial, time and reason takes even more.
    # So doing this would be MUCH faster in terms of CPU for subsequent tests on the same CRL
    # but would take a LOT of memory.
    # Also I expect most providers to support OCSP for first level cert (a lot of revokation),
    # which means we should have to use CRL mostly for intermediaries with much smaller CRL.
    # That's what Let's Encrypt is doing with their R3 intermediate for example.

    private

    def test_crl_revocation cert, issuer:, chain:, **options
      crl_distribution_points = cert.extensions.find do |extension|
        extension.oid == "crlDistributionPoints"
      end

      return [false, "Missing crlDistributionPoints extension", nil] unless crl_distribution_points

      # OpenSSL 2.2+ may simplify this: https://github.com/ruby/openssl/commit/ea702a106d3d8136c48f244593de95666be0edf9
      crl = crl_distribution_points.value.split("\n").find do |description|
        description.match?(/URI:/)
      end

      return [false, "Missing CRL URI in crlDistributionPoints extension", nil] unless crl

      crl_uri = URI(crl[/URI:(.*)/, 1])
      http_response, crl_request_error = follow_crl_redirects(crl_uri, **options)
      return [false, "Request failed (URI: #{crl_uri}): #{crl_request_error}", nil] unless http_response

      response = OpenSSL::X509::CRL.new http_response
      return [false, "Signature verification failed (URI: #{crl_uri})", nil] unless response.verify(issuer.public_key)

      revoked = response.revoked.find { |r| r.serial == cert.serial }
      if revoked
        reason = revoked.extensions.find {|e| e.oid == "CRLReason"}&.value
        return [true, reason || "Unknown reason", revoked.time]
      else
      end

      :crl_ok
    end

    # Returns an array with [response, error_message]
    def follow_crl_redirects(uri, open_timeout: 5, read_timeout: 5, redirection_limit: 5, proxy_host: nil, proxy_port: nil)
      return [nil, "Too many redirections (> #{redirection_limit})"] if redirection_limit == 0

      # Return file from cache if not expired
      @crl_response_cache ||= {}
      cache_entry = @crl_response_cache[uri]
      return [cache_entry[:body], nil] if cache_entry && cache_entry.fetch(:expires) > Time.now

      @logger&.debug { "SSLTest   + CRL: fetch URI #{uri}" }
      path = uri.path == "" ? "/" : uri.path
      http = Net::HTTP.new(uri.hostname, uri.port, proxy_host, proxy_port)
      http.open_timeout = open_timeout
      http.read_timeout = read_timeout

      req = Net::HTTP::Get.new(path)
      # Include conditional caching headers from cache to save bandwidth if list didn't change (304)
      if etag = cache_entry&.fetch(:etag)
        req["If-None-Match"] = etag
      elsif last_mod = cache_entry&.fetch(:last_mod)
        req["If-Modified-Since"] = last_mod
      end
      http_response = http.request(req)
      case http_response
      when Net::HTTPNotModified
        # No changes, bump cache expiration time and return cached body
        @logger&.debug { "SSLTest   + CRL: 304 Not Modified" }
        @crl_response_cache[uri][:expires] = Time.now + CRL_CACHE_DURATION
        [cache_entry[:body], nil]
      when Net::HTTPSuccess
        # Success, update (or add to) cache and return frech body
        @logger&.debug { "SSLTest   + CRL: 200 OK (#{http_response.body.bytesize} bytes)" }
        @logger&.warn { "SSLTest   + CRL: Warning: massive file size" } if http_response.body.bytesize > 1024**2 # 1MB
        @logger&.warn { "SSLTest   + CRL: Warning: no caching headers on #{uri}" } unless http_response["Etag"] or http_response["Last-Modified"]
        @crl_response_cache[uri] = {
          body: http_response.body,
          expires: Time.now + CRL_CACHE_DURATION,
          etag: http_response["Etag"],
          last_mod: http_response["Last-Modified"]
        }
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
