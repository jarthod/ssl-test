module SSLTest
  module OCSP
    ERROR_CACHE_DURATION = 5 * 60 # 5 minutes

    private

    def test_ocsp_revocation cert, issuer:, chain:, **options
      @ocsp_response_cache ||= {}
      @ocsp_request_error_cache ||= {}

      unicity_key = "#{cert.issuer}/#{cert.serial}"

      current_request_error_cache = @ocsp_request_error_cache[unicity_key]
      return current_request_error_cache[:error] if current_request_error_cache && Time.now <= current_request_error_cache[:expires]

      if @ocsp_response_cache[unicity_key].nil? || @ocsp_response_cache[unicity_key][:next_update] <= Time.now
        authority_info_access = cert.extensions.find do |extension|
          extension.oid == "authorityInfoAccess"
        end

        return ocsp_soft_fail_return("Missing authorityInfoAccess extension") unless authority_info_access

        # OpenSSL 2.2+ may simplify this: https://github.com/ruby/openssl/commit/ea702a106d3d8136c48f244593de95666be0edf9
        ocsp = authority_info_access.value.split("\n").find do |description|
          description.start_with?("OCSP")
        end

        return ocsp_soft_fail_return("Missing OCSP URI in authorityInfoAccess extension") unless ocsp

        digest = OpenSSL::Digest::SHA1.new
        certificate_id = OpenSSL::OCSP::CertificateId.new(cert, issuer, digest)

        request = OpenSSL::OCSP::Request.new
        request.add_certid certificate_id
        request.add_nonce

        ocsp_uri = URI(ocsp[/URI:(.*)/, 1])
        http_response, ocsp_request_error = follow_ocsp_redirects(ocsp_uri, request.to_der, **options)
        return ocsp_soft_fail_return("Request failed (URI: #{ocsp_uri}): #{ocsp_request_error}", unicity_key) unless http_response

        response = OpenSSL::OCSP::Response.new http_response
        # https://ruby-doc.org/stdlib-2.6.3/libdoc/openssl/rdoc/OpenSSL/OCSP.html#constants-list
        return ocsp_soft_fail_return("Unsuccessful response (URI: #{ocsp_uri}): #{ocsp_response_status_to_string(response.status)}", unicity_key) unless response.status == OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL
        basic_response = response.basic

        # Check the response signature
        store = OpenSSL::X509::Store.new
        store.set_default_paths
        # https://ruby-doc.org/stdlib-2.4.0/libdoc/openssl/rdoc/OpenSSL/OCSP/BasicResponse.html#method-i-verify
        return ocsp_soft_fail_return("Signature verification failed (URI: #{ocsp_uri})", unicity_key) unless basic_response.verify(chain, store)

        # https://ruby-doc.org/stdlib-2.4.0/libdoc/openssl/rdoc/OpenSSL/OCSP/Request.html#method-i-check_nonce
        return ocsp_soft_fail_return("Nonce check failed (URI: #{ocsp_uri})", unicity_key) unless request.check_nonce(basic_response) != 0

        # https://ruby-doc.org/stdlib-2.3.0/libdoc/openssl/rdoc/OpenSSL/OCSP/BasicResponse.html#method-i-status
        response_certificate_id, status, reason, revocation_time, _this_update, next_update, _extensions = basic_response.status.first

        return ocsp_soft_fail_return("Serial check failed (URI: #{ocsp_uri})", unicity_key) unless response_certificate_id.serial == certificate_id.serial

        @ocsp_response_cache[unicity_key] = { status: status, reason: reason, revocation_time: revocation_time, next_update: next_update }
      end

      ocsp_response = @ocsp_response_cache[unicity_key]

      return [true, revocation_reason_to_string(ocsp_response[:reason]), ocsp_response[:revocation_time]] if ocsp_response[:status] == OpenSSL::OCSP::V_CERTSTATUS_REVOKED
      :ocsp_ok
    end

    # Returns an array with [response, error_message]
    def follow_ocsp_redirects(uri, data, open_timeout: 5, read_timeout: 5, redirection_limit: 5, proxy_host: nil, proxy_port: nil)
      return [nil, "Too many redirections (> #{redirection_limit})"] if redirection_limit == 0

      @logger&.debug { "SSLTest   + OCSP: fetch URI #{uri}" }
      path = uri.path == "" ? "/" : uri.path
      http = Net::HTTP.new(uri.hostname, uri.port, proxy_host, proxy_port)
      http.open_timeout = open_timeout
      http.read_timeout = read_timeout

      http_response = http.post(path, data, "content-type" => "application/ocsp-request")
      case http_response
      when Net::HTTPSuccess
        @logger&.debug { "SSLTest   + OCSP: 200 OK (#{http_response.body.bytesize} bytes)" }
        [http_response.body, nil]
      when Net::HTTPRedirection
        follow_ocsp_redirects(URI(http_response["location"]), data, open_timeout: open_timeout, read_timeout: read_timeout, rproxy_host: proxy_host, proxy_port: proxy_port, edirection_limit: redirection_limit - 1)
      else
        @logger&.debug { "SSLTest   + OCSP: Error: #{http_response.class}" }
        [nil, "Wrong response type (#{http_response.class})"]
      end
    end

    # https://ruby-doc.org/stdlib-2.6.3/libdoc/openssl/rdoc/OpenSSL/OCSP.html#constants-list
    def ocsp_response_status_to_string(response_status)
      case response_status
      when OpenSSL::OCSP::RESPONSE_STATUS_INTERNALERROR
        "Internal error in issuer"
      when OpenSSL::OCSP::RESPONSE_STATUS_MALFORMEDREQUEST
        "Illegal confirmation request"
      when OpenSSL::OCSP::RESPONSE_STATUS_SIGREQUIRED
        "You must sign the request and resubmit"
      when OpenSSL::OCSP::RESPONSE_STATUS_TRYLATER
        "Try again later"
      when OpenSSL::OCSP::RESPONSE_STATUS_UNAUTHORIZED
        "Your request is unauthorized"
      else
        "Unknown reason"
      end
    end

    def revocation_reason_to_string(revocation_reason)
      # https://ruby-doc.org/stdlib-2.4.0/libdoc/openssl/rdoc/OpenSSL/OCSP.html#constants-list
      case revocation_reason
      when OpenSSL::OCSP::REVOKED_STATUS_AFFILIATIONCHANGED
        "The certificate subject's name or other information changed"
      when OpenSSL::OCSP::REVOKED_STATUS_CACOMPROMISE
        "This CA certificate was revoked due to a key compromise"
      when OpenSSL::OCSP::REVOKED_STATUS_CERTIFICATEHOLD
        "The certificate is on hold"
      when OpenSSL::OCSP::REVOKED_STATUS_CESSATIONOFOPERATION
        "The certificate is no longer needed"
      when OpenSSL::OCSP::REVOKED_STATUS_KEYCOMPROMISE
        "The certificate was revoked due to a key compromise"
      when OpenSSL::OCSP::REVOKED_STATUS_NOSTATUS
        "The certificate was revoked for an unknown reason"
      when OpenSSL::OCSP::REVOKED_STATUS_REMOVEFROMCRL
        "The certificate was previously on hold and should now be removed from the CRL"
      when OpenSSL::OCSP::REVOKED_STATUS_SUPERSEDED
        "The certificate was superseded by a new certificate"
      when OpenSSL::OCSP::REVOKED_STATUS_UNSPECIFIED
        "The certificate was revoked for an unspecified reason"
      else
        "Unknown reason"
      end
    end

    def ocsp_soft_fail_return(reason, unicity_key = nil)
       error = [false, reason, nil]
       @ocsp_request_error_cache[unicity_key] = { error: error, expires: Time.now + ERROR_CACHE_DURATION } if unicity_key
       error
    end
  end
end