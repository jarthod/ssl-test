require "net/http"
require "net/https"
require "openssl"
require "uri"

module SSLTest
  VERSION = "1.3.0".freeze

  def self.test url, open_timeout: 5, read_timeout: 5, redirection_limit: 5
    uri = URI.parse(url)
    return if uri.scheme != 'https'
    cert = failed_cert_reason = chain = nil

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
      failed, revoked, message, revocation_date = test_ocsp_revocation(cert, chain, open_timeout: open_timeout, read_timeout: read_timeout, redirection_limit: redirection_limit)
      return [nil, "OCSP test failed: #{message}", cert] if failed
      return [false, "SSL certificate revoked: #{message} (revocation date: #{revocation_date})", cert] if revoked
      return [true, "OCSP test couldn't be performed: #{message}", cert] if message
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
      return [false, error, cert]
    rescue => e
      return [nil, "SSL certificate test failed: #{e.message}"]
    end
  end

  def self.cert_field_to_hash field
    field.to_a.each.with_object({}) do |v, h|
      v = v.to_a
      h[v[0]] = v[1].encode('UTF-8', undef: :replace, invalid: :replace)
    end
  end

  def self.cert_domains cert
    (Array(cert_field_to_hash(cert.subject)['CN']) +
      cert_field_to_hash(cert.extensions)['subjectAltName'].split(/\s*,\s*/))
      .compact
      .map {|s| s.gsub(/^DNS:/, '') }
      .uniq
  end

  def self.matching_domains domains, hostname
    domains.map {|s| Regexp.new("\A#{Regexp.escape(s).gsub('\*', '[^.]+')}\z") }
      .select {|domain| domain.match?(hostname) }
  end

  # https://docs.ruby-lang.org/en/2.2.0/OpenSSL/OCSP.html
  # https://stackoverflow.com/questions/16244084/how-to-programmatically-check-if-a-certificate-has-been-revoked#answer-16257470
  # Returns an array with [ocsp_check_failed, certificate_revoked, error_reason, revocation_date]
  def self.test_ocsp_revocation cert, chain, open_timeout: 5, read_timeout: 5, redirection_limit: 5
    chain[0..-2].each_with_index do |current_checked_cert, i|
      issuer = chain[i + 1]

      digest = OpenSSL::Digest::SHA1.new
      certificate_id = OpenSSL::OCSP::CertificateId.new(current_checked_cert, issuer, digest)

      request = OpenSSL::OCSP::Request.new
      request.add_certid certificate_id
      request.add_nonce

      authority_info_access = current_checked_cert.extensions.find do |extension|
        extension.oid == "authorityInfoAccess"
      end

      descriptions = authority_info_access.value.split("\n")
      ocsp = descriptions.find do |description|
        description.start_with?("OCSP")
      end

      ocsp_uri = URI(ocsp[/URI:(.*)/, 1])
      http_response = follow_ocsp_redirects(ocsp_uri, request.to_der, open_timeout: open_timeout, read_timeout: read_timeout, redirection_limit: redirection_limit)
      return ocsp_soft_fail_return("OCSP response request failed") unless http_response

      response = OpenSSL::OCSP::Response.new http_response.body
      # https://ruby-doc.org/stdlib-2.6.3/libdoc/openssl/rdoc/OpenSSL/OCSP.html#constants-list
      return ocsp_soft_fail_return("OCSP response failed: #{ocsp_response_status_to_string(response.status)}") unless response.status == OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL
      basic_response = response.basic

      # Check the response signature
      store = OpenSSL::X509::Store.new
      store.set_default_paths
      # https://ruby-doc.org/stdlib-2.4.0/libdoc/openssl/rdoc/OpenSSL/OCSP/BasicResponse.html#method-i-verify
      return ocsp_soft_fail_return("OCSP response signature verification failed") unless basic_response.verify(chain, store)

      # https://ruby-doc.org/stdlib-2.4.0/libdoc/openssl/rdoc/OpenSSL/OCSP/Request.html#method-i-check_nonce
      return ocsp_soft_fail_return("OCSP response nonce check failed") unless request.check_nonce(basic_response) != 0

      # https://ruby-doc.org/stdlib-2.4.0/libdoc/openssl/rdoc/OpenSSL/OCSP/BasicResponse.html#method-i-status
      response_certificate_id, status, reason, revocation_time, _this_update, _next_update, _extensions = basic_response.status.first

      return ocsp_soft_fail_return("OCSP response serial check failed") unless response_certificate_id.serial == certificate_id.serial
      return [false, true, revocation_reason_to_string(reason), revocation_time] if status == OpenSSL::OCSP::V_CERTSTATUS_REVOKED
    end
    [false, false, nil, nil]
  rescue => e
    return [true, nil, e.message, nil]
  end

  def self.follow_ocsp_redirects(uri, data, open_timeout: 5, read_timeout: 5, redirection_limit: 5)
    return nil if redirection_limit == 0

    path = uri.path == "" ? "/" : uri.path
    http = Net::HTTP.new(uri.hostname, uri.port)
    http.open_timeout = open_timeout
    http.read_timeout = read_timeout

    http_response = http.post(path, data, "content-type" => "application/ocsp-request")
    case http_response
    when Net::HTTPSuccess
      http_response
    when Net::HTTPRedirection
      follow_ocsp_redirects(URI(http_response["location"]), data, open_timeout: open_timeout, read_timeout: read_timeout, redirection_limit: redirection_limit -1)
    else
      nil
    end
  end

  # https://ruby-doc.org/stdlib-2.6.3/libdoc/openssl/rdoc/OpenSSL/OCSP.html#constants-list
  def self.ocsp_response_status_to_string(response_status)
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

  def self.ocsp_soft_fail_return(reason)
     [false, false, reason, nil].freeze
  end

  def self.revocation_reason_to_string(revocation_reason)
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
end
