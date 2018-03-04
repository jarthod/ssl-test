require "net/https"

module SSLTest
  VERSION = "1.2.0"

  def self.test url, open_timeout: 5, read_timeout: 5
    uri = URI.parse(url)
    return if uri.scheme != 'https'
    cert = failed_cert_reason = nil

    http = Net::HTTP.new(uri.host, uri.port)
    http.open_timeout = open_timeout
    http.read_timeout = read_timeout
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_PEER
    http.verify_callback = -> (verify_ok, store_context) {
      cert = store_context.current_cert
      failed_cert_reason = [store_context.error, store_context.error_string] if store_context.error != 0
      verify_ok
    }

    begin
      http.start { }
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
end
