require "net/https"

module SSLTest
  VERSION = "0.0.2"

  def self.test url
    uri = URI.parse(url)
    return if uri.scheme != 'https'
    cert = failed_cert_reason = nil

    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_PEER
    http.verify_callback = -> (verify_ok, store_context) {
      cert = store_context.current_cert
      failed_cert_reason =  [store_context.error, store_context.error_string] if !verify_ok
      verify_ok
    }

    req = Net::HTTP::Head.new('/')
    begin
      res = http.start { http.request(req) }
      return [true, nil, cert]
    rescue OpenSSL::SSL::SSLError => e
      error = e.message
      error = "error code %d: %s" % failed_cert_reason if failed_cert_reason
      return [false, error, cert]
    rescue => e
      return [nil, "SSL certificate test failed: #{e.message}"]
    end
  end
end
