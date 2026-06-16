module SSLTest
  # A tiny in-process cache store used as the default backend when Rails.cache
  # isn't available. It mirrors the small subset of the ActiveSupport::Cache /
  # Rails.cache API that SSLTest relies on (read/write/delete) so the two are
  # interchangeable. Access is guarded by a Mutex because SSLTest is typically
  # used from threaded servers (e.g. Puma).
  #
  # Unlike a shared/compressed backend (memcache via Dalli), this store is
  # per-process, uncompressed and unbounded, so be careful about memory usage if
  # you validate millions of certificates in a row (the OCSP cache is keyed by
  # certificate serial). For those workloads, configure SSLTest.cache to a shared
  # store instead.
  class MemoryStore
    def initialize
      @data = {}
      @mutex = Mutex.new
    end

    def read(key)
      @mutex.synchronize do
        entry = @data[key]
        next nil unless entry
        if entry[:expires_at] && entry[:expires_at] <= Time.now
          @data.delete(key)
          next nil
        end
        entry[:value]
      end
    end

    def write(key, value, expires_in: nil)
      @mutex.synchronize do
        @data[key] = { value: value, expires_at: expires_in && Time.now + expires_in }
      end
      value
    end

    def delete(key)
      @mutex.synchronize { @data.delete(key) }
    end

    def clear
      @mutex.synchronize { @data.clear }
    end

    # Yields [key, value] for every entry that hasn't expired.
    def each
      return enum_for(:each) unless block_given?
      now = Time.now
      @mutex.synchronize { @data.dup }.each do |key, entry|
        next if entry[:expires_at] && entry[:expires_at] <= now
        yield key, entry[:value]
      end
    end

    # Returns a breakdown of the cached SSLTest entries (CRL lists and OCSP
    # responses/errors) with approximate byte sizes, mainly useful for monitoring
    # memory usage. Specific to ssl-test's key namespace.
    def size
      crl_lists = ocsp_responses = ocsp_errors = 0
      crl_bytes = ocsp_bytes = 0
      each do |key, value|
        case key
        when %r{\A#{CACHE_NAMESPACE}/crl/}
          crl_lists += 1
          crl_bytes += ObjectSize.size(value)
        when %r{\A#{CACHE_NAMESPACE}/ocsp-error/}
          ocsp_errors += 1
          ocsp_bytes += ObjectSize.size(value)
        when %r{\A#{CACHE_NAMESPACE}/ocsp/}
          ocsp_responses += 1
          ocsp_bytes += ObjectSize.size(value)
        end
      end
      {
        crl: { lists: crl_lists, bytes: crl_bytes },
        ocsp: { responses: ocsp_responses, errors: ocsp_errors, bytes: ocsp_bytes }
      }
    end
  end
end
