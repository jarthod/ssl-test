require "ssl-test"
require "active_support"
require "active_support/cache"
require "tmpdir"

# Verifies the cache backends people are likely to plug into SSLTest.cache (the
# classic Rails/ActiveSupport stores) satisfy the read / write / expiration
# contract SSLTest relies on, including (de)serialization of the value shapes it
# stores: Hashes containing Strings (incl. binary CRL bodies), Times, Integers
# and nils, plus Arrays (OCSP errors).
#
# Stores backed by an external server (MemCacheStore, RedisCacheStore) or an
# extra gem are skipped when unavailable, so the suite stays green locally; CI
# provides the servers (see .github/workflows/ruby.yml) so they actually run.
describe "ActiveSupport cache backend compatibility" do
  # Representative of what SSLTest caches: a CRL entry (binary body + Time) and
  # an OCSP error entry (an Array). Fixed Time so serialization round-trips are
  # deterministic.
  let(:crl_entry) do
    { body: ("\x30\x82\x01\x02".b * 50), expires: Time.utc(2030, 1, 1, 12), etag: 'W/"abc123"', last_mod: nil }
  end
  let(:ocsp_error) { [false, "Request failed (URI: http://ocsp.example.com)", nil] }

  # Stores that actually persist values (NullStore intentionally doesn't).
  CACHING_STORES = %w[MemoryStore FileStore MemCacheStore RedisCacheStore]

  def build_store(name)
    case name
    when "MemoryStore"
      ActiveSupport::Cache::MemoryStore.new
    when "FileStore"
      ActiveSupport::Cache::FileStore.new(Dir.mktmpdir("ssl-test-cache"))
    when "NullStore"
      ActiveSupport::Cache::NullStore.new
    when "MemCacheStore"
      require "dalli"
      ActiveSupport::Cache::MemCacheStore.new(ENV.fetch("MEMCACHE_SERVERS", "127.0.0.1:11211"))
    when "RedisCacheStore"
      require "redis"
      ActiveSupport::Cache::RedisCacheStore.new(url: ENV.fetch("REDIS_URL", "redis://127.0.0.1:6379/15"))
    end
  end

  around do |example|
    previous = SSLTest.cache
    example.run
  ensure
    SSLTest.cache = previous
  end

  (CACHING_STORES + %w[NullStore]).each do |name|
    context name do
      before do
        begin
          SSLTest.cache = build_store(name)
        rescue LoadError => e
          skip "#{name} unavailable: #{e.message}"
        end

        # For server-backed stores, ActiveSupport silently treats a missing
        # server as a cache miss; probe so we skip (rather than fail) when the
        # server isn't running.
        if CACHING_STORES.include?(name)
          SSLTest.cache.write("ssl-test/probe", "ok", expires_in: 60)
          skip "#{name} server not reachable" unless SSLTest.cache.read("ssl-test/probe") == "ok"
        end
      end

      if name == "NullStore"
        it "acts as a no-op (the gem still works, just without caching)" do
          SSLTest.cache.write("ssl-test/crl/x", crl_entry, expires_in: nil)
          expect(SSLTest.cache.read("ssl-test/crl/x")).to be_nil
        end
      else
        it "round-trips a CRL entry (binary body + Time serialization)" do
          SSLTest.cache.write("ssl-test/crl/x", crl_entry, expires_in: 100 * 3600)
          expect(SSLTest.cache.read("ssl-test/crl/x")).to eq(crl_entry)
        end

        it "round-trips an OCSP error entry (Array serialization)" do
          SSLTest.cache.write("ssl-test/ocsp-error/y", ocsp_error, expires_in: 300)
          expect(SSLTest.cache.read("ssl-test/ocsp-error/y")).to eq(ocsp_error)
        end

        it "returns nil for a missing key" do
          expect(SSLTest.cache.read("ssl-test/ocsp/missing")).to be_nil
        end

        it "persists entries written with no expiry (expires_in: nil)" do
          SSLTest.cache.write("ssl-test/crl/persist", crl_entry, expires_in: nil)
          expect(SSLTest.cache.read("ssl-test/crl/persist")).to eq(crl_entry)
        end

        it "honors expires_in" do
          SSLTest.cache.write("ssl-test/ocsp/z", { status: 0 }, expires_in: 0.1)
          expect(SSLTest.cache.read("ssl-test/ocsp/z")).to eq({ status: 0 })
          sleep 0.2
          expect(SSLTest.cache.read("ssl-test/ocsp/z")).to be_nil
        end
      end
    end
  end
end
