require "ssl-test"

describe SSLTest::MemoryStore do
  subject(:store) { described_class.new }

  it "round-trips written values" do
    store.write("k", "v")
    expect(store.read("k")).to eq("v")
  end

  it "returns nil for missing keys" do
    expect(store.read("missing")).to be_nil
  end

  it "expires entries after expires_in" do
    store.write("k", "v", expires_in: -1) # already expired
    expect(store.read("k")).to be_nil
  end

  it "keeps entries with no expiry" do
    store.write("k", "v", expires_in: nil)
    expect(store.read("k")).to eq("v")
  end

  it "deletes and clears entries" do
    store.write("a", 1)
    store.write("b", 2)
    store.delete("a")
    expect(store.read("a")).to be_nil
    expect(store.read("b")).to eq(2)
    store.clear
    expect(store.read("b")).to be_nil
  end

  it "iterates non-expired entries with #each" do
    store.write("live", 1)
    store.write("dead", 2, expires_in: -1)
    expect(store.each.to_a).to eq([["live", 1]])
  end

  it "#size reports a CRL/OCSP breakdown" do
    store.write("ssl-test/crl/http://example.com/x.crl", "body")
    store.write("ssl-test/ocsp/issuer/1", { status: 0 })
    store.write("ssl-test/ocsp-error/issuer/2", [false, "err", nil])
    store.write("unrelated/key", "ignored")
    expect(store.size).to match({
      crl:  { lists: 1, bytes: be > 0 },
      ocsp: { responses: 1, errors: 1, bytes: be > 0 }
    })
  end
end

# #size as reported through the default store after real CRL/OCSP fetches.
describe "SSLTest.cache.size" do
  before { SSLTest.cache.clear }

  it "returns 0 by default" do
    expect(SSLTest.cache.size).to eq({
      crl:  { bytes: 0,  lists: 0 },
      ocsp: { bytes: 0, errors: 0, responses: 0 }
    })
  end

  it "returns CRL cache size properly" do
    SSLTest.send(:follow_crl_redirects, URI("http://crl.certigna.fr/certigna.crl")) # 1.1k
    SSLTest.send(:follow_crl_redirects, URI("http://crl3.digicert.com/DigiCertTLSHybridECCSHA3842020CA1-1.crl")) # 26k
    expect(SSLTest.cache.size[:crl][:lists]).to eq(2)
    expect(SSLTest.cache.size[:crl][:bytes]).to be > 2000
  end

  it "returns OCSP cache size properly" do
    SSLTest.test("https://github.com")
    expect(SSLTest.cache.size[:ocsp][:responses]).to eq(1)
    expect(SSLTest.cache.size[:ocsp][:errors]).to eq(0)
    expect(SSLTest.cache.size[:ocsp][:bytes]).to be > 0
    expect(SSLTest.cache.size[:crl][:lists]).to eq(1)
    expect(SSLTest.cache.size[:crl][:bytes]).to be > 100
  end
end
