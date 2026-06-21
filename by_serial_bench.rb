#!/usr/bin/env ruby
#
# Needs the patched openssl that defines #by_serial; point OPENSSL_LIB at the dev
# build (defaults to ../openssl/lib). gem install benchmark-ips benchmark-memory
#
#   ruby by_serial_bench.rb [CRL_URL]

dev = ENV["OPENSSL_LIB"] || File.expand_path("../openssl/lib", __dir__)
$LOAD_PATH.unshift(dev) if File.exist?(File.join(dev, "openssl.so"))

require "openssl"
require "net/http"
require "uri"
require "tmpdir"
require "benchmark/ips"
require "benchmark/memory"

abort "loaded openssl has no #by_serial (set OPENSSL_LIB to the patched build)" unless
  OpenSSL::X509::CRL.method_defined?(:by_serial)

url   = ARGV[0] || "http://c.cf-i.ssl.com/ae801ed1c55bb579d79208b0d772acfb8cc3a208.crl" # big CRL example
cache = File.join(Dir.tmpdir, "by_serial_bench_#{File.basename(URI(url).path)}")
body  = File.exist?(cache) ? File.binread(cache) :
        (warn("downloading #{url} ..."); d = Net::HTTP.get(URI(url)); File.binwrite(cache, d); d)

crl     = OpenSSL::X509::CRL.new(body)
entries = crl.revoked.size
absent  = 0xDEAD_BEEF_CAFE_F00D
present = crl.revoked[entries / 2].serial # middle of the list for median performance

puts "#{OpenSSL::OPENSSL_LIBRARY_VERSION} — #{url}"
puts "#{(body.bytesize / 1e6).round(1)} MB DER, #{entries} revoked entries"

[["not revoked", absent], ["revoked", present]].each do |label, serial|
  abort "mismatch for #{label}" unless
    crl.by_serial(serial) == crl.revoked.find { |r| r.serial == serial }
  puts "\n=== #{label} serial ==="

  puts "\n-- warm: lookup on a parsed CRL --"
  @list = nil
  Benchmark.ips do |x|
    x.config(warmup: 1, time: 3)
    x.report("revoked.find") { (@list ||= crl.revoked).find { |r| r.serial == serial } }
    x.report("by_serial")    { crl.by_serial(serial) }
    x.compare!
  end
  Benchmark.memory do |x|
    x.report("revoked.find") { crl.revoked.find { |r| r.serial == serial } }
    x.report("by_serial")    { crl.by_serial(serial) }
    x.compare!
  end

  puts "\n-- cold: parse a fresh CRL + one lookup --"
  Benchmark.ips do |x|
    x.config(warmup: 0, time: 3)
    x.report("revoked.find") { OpenSSL::X509::CRL.new(body).revoked.find { |r| r.serial == serial } }
    x.report("by_serial")    { OpenSSL::X509::CRL.new(body).by_serial(serial) }
    x.compare!
  end
  Benchmark.memory do |x|
    x.report("revoked.find") { OpenSSL::X509::CRL.new(body).revoked.find { |r| r.serial == serial } }
    x.report("by_serial")    { OpenSSL::X509::CRL.new(body).by_serial(serial) }
    x.compare!
  end
end
