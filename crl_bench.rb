#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Benchmark: checking whether a single serial is revoked in a CRL.
#   A) OpenSSL::X509::CRL#revoked.find { ... }   (only API available today)
#   B) X509_CRL_get0_by_serial()                 (proposed, via Fiddle)
#
# Each approach runs in its own forked process so the reported peak RSS reflects
# only that approach. Requires MRI on Linux (uses fork + /proc; falls back to
# Process.getrusage on macOS/BSD).
#
#   ruby crl_bench.rb [CRL_URL]

require "openssl"
require "fiddle"
require "benchmark"
require "net/http"
require "uri"
require "tmpdir"

CRL_URL = ARGV[0] || "http://c.cf-i.ssl.com/ae801ed1c55bb579d79208b0d772acfb8cc3a208.crl"

# --- fetch the CRL (cached in /tmp so reruns are offline) ----------------------
cache = File.join(Dir.tmpdir, "crl_bench_#{File.basename(URI(CRL_URL).path)}")
body  = if File.exist?(cache)
          File.binread(cache)
        else
          warn "downloading #{CRL_URL} ..."
          data = Net::HTTP.get_response(URI(CRL_URL)).body
          File.binwrite(cache, data)
          data
        end

# --- libcrypto bindings (symbols are already in-process via require "openssl") -
def sym(name)
  Fiddle::Handle::DEFAULT[name]
rescue Fiddle::DLError
  @lib ||= %w[libcrypto.so libcrypto.so.3 libcrypto.dylib libcrypto.so.1.1]
           .lazy.map { |n| begin; Fiddle.dlopen(n); rescue Fiddle::DLError; nil; end }.find(&:itself)
  @lib[name]
end

P, L, I = Fiddle::TYPE_VOIDP, Fiddle::TYPE_LONG, Fiddle::TYPE_INT
D2I_CRL = Fiddle::Function.new(sym("d2i_X509_CRL"),           [P, P, L], P)
D2I_INT = Fiddle::Function.new(sym("d2i_ASN1_INTEGER"),       [P, P, L], P)
GET0    = Fiddle::Function.new(sym("X509_CRL_get0_by_serial"),[P, P, P], I)

# d2i_*(a, **pp, len) advances *pp; wrap a DER String into a C object pointer.
def d2i(fn, der)
  buf = Fiddle::Pointer[der]
  obj = fn.call(nil, Fiddle::Pointer[[buf.to_i].pack("q")], der.bytesize)
  raise "d2i failed" if obj.null?
  obj
end

# Peak resident set size in MB (high-water mark for this process).
def peak_mb
  if File.exist?("/proc/self/status") # Linux
    File.foreach("/proc/self/status") { |l| return l.split[1].to_f / 1024 if l.start_with?("VmHWM:") }
  end
  if Process.respond_to?(:getrusage) # macOS / BSD
    m = Process.getrusage(:SELF).maxrss
    return RUBY_PLATFORM.include?("darwin") ? m / 1024.0 / 1024 : m / 1024.0
  end
  0.0
end

# Run the block in a fresh process; peak RSS then reflects only that work.
def isolate
  rd, wr = IO.pipe
  pid = fork { rd.close; wr.write(Marshal.dump(yield)); wr.close; exit! }
  wr.close
  out = rd.read; rd.close; Process.wait(pid)
  Marshal.load(out)
end

# Approach A: the only thing the gem can do today.
def bench_revoked(body, serial)
  bn = OpenSSL::BN.new(serial)
  crl = nil; tp = Benchmark.realtime { crl = OpenSSL::X509::CRL.new(body) }
  hit = nil; entries = nil
  tl = Benchmark.realtime { list = crl.revoked; entries = list.size; hit = list.find { |r| r.serial == bn } }
  { entries: entries, parse_ms: tp * 1000, lookup_ms: tl * 1000, rss_mb: peak_mb, revoked: !hit.nil? }
end

# Approach B: X509_CRL_get0_by_serial (0 = not found, 1/2 = found).
def bench_get0(body, serial)
  crl = nil; tp = Benchmark.realtime { crl = d2i(D2I_CRL, body) }
  rc = nil
  tl = Benchmark.realtime do
    asn1 = d2i(D2I_INT, OpenSSL::ASN1::Integer.new(serial).to_der)
    rc = GET0.call(crl, Fiddle::NULL, asn1)
  end
  { parse_ms: tp * 1000, lookup_ms: tl * 1000, rss_mb: peak_mb, revoked: rc != 0 }
end

absent  = 0xDEAD_BEEF_CAFE_F00D                              # ~certainly not in the CRL
present = isolate { OpenSSL::X509::CRL.new(body).revoked.first&.serial&.to_i } # a real revoked serial

puts "CRL: #{CRL_URL}"
puts "DER: #{body.bytesize} bytes (#{(body.bytesize / 1e6).round(1)} MB)"
puts "Ruby #{RUBY_VERSION}, openssl gem #{OpenSSL::VERSION}, #{OpenSSL::OPENSSL_LIBRARY_VERSION}"
puts

a = isolate { bench_revoked(body, absent) }
b = isolate { bench_get0(body, absent) }

puts "Lookup of an absent serial (#{a[:entries]} entries in the CRL):"
printf "  %-26s parse %7.1f ms | lookup %8.1f ms | peak RSS %7.1f MB\n",
       "A #revoked.find", a[:parse_ms], a[:lookup_ms], a[:rss_mb]
printf "  %-26s parse %7.1f ms | lookup %8.1f ms | peak RSS %7.1f MB\n",
       "B get0_by_serial", b[:parse_ms], b[:lookup_ms], b[:rss_mb]
printf "  => %.1fx faster lookup, %.1fx less peak RSS\n",
       a[:lookup_ms] / b[:lookup_ms], a[:rss_mb] / b[:rss_mb]
puts

# correctness: both must agree on an absent and a present serial
ok_absent  = (a[:revoked] == false) && (b[:revoked] == false)
ok_present = present && isolate { bench_revoked(body, present)[:revoked] } &&
                        isolate { bench_get0(body, present)[:revoked] }
puts "correctness: absent serial -> both 'not revoked' (#{ok_absent ? 'PASS' : 'FAIL'}); " \
     "present serial -> both 'revoked' (#{ok_present ? 'PASS' : 'FAIL'})"
