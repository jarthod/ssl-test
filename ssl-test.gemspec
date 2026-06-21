# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'ssl-test'

Gem::Specification.new do |spec|
  spec.name          = "ssl-test"
  spec.version       = SSLTest::VERSION
  spec.authors       = ["Adrien Rey-Jarthon"]
  spec.email         = ["jobs@adrienjarthon.com"]
  spec.summary       = %q{Test website SSL certificate validity}
  spec.homepage      = "https://github.com/jarthod/ssl-test"
  spec.license       = "MIT"

  spec.required_ruby_version = ">= 3.1"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", ">= 1.7"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "rspec"
  spec.add_development_dependency "rspec-retry"
  spec.add_development_dependency "webrick"
  # Used to verify SSLTest.cache works with the classic Rails/ActiveSupport
  # cache stores (MemoryStore, FileStore, NullStore, MemCacheStore via dalli,
  # RedisCacheStore via redis).
  spec.add_development_dependency "activesupport"
  spec.add_development_dependency "dalli"
  spec.add_development_dependency "redis"
end
