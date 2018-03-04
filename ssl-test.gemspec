# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'ssl-test'

Gem::Specification.new do |spec|
  spec.name          = "ssl-test"
  spec.version       = SSLTest::VERSION
  spec.authors       = ["Adrien Jarthon"]
  spec.email         = ["jobs@adrienjarthon.com"]
  spec.summary       = %q{Test website SSL certificate validity}
  spec.homepage      = "https://github.com/jarthod/ssl-test"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.7"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "minitest"
end
