# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'rc6/version'

Gem::Specification.new do |spec|
  spec.name          = "rc6"
  spec.version       = RC6::VERSION
  spec.authors       = ["Daniel Otte, Bartosz J"]
  spec.email         = ["daniel.otte@rub.de, thug1337@gmail.com"]
  spec.summary       = %q{RC6 algorithm implementation}
  spec.description   = %q{Fast RC6 decrypt/encrypt using C extension}
  spec.homepage      = "https://github.com/lolet/rc6"
  spec.license       = "GPL"

  spec.files         = `git ls-files -z`.split("\x0")

  spec.extensions    << "ext/rc6/extconf.rb"

  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.7"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rake-compiler", "~> 0.9"
  spec.add_development_dependency "rspec", ">= 2.0.0"
end
