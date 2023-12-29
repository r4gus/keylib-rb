Gem::Specification.new do |s|
  s.name        = "keylib"
  s.version     = "0.1.0"
  s.summary     = "Library for creating FIDO2/Passkey authenticators"
  s.description = "FIDO2 authenticators can be used for single- and multi-factor authentication. This library allows the development of FIDO2 authenticators in Ruby. We provide the building blocks, you bring the glue."
  s.authors     = ["David Pierre Sugar"]
  s.email       = "david@thesugar.de"
  s.files       = ["lib/c2cc.rb", "lib/c2cc/cbor.rb"]
  s.homepage    = ""
  s.license     = "MIT"
end
