# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name        = 'convenient_security'
  spec.version     = '0.0.1'
  spec.summary     = 'Heap-safe client for the convenient-security secrets agent'
  spec.description = 'Fetches secrets through the signed convenient-security bridge ' \
                     'into the process heap — never env or argv.'
  spec.authors     = ['Stateful Ltd']
  # RubyGems requires "Nonstandard" for licences outside its SPDX allow-list.
  # The exact FSL-1.1-ALv2 terms are shipped in LICENSE.md.
  spec.license     = 'Nonstandard'
  spec.files       = Dir['lib/**/*.rb'] + %w[LICENSE.md README.md]
  spec.require_paths = ['lib']
  spec.required_ruby_version = '>= 3.0'
  spec.metadata['rubygems_mfa_required'] = 'true'
end
