# frozen_string_literal: true

require 'minitest/autorun'
require 'json'
require 'tmpdir'
require 'fileutils'
require 'rbconfig'
require 'convenient_security'

# Hermetic bridge tests. The helper executable speaks the private framed
# stdin/stdout protocol, so Ruby framing, environment scrubbing, and typed error
# handling are covered without a Swift build or a live vault.
class ConvenientSecurityTest < Minitest::Test
  def with_fake_bridge(response:)
    dir = Dir.mktmpdir('cs-ruby-bridge-test')
    path = File.join(dir, 'fake-bridge')
    capture_path = File.join(dir, 'capture.json')
    response_json = JSON.generate({ version: 1 }.merge(response))
    script = <<~RUBY
      #!#{RbConfig.ruby}
      require 'json'
      STDIN.binmode
      STDOUT.binmode
      length = STDIN.read(4).unpack1('N')
      request = JSON.parse(STDIN.read(length))
      File.binwrite(
        #{capture_path.dump},
        JSON.generate(
          request: request,
          ambientPresent: ENV.key?('CSEC_TEST_AMBIENT_SECRET')
        )
      )
      payload = #{response_json.dump}
      STDOUT.write([payload.bytesize].pack('N'))
      STDOUT.write(payload)
    RUBY
    File.write(path, script)
    File.chmod(0o700, path)

    result = yield path
    captured = JSON.parse(File.binread(capture_path)) if File.exist?(capture_path)
    [result, captured]
  ensure
    FileUtils.remove_entry(dir) if dir && Dir.exist?(dir)
  end

  def test_access_returns_values_and_sends_a_well_formed_bridge_request
    result, captured = with_fake_bridge(
      response: { values: { 'op://demo/db/url' => 'postgres://synthetic' } }
    ) do |path|
      ConvenientSecurity.access(
        ['op://demo/db/url'], reason: 'boot rails', ttl: 3600, bridge_path: path
      )
    end

    assert_equal({ 'op://demo/db/url' => 'postgres://synthetic' }, result)
    assert_equal 1, captured['request']['version']
    assert_equal ['op://demo/db/url'], captured['request']['references']
    assert_equal 'boot rails', captured['request']['reason']
    assert_equal 3600, captured['request']['ttlSeconds']
  end

  def test_bridge_child_does_not_inherit_the_ruby_environment
    original = ENV['CSEC_TEST_AMBIENT_SECRET']
    ENV['CSEC_TEST_AMBIENT_SECRET'] = 'synthetic-marker-not-a-real-secret'
    _, captured = with_fake_bridge(response: { values: { 'op://demo/key' => 'synthetic' } }) do |path|
      ConvenientSecurity.access(['op://demo/key'], reason: 'env scrub test', ttl: 60, bridge_path: path)
    end
    assert_equal false, captured['ambientPresent']
  ensure
    ENV['CSEC_TEST_AMBIENT_SECRET'] = original
  end

  def test_denied_raises_denied
    assert_raises(ConvenientSecurity::Denied) do
      with_fake_bridge(
        response: { failure: { code: 'consent_denied', message: 'consent denied' } }
      ) do |path|
        ConvenientSecurity.access(['op://demo/key'], reason: 'x', ttl: 60, bridge_path: path)
      end
    end
  end

  def test_typed_failure_raises_generic_error_not_denied
    error = assert_raises(ConvenientSecurity::Error) do
      with_fake_bridge(
        response: { failure: { code: 'policy_denied', message: 'delivery is not allowed' } }
      ) do |path|
        ConvenientSecurity.access(['op://demo/key'], reason: 'x', ttl: 60, bridge_path: path)
      end
    end
    refute_instance_of ConvenientSecurity::Denied, error
    assert_match(/policy_denied/, error.message)
  end

  def test_missing_bridge_raises_actionable_error
    error = assert_raises(ConvenientSecurity::Error) do
      ConvenientSecurity.access(
        ['op://demo/key'],
        reason: 'x',
        ttl: 60,
        bridge_path: '/tmp/csec-test-bridge-does-not-exist'
      )
    end
    assert_match(/not executable/, error.message)
  end

  def test_relative_bridge_path_is_rejected
    error = assert_raises(ConvenientSecurity::Error) do
      ConvenientSecurity.access(
        ['op://demo/key'], reason: 'x', ttl: 60, bridge_path: 'relative/csec'
      )
    end
    assert_match(/must be absolute/, error.message)
  end

  def test_request_bounds_are_checked_before_launch
    assert_raises(ConvenientSecurity::Error) do
      ConvenientSecurity.access(['op://demo/key'], reason: 'x', ttl: 0, bridge_path: '/missing')
    end
    assert_raises(ConvenientSecurity::Error) do
      ConvenientSecurity.access([], reason: 'x', ttl: 60, bridge_path: '/missing')
    end
  end

  def test_default_bridge_path_is_fixed_not_environment_selected
    original = ENV['CSEC_BIN']
    ENV['CSEC_BIN'] = '/tmp/attacker-csec'
    assert_equal(
      '/Library/Application Support/ConvenientSecurity/bin/csec',
      ConvenientSecurity::DEFAULT_BRIDGE_PATH
    )
  ensure
    ENV['CSEC_BIN'] = original
  end
end
