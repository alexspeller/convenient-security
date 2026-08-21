# frozen_string_literal: true

require 'minitest/autorun'
require 'tmpdir'
require 'fileutils'
require 'convenient_security'

# Cross-language integration: Ruby -> real Swift csec bridge -> real Swift fake
# agent. This proves the private bridge framing, parent-root grant, and v2 agent
# protocol agree end-to-end without a vault.
class CrossStackTest < Minitest::Test
  AGENT_BINARY = File.expand_path('../../../agent/.build/debug/cs-fake-agent', __dir__)
  CSEC_BINARY = File.expand_path('../../../agent/.build/debug/csec', __dir__)

  def test_ruby_client_uses_the_signed_bridge_protocol_to_reach_the_agent
    unless File.executable?(AGENT_BINARY) && File.executable?(CSEC_BINARY)
      skip 'csec/cs-fake-agent not built (run `swift build` in agent/)'
    end

    dir = Dir.mktmpdir('cs-xstack')
    socket_path = File.join(dir, 'agent.sock')
    pid = spawn({ 'CSEC_SOCKET' => socket_path }, AGENT_BINARY, %i[out err] => File::NULL)

    begin
      wait_for_socket(socket_path)

      values = ConvenientSecurity.access(
        ['op://demo/db/url'],
        reason: 'cross-stack test',
        ttl: 60,
        bridge_path: CSEC_BINARY,
        test_socket_path: socket_path
      )
      assert_equal 'postgres://s3cr3t', values['op://demo/db/url']

      # A second fetch from the same process is covered by the subtree grant.
      again = ConvenientSecurity.access(
        ['op://demo/db/url'],
        reason: 'cross-stack test',
        ttl: 60,
        bridge_path: CSEC_BINARY,
        test_socket_path: socket_path
      )
      assert_equal 'postgres://s3cr3t', again['op://demo/db/url']

      # An unknown reference must surface as an error, not an empty result.
      assert_raises(ConvenientSecurity::Error) do
        ConvenientSecurity.access(
          ['op://demo/missing'],
          reason: 'cross-stack test',
          ttl: 60,
          bridge_path: CSEC_BINARY,
          test_socket_path: socket_path
        )
      end
    ensure
      Process.kill('TERM', pid)
      Process.wait(pid)
      FileUtils.remove_entry(dir)
    end
  end

  private

  def wait_for_socket(path, timeout: 5)
    deadline = Time.now + timeout
    sleep 0.02 until File.socket?(path) || Time.now > deadline
    raise "agent socket never appeared at #{path}" unless File.socket?(path)
  end
end
