# frozen_string_literal: true

require 'json'
require 'open3'

# Heap-delivery client for the Convenient Security agent.
#
# Ruby cannot authenticate a Unix-socket peer with Security.framework by itself,
# so it never connects to agent.sock. It spawns the installed, signed `csec
# bridge` by absolute path, gives it a plaintext-free request over stdin, and
# receives values over a private stdout pipe. The bridge and daemon authenticate
# each other with kernel audit tokens and code-signing requirements.
module ConvenientSecurity
  class Error < StandardError; end
  class Denied < Error; end

  DEFAULT_BRIDGE_PATH = '/Library/Application Support/ConvenientSecurity/bin/csec'
  MAX_FRAME_BYTES = 8 * 1024 * 1024
  MINIMAL_PATH = '/usr/bin:/bin:/usr/sbin:/sbin'

  # Request one or more references. Values arrive only in this Ruby process's
  # heap. `bridge_path` and `test_socket_path` are explicit integration-test
  # seams; production callers should leave both nil.
  def self.access(
    references,
    reason:,
    ttl:,
    bridge_path: nil,
    test_socket_path: nil
  )
    request = {
      version: 1,
      references: Array(references),
      reason: String(reason),
      ttlSeconds: Integer(ttl)
    }
    validate_request!(request)

    path = bridge_path || DEFAULT_BRIDGE_PATH
    validate_bridge_path!(path, testing_override: !bridge_path.nil?)
    response = run_bridge(request, path, test_socket_path: test_socket_path)
    raise Error, 'unsupported bridge response version' unless response['version'] == 1

    if (failure = response['failure'])
      code = failure['code']
      raise Denied, 'consent denied' if code == 'consent_denied'

      message = failure['message'].is_a?(String) ? failure['message'] : 'bridge request failed'
      raise Error, "#{code || 'bridge_error'}: #{message}"
    end

    values = response['values']
    raise Error, 'malformed bridge response: missing values' unless values.is_a?(Hash)
    expected_keys = request[:references].uniq.sort
    unless values.keys.sort == expected_keys && values.values.all? { |value| value.is_a?(String) }
      raise Error, 'malformed bridge response: values do not match requested references'
    end

    values
  rescue ArgumentError, TypeError => e
    raise Error, "invalid request: #{e.message}"
  end

  def self.validate_request!(request)
    refs = request.fetch(:references)
    ttl = request.fetch(:ttlSeconds)
    reason = request.fetch(:reason)
    raise Error, 'at least one reference is required' if refs.empty?
    raise Error, 'too many references' if refs.length > 64
    unless refs.all? { |reference| reference.is_a?(String) && reference.include?('://') }
      raise Error, 'every reference must be a URI string'
    end
    raise Error, 'ttl must be between 1 and 86400 seconds' unless ttl.between?(1, 86_400)
    raise Error, 'reason must be between 1 and 512 bytes' unless reason.bytesize.between?(1, 512)
  end
  private_class_method :validate_request!

  def self.validate_bridge_path!(path, testing_override:)
    raise Error, 'bridge path must be absolute' unless path.is_a?(String) && path.start_with?('/')
    raise Error, "signed csec bridge is not executable at #{path}" unless File.executable?(path)

    # The test seam intentionally points to an ad-hoc build/fake executable.
    # The normal path must also be independently protected against replacement;
    # csecd performs the final live code-signing check on every connection.
    return if testing_override

    current = File.realpath(path)
    loop do
      stat = File.stat(current)
      unless stat.uid.zero? && (stat.mode & 0o022).zero? && !File.writable?(current)
        raise Error, "installed bridge path is user-writable: #{current}"
      end
      parent = File.dirname(current)
      break if parent == current

      current = parent
    end
  rescue SystemCallError => e
    raise Error, "cannot validate signed csec bridge: #{e.message}"
  end
  private_class_method :validate_bridge_path!

  def self.run_bridge(request, path, test_socket_path:)
    environment = { 'PATH' => MINIMAL_PATH }
    # Release csec compiles out CSEC_SOCKET. This exists solely to point the
    # debug binary at cs-fake-agent in cross-stack tests.
    environment['CSEC_SOCKET'] = test_socket_path if test_socket_path

    response = nil
    Open3.popen3(
      environment,
      path,
      'bridge',
      unsetenv_others: true,
      close_others: true
    ) do |stdin, stdout, stderr, wait_thread|
      [stdin, stdout, stderr].each do |io|
        io.binmode
        # If the Ruby parent replaces its image while consent is pending, the
        # private channel must not flow into that new consumer.
        io.close_on_exec = true
      end
      payload = JSON.generate(request)
      stdin.write([payload.bytesize].pack('N'))
      stdin.write(payload)
      stdin.close

      response = JSON.parse(read_frame(stdout))
      # Drain diagnostics without reflecting them into an exception: a bridge
      # failure must remain value-free even if a future dependency logs badly.
      stderr.read
      status = wait_thread.value
      if !status.success? && !response['failure']
        raise Error, 'signed csec bridge exited without a typed failure'
      end
    end
    response
  rescue Errno::ENOENT, Errno::EACCES => e
    raise Error, "cannot launch signed csec bridge: #{e.message}"
  rescue JSON::ParserError
    raise Error, 'signed csec bridge returned malformed JSON'
  end
  private_class_method :run_bridge

  def self.read_frame(io)
    length = read_exactly(io, 4).unpack1('N')
    if length.zero? || length > MAX_FRAME_BYTES
      raise Error, "bridge sent an out-of-range frame length (#{length})"
    end
    read_exactly(io, length)
  end
  private_class_method :read_frame

  def self.read_exactly(io, count)
    buffer = +''
    buffer.force_encoding(Encoding::BINARY)
    while buffer.bytesize < count
      chunk = io.read(count - buffer.bytesize)
      raise Error, 'bridge closed its private pipe mid-response' if chunk.nil? || chunk.empty?

      buffer << chunk
    end
    buffer
  end
  private_class_method :read_exactly
end
