import Foundation

/// One run of csecd's update check: fetch the signed manifest and its
/// signature, keep the manifest if it verifies and is newer, and say whether a
/// newer release should be announced. It changes nothing on the Mac but its
/// own Updates folder, and never downloads or installs a package.
public struct ReleaseUpdateChecker: Sendable {
    public typealias Fetch = @Sendable (URL) async throws -> Data

    public enum Outcome: Equatable, Sendable {
        /// Nothing to do: a development build, or no pinned key.
        case off(String)
        /// The fetch or the manifest failed; the held copy (if any) stays.
        case failed(String)
        /// Checked; nothing new to announce.
        case checked(ReleaseUpdateStatus)
        /// Checked, and this newer release has not been announced before.
        case announce(ReleaseManifest.Release, running: ReleaseBuild)
    }

    public let store: ReleaseManifestStore
    public let running: ReleaseStamp?
    public let fetch: Fetch

    public init(store: ReleaseManifestStore = ReleaseManifestStore(),
                running: ReleaseStamp? = ReleaseStamp.current,
                fetch: @escaping Fetch = ReleaseManifestFetcher.fetch) {
        self.store = store
        self.running = running
        self.fetch = fetch
    }

    public func check(now: Date = Date()) async -> Outcome {
        if case let .off(reason) = ReleaseUpdateStatus.evaluate(
            running: running, trustedKeys: store.trustedKeys, held: nil, state: ReleaseUpdateCheckState()) {
            return .off(reason)
        }
        var state = store.loadState()
        state.lastAttempt = now
        let failure: String
        do {
            let bytes = try await fetch(ReleaseManifest.manifestURL)
            let signatureData = try await fetch(ReleaseManifest.signatureURL)
            guard let signature = String(data: signatureData, encoding: .utf8) else {
                throw ReleaseManifestFetcher.Failure.notText
            }
            switch try store.accept(bytes: bytes, signature: signature) {
            case .failure(let refused):
                failure = refused.summary
            case .success:
                state.lastSuccess = now
                state.lastFailure = nil
                let status = ReleaseUpdateStatus.evaluate(
                    running: running, trustedKeys: store.trustedKeys, held: store.load(), state: state)
                if case let .available(release, runningBuild) = status,
                   state.announced != release.build.description {
                    state.announced = release.build.description
                    try? store.saveState(state)
                    return .announce(release, running: runningBuild)
                }
                try? store.saveState(state)
                return .checked(status)
            }
        } catch let fetchFailure as ReleaseManifestFetcher.Failure {
            failure = fetchFailure.summary
        } catch {
            failure = "could not save the manifest (\((error as NSError).domain) \((error as NSError).code))"
        }
        state.lastFailure = failure
        try? store.saveState(state)
        return .failed(failure)
    }
}

/// Fetches one manifest file. The request carries nothing that identifies
/// the Mac, the person or the installed build: no cookies or cache, a fixed
/// User-Agent without a version, no query, and no redirect followed. Only
/// https to the fixed address, with the system's certificate checks.
public enum ReleaseManifestFetcher {
    public static let userAgent = "ConvenientSecurity"

    public enum Failure: Error, Equatable, Sendable {
        case unreachable(Int)
        case status(Int)
        case tooLarge
        case notText

        public var summary: String {
            switch self {
            case let .unreachable(code): return "could not reach the release server (error \(code))"
            case let .status(code): return "the release server answered \(code)"
            case .tooLarge: return "the release server sent more than a manifest"
            case .notText: return "the signature is not text"
            }
        }
    }

    /// The exact request csec sends, so its headers are tested.
    public static func request(for url: URL) -> URLRequest {
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 30)
        request.httpMethod = "GET"
        request.httpShouldHandleCookies = false
        request.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        request.setValue("*/*", forHTTPHeaderField: "Accept")
        request.setValue("en", forHTTPHeaderField: "Accept-Language")
        return request
    }

    public static func sessionConfiguration() -> URLSessionConfiguration {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieAcceptPolicy = .never
        configuration.httpShouldSetCookies = false
        configuration.httpCookieStorage = nil
        configuration.urlCache = nil
        configuration.urlCredentialStorage = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.timeoutIntervalForRequest = 30
        configuration.timeoutIntervalForResource = 60
        configuration.waitsForConnectivity = false
        return configuration
    }

    @Sendable
    public static func fetch(_ url: URL) async throws -> Data {
        guard url.scheme == "https" else { throw Failure.unreachable(NSURLErrorAppTransportSecurityRequiresSecureConnection) }
        let session = URLSession(configuration: sessionConfiguration())
        defer { session.finishTasksAndInvalidate() }
        let bytes: URLSession.AsyncBytes
        let response: URLResponse
        do {
            (bytes, response) = try await session.bytes(for: request(for: url), delegate: RedirectRefusal())
        } catch {
            throw Failure.unreachable((error as NSError).code)
        }
        guard let http = response as? HTTPURLResponse else { throw Failure.unreachable(NSURLErrorBadServerResponse) }
        guard http.statusCode == 200 else { throw Failure.status(http.statusCode) }
        var data = Data()
        do {
            for try await byte in bytes {
                data.append(byte)
                if data.count > ReleaseManifest.maximumBytes { throw Failure.tooLarge }
            }
        } catch let failure as Failure {
            throw failure
        } catch {
            throw Failure.unreachable((error as NSError).code)
        }
        return data
    }

    /// A redirect would send the request somewhere csec did not choose; the
    /// 3xx answer is reported as the failure instead.
    private final class RedirectRefusal: NSObject, URLSessionTaskDelegate, Sendable {
        func urlSession(_ session: URLSession, task: URLSessionTask,
                        willPerformHTTPRedirection response: HTTPURLResponse,
                        newRequest request: URLRequest) async -> URLRequest? {
            nil
        }
    }
}

/// The words of csecd's one notification for a newer release.
public enum ReleaseUpdateNotice {
    public static let identifier = "csec-update-available"

    public static func words(release: ReleaseManifest.Release, running: ReleaseBuild) -> (title: String, body: String) {
        let host = release.download.host ?? release.download.absoluteString
        // A rebuilt release keeps its version, so the builds tell them apart.
        let sameVersion = release.build.version == running.version
        let offered = sameVersion ? release.build.description : release.build.version.description
        let installed = sameVersion ? running.description : running.version.description
        return ("csec \(offered) is available",
                "This Mac runs csec \(installed). Download the new package from \(host); "
                    + "`csec doctor` shows the link.")
    }
}
