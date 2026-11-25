import ConvenientSecurity
import Foundation
import Darwin

func runGcloud(_ arguments: [String]) -> Never {
    guard arguments.count >= 3, arguments[0] == "--item", (try? SecretRef(arguments[1])) != nil,
          arguments[2] == "--" else { usage("gcloud") }
    let commandArguments = Array(arguments.dropFirst(3))
    guard GcloudCommand.accepts(commandArguments) else {
        csecError("gcloud", "this wrapper runs API commands with a reviewed access token; use csec identity setup google for sign-in setup, gcloud storage for storage, and the Google client libraries for BigQuery. Alternate credentials, gcloud impersonation and credential-management commands are not supported")
        exit(2)
    }
    for (name, value) in GcloudCommand.environment {
        guard setenv(name, value, 1) == 0 else {
            csecError("gcloud", "could not configure gcloud's in-memory sign-in")
            exit(1)
        }
    }
    runExec(["--set", "\(GcloudCommand.tokenVariable)=\(arguments[1])",
             "--reason", "Google Cloud sign-in", "--redact-output=always", "--", "gcloud"] + commandArguments)
}
