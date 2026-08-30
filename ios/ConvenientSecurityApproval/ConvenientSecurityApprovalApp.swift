import SwiftUI
import UIKit

@main
struct ConvenientSecurityApprovalApp: App {
    @UIApplicationDelegateAdaptor(ApprovalAppDelegate.self) private var appDelegate
    @StateObject private var model = ApprovalViewModel()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(model)
                .task {
                    appDelegate.model = model
                    await model.start()
                }
        }
    }
}

final class ApprovalAppDelegate: NSObject, UIApplicationDelegate {
    weak var model: ApprovalViewModel?

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        application.registerForRemoteNotifications()
        return true
    }

    func application(
        _ application: UIApplication,
        didReceiveRemoteNotification userInfo: [AnyHashable: Any],
        fetchCompletionHandler completionHandler: @escaping (UIBackgroundFetchResult) -> Void
    ) {
        guard let model else {
            completionHandler(.noData)
            return
        }
        Task { @MainActor in
            let changed = await model.refresh()
            completionHandler(changed ? .newData : .noData)
        }
    }
}
