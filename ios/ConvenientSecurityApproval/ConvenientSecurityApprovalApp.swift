import CSECRemoteApprovalCloudKit
import SwiftUI
import UIKit
import UserNotifications

@main
struct ConvenientSecurityApprovalApp: App {
    @UIApplicationDelegateAdaptor(ApprovalAppDelegate.self) private var appDelegate

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(appDelegate.model)
                .task { await appDelegate.model.start() }
        }
    }
}

/// Owns the model, so a push that launches the app in the background — before
/// any scene or view exists — still has something to refresh.
@MainActor
final class ApprovalAppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    let model = ApprovalViewModel()

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        #if DEBUG && targetEnvironment(simulator)
        // Before the model reads anything: the UI tests' starting state.
        let arguments = ProcessInfo.processInfo.arguments
        SimulatorLaunchArgument.apply(arguments)
        if arguments.contains(SimulatorLaunchArgument.refuseSubscription) {
            model.simulateRefusedSubscriptionForTests()
        }
        if arguments.contains(SimulatorLaunchArgument.openAlertForHiddenRequest) {
            // Where iOS would deliver the tap that launched the app.
            let model = self.model
            Task { await model.openAlertForSimulatedHiddenRequest() }
        }
        #endif
        // Set before launch finishes, so a tap on the alert that launched the
        // app is delivered.
        UNUserNotificationCenter.current().delegate = self
        // Registering for pushes never prompts; showing the alert needs the
        // notification permission the app asks for after setup.
        application.registerForRemoteNotifications()
        return true
    }

    func application(
        _ application: UIApplication,
        didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data
    ) {
        model.pushRegistration(succeeded: true)
    }

    func application(
        _ application: UIApplication,
        didFailToRegisterForRemoteNotificationsWithError error: Error
    ) {
        model.pushRegistration(succeeded: false)
    }

    /// The subscription's content-available wake-up, in the background or the
    /// foreground. It carries no request field: the model fetches the mailbox
    /// and verifies every Mac signature.
    func application(
        _ application: UIApplication,
        didReceiveRemoteNotification userInfo: [AnyHashable: Any],
        fetchCompletionHandler completionHandler: @escaping (UIBackgroundFetchResult) -> Void
    ) {
        let model = self.model
        Task {
            let changed = await model.handleRemoteNotification()
            completionHandler(changed ? .newData : .noData)
        }
    }

    /// The alert arrived while the app is open: refresh, with the request it
    /// names, and still show it — the reader may be looking at something
    /// other than the pending list.
    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        let requestID = CloudKitRemoteApprovalRelay.alertRequestID(
            fromRemoteNotification: notification.request.content.userInfo
        )
        completionHandler([.banner, .list, .sound])
        Task { @MainActor in
            _ = await self.model.handleRemoteNotification(alertRequestID: requestID)
        }
    }

    /// The reader tapped the alert: refresh, read the request it names by its
    /// ID, and bring that request's card up. The alert's record name is
    /// `alert-<requestID>`; nothing else in the push is used.
    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        let requestID = CloudKitRemoteApprovalRelay.alertRequestID(
            fromRemoteNotification: response.notification.request.content.userInfo
        )
        Task { @MainActor in
            await self.model.handleNotificationTap(requestID: requestID)
            completionHandler()
        }
    }
}
