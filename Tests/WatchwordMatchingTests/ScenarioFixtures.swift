import Foundation
import WatchwordModel

/// PRD scenario S1: one email, two Amazon accounts.
enum ScenarioFixtures {
    static let vault = UUID()

    static let amazonRetail = Item(
        vaultID: vault,
        title: "Amazon",
        scopes: [ServiceScope(host: "amazon.com", includeSubdomains: true)],
        fields: [
            Field(kind: .email, label: "email", value: "person@example.com"),
            Field(kind: .password, label: "password", value: "retail-password"),
            Field(
                kind: .totp, label: "one-time code",
                value: "otpauth://totp/Amazon:person@example.com?secret=RETAIL&issuer=Amazon"),
        ]
    )

    static let awsRoot = Item(
        vaultID: vault,
        title: "AWS root",
        scopes: [
            ServiceScope(host: "signin.aws.amazon.com", includeSubdomains: false),
            ServiceScope(host: "console.aws.amazon.com", includeSubdomains: true),
        ],
        fields: [
            Field(kind: .email, label: "email", value: "person@example.com"),
            Field(kind: .password, label: "password", value: "aws-password"),
            Field(
                kind: .totp, label: "one-time code",
                value: "otpauth://totp/AWS:person@example.com?secret=AWSROOT&issuer=AWS"),
        ]
    )

    static let all = [amazonRetail, awsRoot]
}
