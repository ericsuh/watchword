import Foundation
import Testing
import WatchwordModel
import WatchwordTestSupport

@testable import WatchwordInterchange

/// Hand-written fixtures in each format, kept as source so a reviewer can read exactly what is imported.
enum Fixtures {
    static let vaultID = UUID(uuidString: "0B5E0C7E-1111-4222-8333-444455556666")!

    /// A valid Base32 TOTP secret (the RFC 6238 test key, `12345678901234567890`).
    static let totpSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

    // MARK: 1PUX

    /// One vault holding an item of each category with a shape of its own, one of another category, an archived
    /// item and a trashed one. Field names and value types follow 1Password's "1PUX format" documentation.
    static let onePUXDocument = #"""
        {
          "accounts": [
            {
              "attrs": {
                "accountName": "Wendy Appleseed",
                "name": "Wendy Appleseed",
                "avatar": "profile-pic.png",
                "email": "wendy.c.appleseed@example.com",
                "uuid": "D4RI47B7BJDT25C2LWA7LEJLHZ",
                "domain": "https://my.1password.com/"
              },
              "vaults": [
                {
                  "attrs": {"uuid": "rr3lr6c2opoggvrete23q72ahi", "desc": "", "avatar": "pic.png", "name": "Personal", "type": "P"},
                  "items": [
                    {
                      "uuid": "fkruyzrldvizuqlnavfj3gltfe",
                      "favIndex": 1,
                      "createdAt": 1614298956,
                      "updatedAt": 1635346445,
                      "state": "active",
                      "categoryUuid": "001",
                      "details": {
                        "loginFields": [
                          {"value": "wendy@example.com", "id": "", "name": "email", "fieldType": "E", "designation": "username"},
                          {"value": "correct horse battery staple", "id": "", "name": "password", "fieldType": "P", "designation": "password"},
                          {"value": "on", "id": "", "name": "remember", "fieldType": "C", "designation": ""},
                          {"value": "EN-GB", "id": "", "name": "locale", "fieldType": "T", "designation": ""}
                        ],
                        "notesPlain": "Line one\nLine two",
                        "sections": [
                          {
                            "title": "Security",
                            "name": "Section_oazxddhvftfknycbbmh5ntwfa4",
                            "fields": [
                              {"title": "PIN", "id": "CCEF647B399604E8F6Q6C8C3W31AFD407", "value": {"concealed": "12345"}, "indexAtSource": 0, "guarded": false, "multiline": false, "dontGenerate": false, "inputTraits": {"keyboard": "default", "correction": "default", "capitalization": "default"}},
                              {"title": "one-time password", "id": "TOTP_564DCF96EAA24B91B3A7C4E3F5A0D6D1", "value": {"totp": "otpauth://totp/Example:wendy?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example"}, "indexAtSource": 1, "guarded": false, "multiline": false, "dontGenerate": false, "inputTraits": {"keyboard": "default", "correction": "default", "capitalization": "default"}},
                              {"title": "recovery email", "id": "A1B2C3D4E5F60718293A4B5C6D7E8F90", "value": {"email": {"email_address": "backup@example.org", "provider": null}}, "indexAtSource": 2, "guarded": false, "multiline": false, "dontGenerate": false, "inputTraits": {"keyboard": "emailAddress", "correction": "default", "capitalization": "default"}},
                              {"title": "member since", "id": "B1B2C3D4E5F60718293A4B5C6D7E8F91", "value": {"date": 1581854400}, "indexAtSource": 3, "guarded": false, "multiline": false, "dontGenerate": false, "inputTraits": {"keyboard": "default", "correction": "default", "capitalization": "default"}},
                              {"title": "empty", "id": "C1B2C3D4E5F60718293A4B5C6D7E8F92", "value": {"string": ""}, "indexAtSource": 4, "guarded": false, "multiline": false, "dontGenerate": false, "inputTraits": {"keyboard": "default", "correction": "default", "capitalization": "default"}}
                            ]
                          }
                        ],
                        "passwordHistory": [
                          {"value": "older password", "time": 1458322355},
                          {"value": "old password", "time": 1558322355}
                        ]
                      },
                      "overview": {
                        "subtitle": "wendy@example.com",
                        "urls": [
                          {"label": "", "url": "https://www.example.com/login"},
                          {"label": "", "url": "https://accounts.example.co.uk"},
                          {"label": "", "url": "https://github.io"}
                        ],
                        "title": "Example",
                        "url": "https://www.example.com/login",
                        "ps": 54,
                        "pbe": 86.13621,
                        "pgrng": true,
                        "tags": ["work", "shared/finance"]
                      }
                    },
                    {
                      "uuid": "pwd5yzrldvizuqlnavfj3gltfe",
                      "favIndex": 0,
                      "createdAt": 1614298957,
                      "updatedAt": 1635346446,
                      "state": "active",
                      "categoryUuid": "005",
                      "details": {"loginFields": [], "notesPlain": "", "password": "hunter2hunter2", "sections": [], "passwordHistory": []},
                      "overview": {"subtitle": "", "title": "Garage door", "url": "", "ps": 30, "pbe": 40.0, "pgrng": false}
                    },
                    {
                      "uuid": "note3zrldvizuqlnavfj3gltfe",
                      "favIndex": 0,
                      "createdAt": 1614298958,
                      "updatedAt": 1635346447,
                      "state": "active",
                      "categoryUuid": "003",
                      "details": {"loginFields": [], "notesPlain": "The safe is behind the painting.", "sections": [], "passwordHistory": []},
                      "overview": {"subtitle": "The safe is behind", "title": "Safe", "url": "", "tags": []}
                    },
                    {
                      "uuid": "api2yzrldvizuqlnavfj3gltfe",
                      "favIndex": 0,
                      "createdAt": 1614298959,
                      "updatedAt": 1635346448,
                      "state": "active",
                      "categoryUuid": "112",
                      "details": {
                        "loginFields": [],
                        "notesPlain": "",
                        "sections": [
                          {
                            "title": "",
                            "name": "",
                            "fields": [
                              {"title": "username", "id": "username", "value": {"string": "deploy-bot"}, "indexAtSource": 0, "guarded": true, "multiline": false, "dontGenerate": false, "inputTraits": {"keyboard": "default", "correction": "default", "capitalization": "default"}},
                              {"title": "credential", "id": "credential", "value": {"concealed": "sk_live_abc123"}, "indexAtSource": 1, "guarded": true, "multiline": false, "dontGenerate": true, "inputTraits": {"keyboard": "default", "correction": "default", "capitalization": "default"}},
                              {"title": "type", "id": "type", "value": {"menu": "bearer"}, "indexAtSource": 2, "guarded": true, "multiline": false, "dontGenerate": false, "inputTraits": {"keyboard": "default", "correction": "default", "capitalization": "default"}},
                              {"title": "expires", "id": "expires", "value": {"date": 1893499200}, "indexAtSource": 3, "guarded": true, "multiline": false, "dontGenerate": false, "inputTraits": {"keyboard": "default", "correction": "default", "capitalization": "default"}},
                              {"title": "hostname", "id": "hostname", "value": {"string": "api.example.com"}, "indexAtSource": 4, "guarded": true, "multiline": false, "dontGenerate": false, "inputTraits": {"keyboard": "default", "correction": "default", "capitalization": "default"}}
                            ]
                          }
                        ],
                        "passwordHistory": []
                      },
                      "overview": {"subtitle": "", "title": "Deploy token", "url": "", "tags": ["work"]}
                    },
                    {
                      "uuid": "bank1zrldvizuqlnavfj3gltfe",
                      "favIndex": 0,
                      "createdAt": 1614298960,
                      "updatedAt": 1635346449,
                      "state": "active",
                      "categoryUuid": "101",
                      "details": {
                        "loginFields": [],
                        "notesPlain": "Joint account",
                        "sections": [
                          {
                            "title": "",
                            "name": "",
                            "fields": [
                              {"title": "bank name", "id": "bankName", "value": {"string": "First Example Bank"}, "indexAtSource": 0, "guarded": true, "multiline": false, "dontGenerate": false, "inputTraits": {"keyboard": "default", "correction": "default", "capitalization": "words"}},
                              {"title": "type", "id": "accountType", "value": {"menu": "savings"}, "indexAtSource": 1, "guarded": true, "multiline": false, "dontGenerate": false, "inputTraits": {"keyboard": "default", "correction": "default", "capitalization": "default"}},
                              {"title": "routing number", "id": "routingNo", "value": {"string": "021000021"}, "indexAtSource": 2, "guarded": true, "multiline": false, "dontGenerate": false, "inputTraits": {"keyboard": "numberPad", "correction": "default", "capitalization": "default"}},
                              {"title": "account number", "id": "accountNo", "value": {"string": "9876543210"}, "indexAtSource": 3, "guarded": true, "multiline": false, "dontGenerate": false, "inputTraits": {"keyboard": "numberPad", "correction": "default", "capitalization": "default"}},
                              {"title": "IBAN", "id": "iban", "value": {"string": "GB33BUKB20201555555555"}, "indexAtSource": 4, "guarded": true, "multiline": false, "dontGenerate": false, "inputTraits": {"keyboard": "default", "correction": "default", "capitalization": "allCharacters"}},
                              {"title": "PIN", "id": "telephonePin", "value": {"concealed": "4321"}, "indexAtSource": 5, "guarded": true, "multiline": false, "dontGenerate": true, "inputTraits": {"keyboard": "numberPad", "correction": "default", "capitalization": "default"}}
                            ]
                          },
                          {
                            "title": "Branch Information",
                            "name": "branchInfo",
                            "fields": [
                              {"title": "phone", "id": "branchPhone", "value": {"phone": "+44 20 7946 0000"}, "indexAtSource": 0, "guarded": true, "multiline": false, "dontGenerate": false, "inputTraits": {"keyboard": "namePhonePad", "correction": "default", "capitalization": "default"}}
                            ]
                          }
                        ],
                        "passwordHistory": []
                      },
                      "overview": {"subtitle": "First Example Bank", "title": "Savings", "url": "", "tags": []}
                    },
                    {
                      "uuid": "memb1zrldvizuqlnavfj3gltfe",
                      "favIndex": 0,
                      "createdAt": 1614298961,
                      "updatedAt": 1635346450,
                      "state": "archived",
                      "categoryUuid": "105",
                      "details": {
                        "loginFields": [],
                        "notesPlain": "",
                        "sections": [
                          {
                            "title": "",
                            "name": "",
                            "fields": [
                              {"title": "group", "id": "org_name", "value": {"string": "City Library"}, "indexAtSource": 0, "guarded": true, "multiline": false, "dontGenerate": false, "inputTraits": {"keyboard": "default", "correction": "default", "capitalization": "words"}},
                              {"title": "website", "id": "website", "value": {"url": "https://library.example.org/account"}, "indexAtSource": 1, "guarded": true, "multiline": false, "dontGenerate": false, "inputTraits": {"keyboard": "URL", "correction": "default", "capitalization": "default"}},
                              {"title": "member ID", "id": "membership_no", "value": {"string": "L-000123"}, "indexAtSource": 2, "guarded": true, "multiline": false, "dontGenerate": false, "inputTraits": {"keyboard": "default", "correction": "default", "capitalization": "default"}},
                              {"title": "expiry date", "id": "expiry_date", "value": {"monthYear": 203012}, "indexAtSource": 3, "guarded": true, "multiline": false, "dontGenerate": false, "inputTraits": {"keyboard": "default", "correction": "default", "capitalization": "default"}},
                              {"title": "PIN", "id": "pin", "value": {"concealed": "0420"}, "indexAtSource": 4, "guarded": true, "multiline": false, "dontGenerate": true, "inputTraits": {"keyboard": "numberPad", "correction": "default", "capitalization": "default"}}
                            ]
                          }
                        ],
                        "passwordHistory": []
                      },
                      "overview": {"subtitle": "City Library", "title": "Library card", "url": "", "tags": []}
                    },
                    {
                      "uuid": "card1zrldvizuqlnavfj3gltfe",
                      "favIndex": 0,
                      "createdAt": 1614298962,
                      "updatedAt": 1635346451,
                      "state": "active",
                      "categoryUuid": "002",
                      "details": {
                        "loginFields": [],
                        "notesPlain": "",
                        "sections": [
                          {
                            "title": "",
                            "name": "",
                            "fields": [
                              {"title": "cardholder name", "id": "cardholder", "value": {"string": "Wendy Appleseed"}, "indexAtSource": 0, "guarded": true, "multiline": false, "dontGenerate": false, "inputTraits": {"keyboard": "default", "correction": "default", "capitalization": "words"}},
                              {"title": "type", "id": "type", "value": {"creditCardType": "visa"}, "indexAtSource": 1, "guarded": true, "multiline": false, "dontGenerate": false, "inputTraits": {"keyboard": "default", "correction": "default", "capitalization": "default"}},
                              {"title": "number", "id": "ccnum", "value": {"creditCardNumber": "4111111111111111"}, "indexAtSource": 2, "guarded": true, "multiline": false, "dontGenerate": false, "inputTraits": {"keyboard": "numberPad", "correction": "default", "capitalization": "default"}},
                              {"title": "verification number", "id": "cvv", "value": {"concealed": "123"}, "indexAtSource": 3, "guarded": true, "multiline": false, "dontGenerate": true, "inputTraits": {"keyboard": "numberPad", "correction": "default", "capitalization": "default"}},
                              {"title": "expiry date", "id": "expiry", "value": {"monthYear": 202912}, "indexAtSource": 4, "guarded": true, "multiline": false, "dontGenerate": false, "inputTraits": {"keyboard": "default", "correction": "default", "capitalization": "default"}},
                              {"title": "billing address", "id": "address", "value": {"address": {"street": "1 Infinite Loop", "city": "Cupertino", "country": "us", "zip": "95014", "state": "CA"}}, "indexAtSource": 5, "guarded": true, "multiline": false, "dontGenerate": false, "inputTraits": {"keyboard": "default", "correction": "default", "capitalization": "default"}},
                              {"title": "statement", "id": "stmt", "value": {"file": {"fileId": "abc", "fileName": "statement.pdf", "decryptedSize": 1024}}, "indexAtSource": 6, "guarded": true, "multiline": false, "dontGenerate": false, "inputTraits": {"keyboard": "default", "correction": "default", "capitalization": "default"}},
                              {"title": "linked login", "id": "ref", "value": {"reference": "fkruyzrldvizuqlnavfj3gltfe"}, "indexAtSource": 7, "guarded": true, "multiline": false, "dontGenerate": false, "inputTraits": {"keyboard": "default", "correction": "default", "capitalization": "default"}},
                              {"title": "hologram", "id": "holo", "value": {"futureType": "sparkly"}, "indexAtSource": 8, "guarded": true, "multiline": false, "dontGenerate": false, "inputTraits": {"keyboard": "default", "correction": "default", "capitalization": "default"}}
                            ]
                          }
                        ],
                        "passwordHistory": []
                      },
                      "overview": {"subtitle": "4111 **** 1111", "title": "Visa", "url": "", "tags": []}
                    },
                    {
                      "uuid": "trsh1zrldvizuqlnavfj3gltfe",
                      "favIndex": 0,
                      "createdAt": 1614298963,
                      "updatedAt": 1635346452,
                      "state": "trashed",
                      "categoryUuid": "001",
                      "details": {
                        "loginFields": [
                          {"value": "old-user", "id": "", "name": "username", "fieldType": "T", "designation": "username"},
                          {"value": "old-pass", "id": "", "name": "password", "fieldType": "P", "designation": "password"}
                        ],
                        "notesPlain": "",
                        "sections": [],
                        "passwordHistory": []
                      },
                      "overview": {"subtitle": "old-user", "title": "Closed account", "url": "https://closed.example.net", "tags": []}
                    }
                  ]
                }
              ]
            }
          ]
        }
        """#

    static var onePUXBytes: [UInt8] { Array(onePUXDocument.utf8) }

    /// A `.1pux` archive of `onePUXDocument`, written by the fixture builder with a deflate member.
    static func onePUXArchive(document: [UInt8] = onePUXBytes) -> [UInt8] {
        let attributes = #"{"version":3,"description":"1Password Unencrypted Export","createdAt":1635346500}"#
        return ZIPFixture([
            ZIPFixture.Member(name: "export.attributes", contents: Array(attributes.utf8)),
            ZIPFixture.Member(name: "export.data", contents: document, data: DeflateFixture.stored(document)),
            ZIPFixture.Member(name: "files/", contents: []),
        ]).bytes()
    }

    // MARK: CSV

    static let applePasswordsCSV = [
        "Title,URL,Username,Password,Notes,OTPAuth",
        "Example,https://example.com/,wendy,\"p,ass\"\"word\",\"two",
        "lines\",otpauth://totp/Example:wendy?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example",
        "Router,http://192.168.1.1/,admin,=cmd|' /C calc'!A0,,",
        "Example (www),https://www.example.com/,wendy@example.com,-leading-dash,,",
        "",
    ].joined(separator: "\n")

    static let onePassword8CSV = [
        "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes",
        "Example,https://example.com/login,wendy,hunter2hunter2,\(totpSecret),true,false,work;family,First note",
        "Old thing,https://old.example.net,olduser,oldpass,,false,true,,",
        "Just a password,,,s3cret-only,,false,false,,",
        "",
    ].joined(separator: "\r\n")

    static let onePassword7CSV = [
        "Title,URL,Username,Password,Notes,Type,Security answer",
        "Example,example.com,wendy,hunter2hunter2,note,Login,Fluffy",
        "",
    ].joined(separator: "\n")

    // MARK: CXF

    /// 32 bytes of credential ID, a 16-byte user handle and a short stand-in for a PKCS#8 key, base64url.
    static let credentialID = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
    static let userHandle = "dXNlci1oYW5kbGUtMDAwMQ"
    static let privateKey = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg"
    static let prfSecret = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8"

    static let cxfDocument = #"""
        {
          "version": {"major": 1, "minor": 0},
          "exporterRpId": "exporter.example",
          "exporterDisplayName": "Exporter",
          "timestamp": 1755129600,
          "accounts": [
            {
              "id": "YWNjb3VudC0x",
              "username": "wendy",
              "email": "wendy@example.com",
              "collections": [],
              "items": [
                {
                  "id": "aXRlbS0x",
                  "creationAt": 1614298956,
                  "modifiedAt": 1635346445,
                  "title": "Example",
                  "favorite": true,
                  "scope": {"urls": ["https://example.com/login", "https://co.uk"], "androidApps": []},
                  "credentials": [
                    {
                      "type": "basic-auth",
                      "username": {"fieldType": "string", "value": "wendy"},
                      "password": {"fieldType": "concealed-string", "value": "correct horse battery staple"}
                    },
                    {
                      "type": "totp",
                      "secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                      "period": 30,
                      "digits": 6,
                      "username": "wendy",
                      "algorithm": "sha1",
                      "issuer": "Example"
                    },
                    {
                      "type": "passkey",
                      "credentialId": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
                      "rpId": "example.com",
                      "username": "wendy",
                      "userDisplayName": "Wendy Appleseed",
                      "userHandle": "dXNlci1oYW5kbGUtMDAwMQ",
                      "key": "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg",
                      "fido2Extensions": {
                        "hmacCredentials": {
                          "algorithm": "hmac-sha256",
                          "credWithUV": "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8",
                          "credWithoutUV": "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8"
                        }
                      }
                    },
                    {"type": "note", "content": {"fieldType": "string", "value": "Remember the dog's name."}},
                    {
                      "type": "custom-fields",
                      "label": "Security questions",
                      "fields": [
                        {"fieldType": "concealed-string", "value": "Fluffy", "label": "First pet?"},
                        {"fieldType": "string", "value": "Springfield", "label": "Town of birth?"}
                      ]
                    }
                  ],
                  "tags": ["work"]
                },
                {
                  "id": "aXRlbS0y",
                  "title": "Deploy token",
                  "credentials": [
                    {
                      "type": "api-key",
                      "key": {"fieldType": "concealed-string", "value": "sk_live_abc123"},
                      "username": {"fieldType": "string", "value": "deploy-bot"},
                      "keyType": {"fieldType": "string", "value": "bearer"},
                      "url": {"fieldType": "string", "value": "https://api.example.com"},
                      "expiryDate": {"fieldType": "date", "value": "2030-01-01"}
                    }
                  ]
                },
                {
                  "id": "aXRlbS0z",
                  "title": "Home network",
                  "credentials": [
                    {
                      "type": "wifi",
                      "ssid": {"fieldType": "string", "value": "Appleseed"},
                      "networkSecurityType": {"fieldType": "wifi-network-security-type", "value": "wpa3-personal"},
                      "passphrase": {"fieldType": "concealed-string", "value": "open sesame"},
                      "hidden": {"fieldType": "boolean", "value": "false"}
                    }
                  ]
                },
                {
                  "id": "aXRlbS00",
                  "title": "Just a note",
                  "credentials": [{"type": "note", "content": {"fieldType": "string", "value": "Nothing else."}}]
                }
              ]
            }
          ]
        }
        """#

    static var cxfBytes: [UInt8] { Array(cxfDocument.utf8) }
}

/// What two imports of the same data must agree on: everything but the identifiers the injected generator made.
struct ItemShape: Equatable, CustomStringConvertible {
    struct FieldShape: Equatable {
        var kind: FieldKind
        var label: String
        var value: String
        var meta: [String: String]
    }

    var title: String
    var scopes: [ServiceScope]
    var fields: [FieldShape]
    var tags: Set<String>
    var notes: String
    var archived: Bool
    var createdAt: Date
    var modifiedAt: Date
    var history: [[FieldShape]]
    var historyDates: [Date]

    init(_ item: Item) {
        func shape(_ field: Field) -> FieldShape {
            FieldShape(kind: field.kind, label: field.label, value: field.value, meta: field.meta)
        }
        title = item.title
        scopes = item.scopes
        fields = item.fields.map(shape)
        tags = item.tags
        notes = item.notes
        archived = item.archived
        createdAt = item.createdAt
        modifiedAt = item.modifiedAt
        history = item.history.map { $0.fields.map(shape) }
        historyDates = item.history.map(\.replacedAt)
    }

    var description: String { "\(title): \(fields.map { "\($0.kind.rawValue)=\($0.value)" })" }
}

extension ImportResult {
    func entry(titled title: String) throws -> ImportedEntry {
        try #require(entries.first { $0.item.title == title }, "no entry titled \(title)")
    }

    func warnings(for title: String) -> [ImportWarning] {
        report.warnings.filter { $0.entry.title == title }.map(\.warning)
    }
}

extension Item {
    func values(_ kind: FieldKind) -> [String] {
        fields.filter { $0.kind == kind }.map(\.value)
    }

    func field(labelled label: String) -> Field? {
        fields.first { $0.label == label }
    }
}
