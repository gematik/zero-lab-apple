import Foundation
import CryptoKit
import SwiftASN1


class JOSEIdentity: SecureEnclaveIdentity {
    var context: String
    var keyTag: String
    var accessFlags: SecAccessControlCreateFlags
    var _privateSecKey: SecKey?
    var publicKey: P256.Signing.PublicKey!
    var privateSecKey: SecKey {
        return _privateSecKey!
    }

    init(
        _ context: String,
        accessFlags: SecAccessControlCreateFlags = [.privateKeyUsage]
    ) throws {
        self.context = context
        self.keyTag = "tcl:jose:\(context)"
        self.accessFlags = accessFlags
        super.init()
        try prepareKeys()
    }

    private func prepareKeys() throws {
        let existingSecKey = try querySecKey(keyTag)

        if let existingKey = existingSecKey {
            self._privateSecKey = existingKey
        } else {
            print("Cannot load existing identity. Creating new one.")
            self._privateSecKey = try generateSecKey(keyTag, accessFlags: accessFlags)
        }

        self.publicKey = try getPublicKey(privateKey: self._privateSecKey!)
    }

}

