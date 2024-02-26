import Foundation
import CryptoKit
import JOSESwift

/// Extension to convert between JWK ECPrivateKey and SecKey
extension ECPrivateKey {
    func secKey() throws -> SecKey {
        if self.keyType != .EC {
            throw JOSESwiftError.invalidCurveType
        }
                
        let d = Data(base64URLEncoded: self.privateKey.data(using: .utf8)!)!
        let x963Representation = switch(self.crv) {
        case .P256:
            try P256.Signing.PrivateKey(rawRepresentation: d).x963Representation
        case .P384:
            try P384.Signing.PrivateKey(rawRepresentation: d).x963Representation
        case .P521:
            try P521.Signing.PrivateKey(rawRepresentation: d).x963Representation
        }
                
        let attributes: [String:Any] = [
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
        ]

        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(x963Representation as CFData, attributes as CFDictionary, &error) else {
           throw error!.takeRetainedValue()
        }

        return secKey
    }
}
