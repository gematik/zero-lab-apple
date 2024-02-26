import Foundation
import CryptoKit
import JOSESwift

fileprivate func josePrivateKey(_ x963Representation: Data) throws -> ECPrivateKey {
    let attributes: [String:Any] = [
        kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
        kSecAttrKeyType as String: kSecAttrKeyTypeEC,
    ]

    var error: Unmanaged<CFError>?
    guard let secKey = SecKeyCreateWithData(x963Representation as CFData, attributes as CFDictionary, &error) else {
       throw error!.takeRetainedValue()
    }
    
    return try ECPrivateKey(privateKey: secKey)
}


fileprivate func josePublicKey(_ x963Representation: Data) throws -> ECPublicKey {
    let attributes: [String:Any] = [
        kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        kSecAttrKeyType as String: kSecAttrKeyTypeEC,
    ]

    var error: Unmanaged<CFError>?
    guard let secKey = SecKeyCreateWithData(x963Representation as CFData, attributes as CFDictionary, &error) else {
       throw error!.takeRetainedValue()
    }
    
    return try ECPublicKey(publicKey: secKey)
}


public extension P256.Signing.PrivateKey {
    func jwk() throws -> ECPrivateKey {
        return try josePrivateKey(self.x963Representation)
    }
}

public extension P384.Signing.PrivateKey {
    func jwk() throws -> ECPrivateKey {
        return try josePrivateKey(self.x963Representation)
    }
}

public extension P521.Signing.PrivateKey {
    func jwk() throws -> ECPrivateKey {
        return try josePrivateKey(self.x963Representation)
    }
}

public extension P256.Signing.PublicKey {
    func jwk() throws -> ECPublicKey {
        return try josePublicKey(self.x963Representation)
    }
}

public extension P384.Signing.PublicKey {
    func jwk() throws -> ECPublicKey {
        return try josePublicKey(self.x963Representation)
    }
}

public extension P521.Signing.PublicKey {
    func jwk() throws -> ECPublicKey {
        return try josePublicKey(self.x963Representation)
    }
}

