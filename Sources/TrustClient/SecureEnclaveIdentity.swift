import Foundation
import X509
import CryptoKit
import SwiftASN1


public struct SecureEnclaveIdentityError: Error {
    var details: String
    init(_ error:  Unmanaged<CFError>) {
        details = "\(error.self): \(error.takeRetainedValue().localizedDescription)"
    }
    init(_ details: String) {
        self.details = details
    }
}

/// Base class for all identities which use SecKeys from Secure Enclave
class SecureEnclaveIdentity {
    func querySecKey(_ keyTag: String) throws -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag,
            kSecReturnRef as String: true
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            return nil
        }
        return (item as! SecKey)
    }

    func querySecIdentity(_ keyTag: String) throws -> SecIdentity? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrApplicationTag as String: keyTag,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnRef as String: true,
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            return nil
        }

        return (item as! SecIdentity)
    }

    func deleteSecKey(_ keyTag: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag,
            kSecReturnRef as String: true
        ]

        SecItemDelete(query as CFDictionary)
    }

    func generateSecKey(_ keyTag: String, accessFlags: SecAccessControlCreateFlags) throws -> SecKey {
        // delete key if it already exists
        try deleteSecKey(keyTag)

        var error: Unmanaged<CFError>?

        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            accessFlags,
            &error
        ) else {
            throw SecureEnclaveIdentityError(error!)
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: keyTag,
                kSecAttrAccessControl as String: access,
            ]
        ]

        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw SecureEnclaveIdentityError(error!)
        }

        return privateKey
    }

    func sign(_ data: Data, withKey privateKey: SecKey, algorithm: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256) throws -> Data {
        guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
            throw SecureEnclaveIdentityError("Algorithm not supported")
        }

        var error: Unmanaged<CFError>?

        guard let signature = SecKeyCreateSignature(
            privateKey,
            algorithm,
            data as CFData,
            &error
        ) as Data? else {
            throw SecureEnclaveIdentityError(error!)
        }

        return signature

    }

    func createCertificateSigningRequest(
        _ subject: DistinguishedName,
        withKey privateKey: SecKey,
        attributes: CertificateSigningRequest.Attributes = CertificateSigningRequest.Attributes()
    ) throws -> CertificateSigningRequest {
        let puk = try getPublicKey(privateKey: privateKey)

        var coder = DER.Serializer()

        /*
         let extensions = try Certificate.Extensions {
         //https://oidref.com/1.3.6.1.5.5.7.48.1.2
         Certificate.Extension(oid: [1, 3, 6, 1 ,5, 5, 7, 48, 1, 2], critical: true, value: "foo".data(using: .utf8)!.slice)
         }
         let extensionRequest = ExtensionRequest(extensions: extensions)

         var varAttrs = try CertificateSigningRequest.Attributes(
         [.init(extensionRequest)]
         )
         */

        try coder.appendConstructedNode(identifier: .sequence) { coder in
            try coder.serialize(CertificateSigningRequest.Version.v1.rawValue)
            try coder.serialize(subject)
            coder.serializeRawBytes(puk.derRepresentation)
            try coder.serializeSetOf(attributes, identifier: .init(tagWithNumber: 0, tagClass: .contextSpecific))
        }

        let infoBytes = coder.serializedBytes

        let derSignature = try sign(Data(infoBytes), withKey: privateKey)

        let signature = try P256.Signing.ECDSASignature(derRepresentation: derSignature)

        // sanity self-check: ist sognature valid?
        if !puk.isValidSignature(signature, for: SHA256.hash(data: infoBytes)) {
            throw SecureEnclaveIdentityError("Our own signature is not valid")
        }

        let half = signature.rawRepresentation.count / 2
        let r = signature.rawRepresentation.prefix(upTo: half).asn1Integer
        let s = signature.rawRepresentation.suffix(from: half).asn1Integer
        coder = DER.Serializer()
        try coder.appendConstructedNode(identifier: .sequence) { coder in
            try coder.serialize(r)
            try coder.serialize(s)
        }
        let signatureBytes = coder.serializedBytes

        // create the whole CSR ASN.1 structure
        coder = DER.Serializer()
        try coder.appendConstructedNode(identifier: .sequence) { coder in
            coder.serializeRawBytes(infoBytes)
            try coder.appendConstructedNode(identifier: .sequence) { coder in
                let ecdsaWithSHA256: ASN1ObjectIdentifier = [1, 2, 840, 10045, 4, 3, 2]
                try coder.serialize(ecdsaWithSHA256)
            }
            try coder.serialize(ASN1BitString(bytes: ArraySlice(signatureBytes)))
        }

        return try CertificateSigningRequest(derEncoded: coder.serializedBytes)
    }

    func deleteSecCertificate(_ keyTag: String) throws {
        // delete existing certificate
        let deleteQuery: [String: Any] = [kSecClass as String: kSecClassCertificate,
                                          kSecAttrLabel as String: keyTag]
        SecItemDelete(deleteQuery as CFDictionary)
    }

    func queryCertificate(_ keyTag: String) throws -> Certificate? {
        let retrieveQuery: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: keyTag,
            kSecReturnRef as String: true,
        ]
        var result : CFTypeRef?
        let status : OSStatus = SecItemCopyMatching(retrieveQuery as CFDictionary, &result)

        guard status == errSecSuccess else {
            return nil
        }

        let secCert = result as! SecCertificate
        let certData = SecCertificateCopyData(secCert) as Data

        return try Certificate(derEncoded: certData.slice)
    }

    func updateSecCertificate(_ keyTag: String, certificate: Certificate) throws  {
        // delete certificate if it alreaedy exists
        try deleteSecCertificate(keyTag)

        var der = DER.Serializer()
        try certificate.serialize(into: &der)

        // Create a SecCertificate object from DER data
        guard let secCert = SecCertificateCreateWithData(nil, Data(der.serializedBytes) as CFData) else {
            throw SecureEnclaveIdentityError("Unable to convert DER to SecCertificate")
        }

        let addQuery: [String: Any] = [
         kSecClass as String: kSecClassCertificate,
         kSecValueRef as String: secCert,
         kSecAttrLabel as String: keyTag
        ]
        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        guard addStatus == errSecSuccess else { throw SecureEnclaveIdentityError("Error storing certificate in keychain: \(addStatus)")}
    }

    func getPublicKey(privateKey: SecKey) throws -> P256.Signing.PublicKey {
        var error: Unmanaged<CFError>?

        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw SecureEnclaveIdentityError("Unable to extract public key")
        }
        guard let pukData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw SecureEnclaveIdentityError("Error copying public key")
        }

        return try P256.Signing.PublicKey(x963Representation: pukData)
    }

}
