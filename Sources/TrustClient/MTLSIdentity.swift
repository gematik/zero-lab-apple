import Foundation
import CryptoKit
import X509
import DeviceCheck
import SwiftASN1

class MTLSIdentity: SecureEnclaveIdentity {
    var context: String
    var mtlsKeyTag: String
    var mtlsAccessFlags: SecAccessControlCreateFlags
    var mtlsKey: SecKey!
    var mtlsIdentity: SecIdentity?

    init(
        _ context: String,
        accessFlags: SecAccessControlCreateFlags = [.privateKeyUsage]
    ) throws {
        self.context = context
        self.mtlsKeyTag = "tcl:mtls:\(context)"
        self.mtlsAccessFlags = accessFlags
        super.init()
        try prepareKeys()
    }

    private func prepareKeys() throws {
        let existingKey = try querySecKey(mtlsKeyTag)

        if let existingKey = existingKey {
            self.mtlsKey = existingKey
        } else {
            print("Cannot load existing identity. Creating new one.")
            self.mtlsKey = try generateSecKey(mtlsKeyTag, accessFlags: mtlsAccessFlags)
        }

        self.mtlsIdentity = try querySecIdentity(mtlsKeyTag)
        if self.mtlsIdentity == nil {
            print("No certificate available for identity \(context). MTLS wont work.")
        }

    }

    func reset() throws {
        try deleteSecCertificate(mtlsKeyTag)
        try deleteSecKey(mtlsKeyTag)
        try prepareKeys()
    }

    func updateCertificate(_ certificate: Certificate) throws {
        try updateSecCertificate(mtlsKeyTag, certificate: certificate)
        try prepareKeys()
    }

    func createCertificateSigningRequest() throws -> CertificateSigningRequest {
        let subject = try DistinguishedName([
            .init(type: .NameAttributes.commonName, utf8String: "Trust Client MTLS"),
        ])
        return try createCertificateSigningRequest(subject, withKey: mtlsKey)
    }

    func retrieveCertificate() throws -> Certificate? {
        return try queryCertificate(mtlsKeyTag)
    }

    class MTLSDelegate: NSObject, URLSessionDelegate {
        let identity: MTLSIdentity

        init(_ mtlsIdentity: MTLSIdentity) {
            self.identity = mtlsIdentity
        }

        func urlSession(
            _ session: URLSession,
            didReceive challenge: URLAuthenticationChallenge,
            completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
        ) {
            if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodClientCertificate {
                guard let secIdentity =  identity.mtlsIdentity else {
                    // allow connections without MTLS as fallback
                    completionHandler(.performDefaultHandling, nil)
                    return
                }
                let credential = URLCredential(identity: secIdentity, certificates: nil, persistence: .forSession)
                completionHandler(.useCredential, credential)
            } else {
                completionHandler(.performDefaultHandling, nil)
            }
        }
    }

    func makeURLSession(configuration: URLSessionConfiguration) throws -> URLSession {
        let delegate = MTLSDelegate(self)
        let session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: .none)
        return session

    }

}

