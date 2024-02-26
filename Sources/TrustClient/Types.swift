import Foundation

public enum AttestationFormat: String, Codable {
    case attestation = "apple-attestation"
    case assertion = "apple-assertion"
}

public enum RegistrationStatus: String, Codable {
    case pending = "pending"
    case error = "error"
    case cancelled = "cancelled"
    case complete = "complete"
}

public struct RegistrationRequest: Encodable {
    public let name: String
    public let csr: Data
}

public struct RegistrationChallenge: Codable {
    public let type: String
    public let url: String
    public let status: String
}

public struct RegistrationResponse: Decodable {
    public let id: String
    public let status: RegistrationStatus
    public let challenges: [RegistrationChallenge]
    public var clientId: String? = nil
    public var clientLocation: String? = nil
    public var clientCertificate: Data? = nil
}

public struct EchoResponse: Decodable {
    public let headers: [String: [String]]
    public let host: String
    public let metadata: [String: String]
    public let method: String
    public let proto: String
    public let remoteAddr: String
    public let requestURI: String
    public let tlsCipherSuite: String
    public let tlsClientCertificates: [TLSCertificate]
    public let tlsHostname: String
    public let tlsVersion: String
}

public struct TLSCertificate: Codable {
    public let issuer: String
    public let notAfter: String
    public let notBefore: String
    public let subject: String
}
