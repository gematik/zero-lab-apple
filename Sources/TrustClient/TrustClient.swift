import CryptoKit
import X509
import JOSESwift
import SwiftASN1
import AuthenticationServices
import SwiftUI


public enum TrustClientError: Error {
    case genericError(_ details: String = "")
    case invalidRuntimeEnvironent(_ details: String = "")
    case clientNotRegistered
    case badServerResponse(_ statusCode: Int)
    case attestationFailed(cause: Error?)
}

public class TrustClient {
    var _state: State
    public var state: State {
        return _state
    }
    public var urlSessionConfig: URLSessionConfiguration
    public static var defaultUrlSessionConfig: URLSessionConfiguration {
        let config = URLSessionConfiguration.ephemeral
        config.httpAdditionalHeaders = [
            "User-Agent": "TrustClient/0.0.1"
        ]
        return config
    }

    public enum State {
        case unregistered
        case registrationPending
        case registrationError
        case registrationExpired
        case registered
    }

    struct Endpoints {
        let baseURL: URL
        let nonce: URL
        let newRegistration: URL
        // debugging
        let echo: URL
        let issueAnonymousCert: URL
        init(baseURL: URL) {
            self.baseURL = baseURL
            self.nonce = URL(string: "/reg/nonce", relativeTo: baseURL)!
            self.newRegistration = URL(string: "/reg/registrations", relativeTo: baseURL)!
            // debugging
            self.echo = URL(string: "/echo", relativeTo: baseURL)!
            self.issueAnonymousCert = URL(string: "/ca/issue-cert", relativeTo: baseURL)!
        }
    }
    
    var endpoints: Endpoints
    var urlSession: URLSession

    var attestor: Attestor
    var mtlsIdentity: MTLSIdentity
    var mtlsURLSession: URLSession

    var joseIdentity: JOSEIdentity

    var registrationURL: URL?
    
    public init(
        regURL: URL,
        context: String = "default",
        urlSessionConfig: URLSessionConfiguration = TrustClient.defaultUrlSessionConfig
    ) throws {
        self.endpoints = Endpoints(baseURL: regURL)
        self.urlSessionConfig = urlSessionConfig
        self.urlSession = URLSession(configuration: urlSessionConfig)

        self.attestor = Attestor(context)

        self.mtlsIdentity = try MTLSIdentity(context)
        self.mtlsURLSession = try self.mtlsIdentity.makeURLSession(configuration: urlSessionConfig)

        joseIdentity = try JOSEIdentity(context)

        if let cert = try mtlsIdentity.retrieveCertificate() {
            if cert.notValidAfter <= Date() {
                self._state = .registrationExpired
            } else {
                self._state = .registered
            }
        } else {
            self._state = .unregistered
        }
    }

    public func makeMTLSURLSession(configuration: URLSessionConfiguration = URLSessionConfiguration.ephemeral) throws -> URLSession {
        return try self.mtlsIdentity.makeURLSession(configuration: configuration)
    }

    public func echo() async throws -> EchoResponse {
        let request = URLRequest(url: endpoints.echo)

        let (data, response) = try await mtlsURLSession.data(for: request)
        let statusCode = (response as! HTTPURLResponse).statusCode
        if statusCode != 200 {
            throw TrustClientError.badServerResponse(statusCode)
        }
        guard let echoOutput = try? JSONDecoder().decode(EchoResponse.self, from: data) else {
            throw TrustClientError.genericError("Unable to parse JSON to \(EchoResponse.self)")
        }

        return echoOutput
    }
    
    public func updateMTLSCertificate() async throws -> Certificate {
        let csr = try mtlsIdentity.createCertificateSigningRequest()
        let csrPEM = try csr.serializeAsPEM()
        print(csrPEM.pemString)
        var request = URLRequest(url: endpoints.issueAnonymousCert)
        request.addValue("application/pkcs10", forHTTPHeaderField: "Content-Type")
        request.httpMethod = "POST"
        request.httpBody = Data(csrPEM.derBytes)

        let (data, response) = try await urlSession.data(for: request)
        let statusCode = (response as! HTTPURLResponse).statusCode
        if statusCode != 200 {
            throw TrustClientError.badServerResponse(statusCode)
        }

        guard let pemString = String(data: data, encoding: .utf8) else {
            throw TrustClientError.genericError("Unable to parse server response.")
        }
        let certificate = try Certificate(pemEncoded: pemString)

        try mtlsIdentity.updateCertificate(certificate)

        return certificate
    }

    public func nonce() async throws -> String {
        var request = URLRequest(url: endpoints.nonce)
        request.httpMethod = "HEAD"

        let (_, response) = try await urlSession.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw TrustClientError.genericError("Where did HTTP go?")
        }
        if httpResponse.statusCode != 201 {
            throw TrustClientError.badServerResponse(httpResponse.statusCode)
        }

        guard let nonce = httpResponse.value(forHTTPHeaderField: "Replay-Nonce") else {
            throw TrustClientError.genericError("Header Replay-Nonce is noct set")
        }

        return nonce
    }

    public func register(nonce: String, authenticationSessionCallback: ((URL) async throws ->URL)? = nil) async throws -> RegistrationResponse {
        let pukJwk = try joseIdentity.publicKey.jwk()

        var header = try JWSHeader(parameters: [
            "alg": SignatureAlgorithm.ES256.rawValue,
            "nonce": nonce,
            "cty": "x-registration-apple+json",
        ])
        header.jwkTyped = pukJwk

        let csr = try mtlsIdentity.createCertificateSigningRequest()
        var der = DER.Serializer()
        try csr.serialize(into: &der)

        let registrationInput = RegistrationRequest(
            name: "iPhone",
            csr: Data(der.serializedBytes)
        )

        let payload = Payload(try JSONEncoder().encode(registrationInput))

        guard let signer = Signer(signingAlgorithm: .ES256, key: joseIdentity.privateSecKey) else {
            throw TrustClientError.genericError("Unable create JWS signer")
        }

        guard let jws = try? JWS(header: header, payload: payload, signer: signer) else {
            throw TrustClientError.genericError("Unable to sign message using JWS")
        }


        var request = URLRequest(url: endpoints.newRegistration)
        request.httpMethod = "POST"
        request.addValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")

        let attestation = try await attestor.generateAndAttestKey(clientData: jws.compactSerializedData)
        var params = URLComponents()
        params.queryItems = [
            URLQueryItem(name: "message", value: jws.compactSerializedString),
            URLQueryItem(name: "attestation_format", value: AttestationFormat.attestation.rawValue),
            URLQueryItem(name: "attestation_data", value: attestation.base64URLEncodedString())
        ]

        request.httpBody = params.query?.data(using: .utf8)

        let (data, response) = try await urlSession.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw TrustClientError.genericError("Where did HTTP go?")
        }
        if httpResponse.statusCode != 201 {
            throw TrustClientError.badServerResponse(httpResponse.statusCode)
        }

        self.registrationURL = try location(httpResponse)
        var registration = try JSONDecoder().decode(RegistrationResponse.self, from: data)
        for challenge in registration.challenges {
            if challenge.type == "oidc" {
                guard let authenticationSessionCallback = authenticationSessionCallback else {
                    throw TrustClientError.genericError("Received OIDC challenge, but no callback is provided")
                }
                guard let authUrl = URL(string: challenge.url) else {
                    throw TrustClientError.genericError("Invalid URL: \(challenge.url)")
                }
                let urlFromServer = try await authenticationSessionCallback(authUrl)
                registration = try await fetchRegistration()
            }
        }
        return registration
    }
    
    public func fetchRegistration() async throws -> RegistrationResponse {

        let nonce = try await nonce()
        
        let pukJwk = try joseIdentity.publicKey.jwk()

        var header = try JWSHeader(parameters: [
            "alg": SignatureAlgorithm.ES256.rawValue,
            "nonce": nonce,
        ])
        header.jwkTyped = pukJwk
        
        let payload = Payload("".data(using: .utf8)!)

        guard let signer = Signer(signingAlgorithm: .ES256, key: joseIdentity.privateSecKey) else {
            throw TrustClientError.genericError("Unable create JWS signer")
        }

        guard let jws = try? JWS(header: header, payload: payload, signer: signer) else {
            throw TrustClientError.genericError("Unable to sign message using JWS")
        }

        let assertion = try await self.attestor.generateAssertion(clientData: jws.compactSerializedData)

        guard let registrationURL = self.registrationURL else {
            throw TrustClientError.genericError("No pending registration")
        }

        var request = URLRequest(url: registrationURL)

        request.httpMethod = "POST"
        request.addValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        var params = URLComponents()
        params.queryItems = [
            URLQueryItem(name: "message", value: jws.compactSerializedString),
            // dont get confused with the parameter name "attestation". the api uses this term for any kind of attestations incl. DCAppAttest assertions
            URLQueryItem(name: "attestation_format", value: AttestationFormat.assertion.rawValue),
            URLQueryItem(name: "attestation_data", value: assertion.base64URLEncodedString())
        ]
        request.httpBody = params.query?.data(using: .utf8)


        let (data, response) = try await urlSession.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw TrustClientError.genericError("Where did HTTP go?")
        }
        if httpResponse.statusCode != 200 {
            throw TrustClientError.badServerResponse(httpResponse.statusCode)
        }


        let registration = try JSONDecoder().decode(RegistrationResponse.self, from: data)

        print(String(data: data, encoding: .utf8))
        print(registration)

        if let certData = registration.clientCertificate  {
            print("Got certificate \(certData.base64EncodedString())")
            let certificate = try Certificate(derEncoded: certData.slice)
            try self.mtlsIdentity.updateCertificate(certificate)
        }

        return registration
    }
    
    func location(_ httpResponse: HTTPURLResponse) throws -> URL {
        guard let urlString = httpResponse.value(forHTTPHeaderField: "Location") else {
            throw TrustClientError.genericError("Location header not provided by the server")
        }
        guard let url = URL(string: urlString) else {
            throw TrustClientError.genericError("Server provided invalid URL: \(urlString)")

        }
        return url
    }
}

