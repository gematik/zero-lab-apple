import XCTest
@testable import TrustClient
import CryptoKit
import JOSESwift
import DeviceCheck

final class TrustClientTests: XCTestCase {
    let testJwkData = """
{"crv":"P-256","d":"RAsLqZOL-WN8-YWrEbxM_cqG_Tmr-6LsfOG7DJMZYac","kty":"EC","x":"X6G6MXf5A0Pn5MkCffwzg5V64UaPUE0t2RahDjGMBrA","y":"uuoTkMVDsT_yF-PCDtDRv1vBniA13KNtMd4pqqM_onc"}
""".data(using: .utf8)!
    func testJWK() throws {
        let pukJwk = try ECPublicKey(data: testJwkData)
        let thumbprint = try pukJwk.thumbprint(algorithm: .SHA256)
        XCTAssertEqual(thumbprint, "mjPJqJTKJJkSePnZI5jnPkjn206kUmGpWp5tC14twEg")
    }
    
    func testJWS() throws {
        let key = P256.Signing.PrivateKey()
        
        let attributes: [String:Any] = [
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeyType as String: kSecAttrKeyTypeEC,
        ]

        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateWithData(key.x963Representation as CFData, attributes as CFDictionary, &error) else {
           throw error!.takeRetainedValue()
        }
        
        let k = try ECPrivateKey(privateKey: secKey)
        print(k.jsonString()!)

        
        let prkJwk = try key.jwk()
        let pukJwk = try key.publicKey.jwk()
        
        //let prkJwk = try ECPrivateKey(data: testJwkData)
        //let pukJwk = try ECPublicKey(data: testJwkData)

        var header = JWSHeader(algorithm: .ES256)
        header.jwkTyped = pukJwk
        
        let message = "Summer ⛱, Sun ☀️, Cactus 🌵".data(using: .utf8)!

        let payload = Payload(message)
        
        let prkSekKey = try prkJwk.secKey()
                
        guard let signer = Signer(signingAlgorithm: .ES256, key: prkSekKey) else {
            XCTFail("Unable to create signer")
            return
        }
        
        guard let jws = try? JWS(header: header, payload: payload, signer: signer) else {
            XCTFail("Unable to create JWS")
            return
        }

    
        print(jws.compactSerializedString)
        print(prkJwk.jsonString()!)
        print(pukJwk.jsonString()!)

    }
    
    func testAttestationHeader() throws {
        let testAttestation = "test attestation".data(using: .utf8)!

        let prkJwk = try ECPrivateKey(data: testJwkData)
        let pukJwk = try ECPublicKey(data: testJwkData)

        var header = try JWSHeader(parameters: [
            "alg": SignatureAlgorithm.ES256.rawValue,
            "urn:gematik:attestation": ["fmt": AttestationFormat.attestation.rawValue, "data": testAttestation.base64EncodedString()]
        ])
        header.jwkTyped = pukJwk
        
        let message = "Summer ⛱, Sun ☀️, Cactus 🌵".data(using: .utf8)!

        let payload = Payload(message)
        
        let prkSekKey = try prkJwk.secKey()
                
        guard let signer = Signer(signingAlgorithm: .ES256, key: prkSekKey) else {
            XCTFail("Unable to create signer")
            return
        }
        
        guard let jws = try? JWS(header: header, payload: payload, signer: signer) else {
            XCTFail("Unable to create JWS")
            return
        }

        print(jws.compactSerializedString)
        print(prkJwk.jsonString()!)        
    }
}
