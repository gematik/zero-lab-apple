import Foundation
import DeviceCheck
import CryptoKit

class Attestor {
    var context: String
    var keyId: String? {
        set {
            UserDefaults.standard.setValue(newValue, forKey: "tcl:app-attest:\(context)")
        }
        get {
            UserDefaults.standard.string(forKey: "tcl:app-attest:\(context)")
        }
    }
    var attestService: DCAppAttestService

    init(_ context: String) {
        self.context = context
        self.attestService = DCAppAttestService.shared
    }

    func isInitialized() -> Bool {
        keyId != nil
    }

    func generateAndAttestKey(clientData: Data) async throws -> Data {
        if !attestService.isSupported {
            throw TrustClientError.invalidRuntimeEnvironent("Attestation is not supported")
        }

        self.keyId = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<String, Error>) in
            attestService.generateKey { newKeyId, error in
                guard error == nil else {
                    continuation.resume(throwing: TrustClientError.attestationFailed(cause: error))
                    return
                }
                if let newKeyId = newKeyId {
                    continuation.resume(returning: newKeyId)
                } else {
                    continuation.resume(throwing: TrustClientError.attestationFailed(cause: nil))
                }
            }
        }

        let clientDataHash = Data(SHA256.hash(data: clientData))

        if let keyId = self.keyId {
            return try await attestService.attestKey(keyId, clientDataHash: clientDataHash)
        } else {
            throw TrustClientError.attestationFailed(cause: nil)
        }

    }


    func generateAssertion(clientData: Data) async throws -> Data{
        if let keyId = self.keyId {
            let clientDataHash = Data(SHA256.hash(data: clientData))
            return try await attestService.generateAssertion(keyId, clientDataHash: clientDataHash)
        } else {
            throw TrustClientError.attestationFailed(cause: nil)
        }
    }

}
