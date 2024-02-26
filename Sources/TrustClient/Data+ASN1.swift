import Foundation

/// ASN1. extensions to Data object to make code more clean
extension Data {
    /// Converts this data to ArraySlice, required for ASN.1 / DER Encoding
    var slice: ArraySlice<UInt8> {
        return ArraySlice<UInt8>(self)
    }
    
    // Converts the bytes to big endian integer representation as ArraySlice
    // by deletiing the zero bytes a the beginning of the data.
    // It is required to properly encode ECC signatures into ASN.1
    var asn1Integer: ArraySlice<UInt8> {
        return self.drop(while: { $0 == 0 }).slice
    }
}
