//===----------------------------------------------------------------------===//
//
// This source file is part of the AWSSDKSwift open source project
//
// Copyright (c) 2017-2020 the AWSSDKSwift project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of AWSSDKSwift project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

// Replicating the CryptoKit framework interface for < macOS 10.15

//#if !os(Linux) && !os(Android)
//
import CommonCrypto
//#else
//import CryptoSwift
//import Foundation
//#endif

import protocol Foundation.DataProtocol

/// Hash Authentication Code returned by HMAC
public struct HashAuthenticationCode: ByteArray {
    public var bytes: [UInt8]
}

/// Object generating HMAC for data block given a symmetric key
public struct HMAC<H: CCHashFunction> {
    let key: SymmetricKey
    
    #if !os(Linux) && !os(Android)
    var context: CCHmacContext
    #else
    var context: Data
    #endif
    
    /// return authentication code for data block given a symmetric key
    public static func authenticationCode<D: DataProtocol>(for data: D, using key: SymmetricKey) -> HashAuthenticationCode {
        var hmac = HMAC(key: key)
        hmac.update(data: data)
        return hmac.finalize()
    }

    /// update HMAC calculation with a block of data
    public mutating func update<D: DataProtocol>(data: D) {
        if let digest = data.withContiguousStorageIfAvailable({ bytes in
            return self.update(bufferPointer: .init(bytes))
        }) {
            return digest
        } else {
            var buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: data.count)
            data.copyBytes(to: buffer)
            defer { buffer.deallocate() }
            self.update(bufferPointer: .init(buffer))
        }
    }
//}
//
//extension HMAC {
    /// initialize HMAC with symmetric key
    public init(key: SymmetricKey) {
        self.key = key
        #if !os(Linux) && !os(Android)
        self.context = CCHmacContext()
        #else
        self.context = Data()
        #endif
        self.initialize()
    }

    /// initialize HMAC calculation
    mutating func initialize() {
        #if !os(Linux) && !os(Android)
        CCHmacInit(&self.context, H.algorithm, self.key.bytes, self.key.bytes.count)
        #endif
    }

    /// update HMAC calculation with a buffer
    public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
        #if !os(Linux) && !os(Android)
        CCHmacUpdate(&self.context, bufferPointer.baseAddress, bufferPointer.count)
        #endif
    }

    /// finalize HMAC calculation and return authentication code
    public mutating func finalize() -> HashAuthenticationCode {
        #if !os(Linux) && !os(Android)
        var authenticationCode: [UInt8] = .init(repeating: 0, count: H.Digest.byteCount)
        CCHmacFinal(&self.context, &authenticationCode)
        return .init(bytes: authenticationCode)
        #else
        let hmac = CryptoSwift.HMAC(key:self.key.bytes, variant:CryptoSwift.HMAC.Variant.sha256)
        return try! HashAuthenticationCode(bytes:hmac.authenticate( [UInt8] (self.context)))
        #endif
        
        
    }
}

//#endif
