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

#if !os(Linux) && !os(Android)

import CommonCrypto

public extension Insecure {
    struct MD5Digest: ByteDigest {
        public static var byteCount: Int { return Int(CC_MD5_DIGEST_LENGTH) }
        public var bytes: [UInt8]
    }

    struct MD5: CCHashFunction {
        public typealias Digest = MD5Digest
        public static var algorithm: CCHmacAlgorithm { return CCHmacAlgorithm(kCCHmacAlgMD5) }
        var context: CC_MD5_CTX

        public static func hash(bufferPointer: UnsafeRawBufferPointer) -> Self.Digest {
            var digest: [UInt8] = .init(repeating: 0, count: Digest.byteCount)
            CC_MD5(bufferPointer.baseAddress, CC_LONG(bufferPointer.count), &digest)
            return .init(bytes: digest)
        }

        public init() {
            self.context = CC_MD5_CTX()
            CC_MD5_Init(&self.context)
        }

        public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
            CC_MD5_Update(&self.context, bufferPointer.baseAddress, CC_LONG(bufferPointer.count))
        }

        public mutating func finalize() -> Self.Digest {
            var digest: [UInt8] = .init(repeating: 0, count: Digest.byteCount)
            CC_MD5_Final(&digest, &self.context)
            return .init(bytes: digest)
        }
    }
}
#else
import CryptoSwift
import Foundation
//
//do {
//    var digest = MD5()
//    let partial1 = try digest.update(withBytes: [0x31, 0x32])
//    let partial2 = try digest.update(withBytes: [0x33])
//    let result = try digest.finish()
//} catch { }

public extension Insecure {
    struct MD5Digest: ByteDigest {
        public static var byteCount: Int { return Int(16) } //CryptoSwift.MD5.digestLength) }
        public var bytes: [UInt8]
    }

    struct MD5: CCHashFunction {
        public typealias Digest = MD5Digest
//        public static var algorithm: CCHmacAlgorithm { return CCHmacAlgorithm(kCCHmacAlgMD5) }
//        var context: CC_MD5_CTX
        var digest = CryptoSwift.MD5()
        
        public static func hash(bufferPointer: UnsafeRawBufferPointer) -> Self.Digest {
            
            let data = Data(bytes:bufferPointer.baseAddress!, count:bufferPointer.count)

            var md5 = MD5()
            try! md5.digest.update(withBytes:[UInt8](data))
            
            let result = try! md5.digest.finish()
            return MD5Digest(bytes: result)
//            var digest: [UInt8] = .init(repeating: 0, count: Digest.byteCount)
//            CC_MD5(bufferPointer.baseAddress, CC_LONG(bufferPointer.count), &digest)
//            return .init(bytes: digest)
        }

        public init() {
//            self.context = CC_MD5_CTX()
//            CC_MD5_Init(&self.context)
        }

        public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
            let data = Data(bytes:bufferPointer.baseAddress!, count:bufferPointer.count)

            try! self.digest.update(withBytes: [UInt8](data))//bufferPointer)

           // CC_MD5_Update(&self.context, bufferPointer.baseAddress, CC_LONG(bufferPointer.count))
        }

        public mutating func finalize() -> Self.Digest {
            
            let result = try! digest.finish()
            return MD5Digest(bytes: result)

//            var digest: [UInt8] = .init(repeating: 0, count: Digest.byteCount)
//            CC_MD5_Final(&digest, &self.context)
//            return .init(bytes: digest)
        }
    }
}
#endif
