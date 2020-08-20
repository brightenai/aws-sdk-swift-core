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
//
//#if os(Android)
//import CryptoSwift
//import Foundation
//
//public struct SHA256Digest : AWSCrypto.Digest, ByteDigest
//{
//    public static var byteCount = SHA2.Variant.sha256.digestLength
//    public var bytes: [UInt8]
//
//    init( bytes:Array<UInt8>)
//    {
//        self.bytes = bytes
//    }
//}
//
//public struct SHA256 : CCHashFunction
//{
//    public typealias Digest = SHA256Digest
//
//    var digest = CryptoSwift.SHA2(variant: .sha256)
//
//    public static func hash(bufferPointer: UnsafeRawBufferPointer) -> SHA256Digest {
//
//        let data = Data(bytes:bufferPointer.baseAddress!, count:bufferPointer.count)
//        return SHA256(bytes: data).hash2()
//    }
//
//    public static func hash(data: [UInt8]) -> SHA256Digest {
//
//        let d2 = Data(bytes: data, count: data.count)
//        return SHA256(bytes: d2).hash2()
//    }
//
//    func hash2() -> SHA256Digest
//    {
//        //let hash = bytes.sha256()
//        var digest = self.digest
//        let hash = try! digest.finish()
//
//        return SHA256Digest(bytes:[UInt8](hash))
//    }
//
//    public init(bytes: Data)
//    {
//         let _ = try! digest.update(withBytes: [UInt8](bytes))
//
//    }
//
//    public init() {
//
//    }
//
//    public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
//
//        let bytes = Data(bytes:bufferPointer.baseAddress!, count:bufferPointer.count)
//
//        let _ =  try! digest.update(withBytes: [UInt8](bytes))
//    }
//
//    public mutating func finalize() -> SHA256Digest
//    {
//        return hash2()
//    }
//}
//
//#endif
//#if !os(Linux) && !os(Android)

import CommonCrypto

public struct SHA256Digest: ByteDigest {
    public static var byteCount: Int { return Int(CC_SHA256_DIGEST_LENGTH) }
    public var bytes: [UInt8]
}
public struct SHA256: CCHashFunction {
    public typealias Digest = SHA256Digest
    public static var algorithm: CCHmacAlgorithm { return CCHmacAlgorithm(kCCHmacAlgSHA256) }
    var context: CC_SHA256_CTX

    public static func hash(bufferPointer: UnsafeRawBufferPointer) -> Self.Digest {
        var digest: [UInt8] = .init(repeating: 0, count: Digest.byteCount)
        CC_SHA256(bufferPointer.baseAddress, CC_LONG(bufferPointer.count), &digest)
        return .init(bytes: digest)
    }

    public init() {
        self.context = CC_SHA256_CTX()
        CC_SHA256_Init(&self.context)
    }

    public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
        CC_SHA256_Update(&self.context, bufferPointer.baseAddress, CC_LONG(bufferPointer.count))
    }

    public mutating func finalize() -> Self.Digest {
        var digest: [UInt8] = .init(repeating: 0, count: Digest.byteCount)
        CC_SHA256_Final(&digest, &self.context)
        return .init(bytes: digest)
    }
}

public struct SHA384Digest: ByteDigest {
    public static var byteCount: Int { return Int(CC_SHA384_DIGEST_LENGTH) }
    public var bytes: [UInt8]
}

public struct SHA384: CCHashFunction {
    public typealias Digest = SHA384Digest
    public static var algorithm: CCHmacAlgorithm { return CCHmacAlgorithm(kCCHmacAlgSHA384) }
    var context: CC_SHA512_CTX

    public static func hash(bufferPointer: UnsafeRawBufferPointer) -> Self.Digest {
        var digest: [UInt8] = .init(repeating: 0, count: Digest.byteCount)
        CC_SHA384(bufferPointer.baseAddress, CC_LONG(bufferPointer.count), &digest)
        return .init(bytes: digest)
    }

    public init() {
        self.context = CC_SHA512_CTX()
        CC_SHA384_Init(&self.context)
    }

    public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
        CC_SHA384_Update(&self.context, bufferPointer.baseAddress, CC_LONG(bufferPointer.count))
    }

    public mutating func finalize() -> Self.Digest {
        var digest: [UInt8] = .init(repeating: 0, count: Digest.byteCount)
        CC_SHA384_Final(&digest, &self.context)
        return .init(bytes: digest)
    }
}

public struct SHA512Digest: ByteDigest {
    public static var byteCount: Int { return Int(CC_SHA512_DIGEST_LENGTH) }
    public var bytes: [UInt8]
}

public struct SHA512: CCHashFunction {
    public typealias Digest = SHA512Digest
    public static var algorithm: CCHmacAlgorithm { return CCHmacAlgorithm(kCCHmacAlgSHA512) }
    var context: CC_SHA512_CTX

    public static func hash(bufferPointer: UnsafeRawBufferPointer) -> Self.Digest {
        var digest: [UInt8] = .init(repeating: 0, count: Digest.byteCount)
        CC_SHA512(bufferPointer.baseAddress, CC_LONG(bufferPointer.count), &digest)
        return .init(bytes: digest)
    }

    public init() {
        self.context = CC_SHA512_CTX()
        CC_SHA512_Init(&self.context)
    }

    public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
        CC_SHA512_Update(&self.context, bufferPointer.baseAddress, CC_LONG(bufferPointer.count))
    }

    public mutating func finalize() -> Self.Digest {
        var digest: [UInt8] = .init(repeating: 0, count: Digest.byteCount)
        CC_SHA512_Final(&digest, &self.context)
        return .init(bytes: digest)
    }
}

//#endif
