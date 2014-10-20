//
//  Cipher.swift
//  SwiftCrypt
//
//  Created by Rafael Almeida on 19/10/14.
//  Copyright (c) 2014 ISWE. All rights reserved.
//

import CommonCrypto
import Foundation
import Security


public class Cipher {

    let chosenCipherBlockSize =	kCCBlockSizeAES128
    
    //Crypto reference.
    private var context = UnsafeMutablePointer<CCCryptorRef>.alloc(1)
    
    public enum Operation
    {
        case Encrypt, Decrypt
        
        func nativeValue() -> CCOperation {
            switch self {
            case Encrypt : return CCOperation(kCCEncrypt)
            case Decrypt : return CCOperation(kCCDecrypt)
            }
        }
    }
    
    var input:NSData
    var symmetricKey:NSData
    
    init(input:NSData, symmetricKey:NSData){
        self.input = input
        self.symmetricKey = symmetricKey
        
    }
    
    func createCipher(operation:Operation, padding:Options) -> Status {
        
        var pkcs7 = padding
        var ivBuffer = UnsafePointer<Void>()
        
        // We don't want to toss padding on if we don't need to
        if (operation == .Encrypt) {
            if (padding.rawValue != UInt(kCCOptionECBMode)) {
                if ((input.length % chosenCipherBlockSize) == 0) {
                    pkcs7 = Options.None
                } else {
                    pkcs7 = Options.PKCS7Padding
                }
            }
        }
        
        // Create and Initialize the crypto reference.
        let rawStatus = CCCryptorCreate(operation.nativeValue(),
            CCAlgorithm(kCCAlgorithmAES128),
            CCOptions(pkcs7.toRaw()),
            symmetricKey.bytes,
            UInt(chosenCipherBlockSize),
            ivBuffer,
            context
        )
        
        if let status = Status.fromRaw(rawStatus) {
            return status
        }
        else {
            println("FATAL_ERROR: CCCryptorCreate returned unexpected status (\(rawStatus)).")
            fatalError("CCCryptorCreate returned unexpected status.")
        }
    }
    
    /**
        Determines the number of bytes that wil be output by this Cryptor if inputBytes of additional
        data is input.
    
        :param: inputByteCount number of bytes that will be input.
        :param: isFinal true if buffer to be input will be the last input buffer, false otherwise.
    */
    func getOutputLength(inputByteCount : UInt, isFinal : Bool = false) -> UInt
    {
        return CCCryptorGetOutputLength(context.memory, inputByteCount, isFinal)
    }
    
    func update() -> (UInt, Status) {
        
        // Calculate byte block alignment for all calls through to and including final.
        let outputLength = getOutputLength(UInt(input.length), isFinal: true)
        let resultBuffer        = NSMutableData(length: Int(outputLength))
        let resultBufferPointer = UnsafeMutablePointer<UInt8>(resultBuffer.mutableBytes)
        
        var dataOutMoved = UInt(0)
        
        // Actually perform the encryption or decryption.
        let rawStatus = CCCryptorUpdate(context.memory,
            input.bytes,
            UInt(input.length),
            resultBufferPointer,
            UInt(outputLength),
            &dataOutMoved
        )
        
        if let status = Status.fromRaw(rawStatus) {
            return (dataOutMoved, status)
        }
        else {
            println("FATAL_ERROR: CCCryptorUpdate returned unexpected status (\(rawStatus)).")
            fatalError("CCCryptorUpdate returned unexpected status.")
        }
    }
    
    /**
        Retrieves all remaining encrypted or decrypted data from this cryptor.
    
        :note: If the underlying algorithm is an block cipher and the padding option has
        not been specified and the cumulative input to the cryptor has not been an integral
        multiple of the block length this will fail with an alignment error.
    
        :note: This method updates the status property
    
        :param: byteArrayOut the output bffer
        :returns: a tuple containing the number of output bytes produced and the status (see Status)
    */
    public func final() -> (UInt, Status, NSData) {
        
        let outputLength        = getOutputLength(UInt(input.length), isFinal: true)
        let resultBuffer        = NSMutableData(length: Int(outputLength))
        let resultBufferPointer = UnsafeMutablePointer<UInt8>(resultBuffer.mutableBytes)
        
        var dataOutMoved = UInt(0)
        
        let status = final(resultBufferPointer, byteCapacityOut: outputLength, byteCountOut: &dataOutMoved)
        
        if status == Status.Success {
            let result = NSData(bytes:resultBuffer.bytes, length:Int(dataOutMoved))
            return (dataOutMoved, status, result)
        }
        else{
            println("FATAL_ERROR: CCCryptorFinal returned unexpected status (\(status.toRaw())).")
            fatalError("CCCryptorUpdate returned unexpected status.")
        }
    }
    
    /**
        Retrieves all remaining encrypted or decrypted data from this cryptor.
    
        :note: If the underlying algorithm is an block cipher and the padding option has
        not been specified and the cumulative input to the cryptor has not been an integral
        multiple of the block length this will fail with an alignment error.
    
        :note: This method updates the status property
    
        :param: bufferOut pointer to output buffer
        :param: outByteCapacity capacity of the output buffer in bytes
        :param: outByteCount on successful completion, the number of bytes written to the output buffer
    */
    public func final(bufferOut: UnsafeMutablePointer<Void>, byteCapacityOut : UInt, inout byteCountOut : UInt) -> Status {
        let rawStatus = CCCryptorFinal(context.memory, bufferOut, byteCapacityOut, &byteCountOut)
        if let status = Status.fromRaw(rawStatus)
        {
            return status
        }
        else
        {
            println("FATAL_ERROR: CCCryptorFinal returned unexpected status (\(rawStatus)).")
            fatalError("CCCryptorUpdate returned unexpected status.")
        }
    }
    
    func encryptAndDecrypt(operation:Operation) -> NSData? {
        var status = createCipher(operation, padding: Options.PKCS7Padding)
        
        if status == Status.Success {
            
            let (dataOutMoved, status) = update()
            
            if status == Status.Success {
                let (byteMovedOut, status, result) = final()
                
                if status == Status.Success {
                    return result
                }
            }
            
        }
        
        return nil
    }
    
    public func encrypt() -> NSData? {
        return encryptAndDecrypt(Operation.Encrypt)
    }
    
    public func decrypt() -> NSData? {
        return encryptAndDecrypt(Operation.Decrypt)
    }
    
    
    /*
    * It turns out to be rather tedious to reprent ORable
    * bitmask style options in Swift. I would love to
    * to say that I was smart enough to figure out the
    * magic incantions below for myself, but it was, in fact,
    * NSHipster
    * From: http://nshipster.com/rawoptionsettype/
    */
    public struct Options : RawOptionSetType, BooleanType {
        private var value: UInt = 0
        typealias RawValue = UInt
        public var rawValue : UInt { return self.value }
        
        public init(_ rawValue: UInt) {
            self.value = rawValue
        }
        
        
        // Needed for 1.1 RawRepresentable
        public init(rawValue: UInt) {
            self.value = rawValue
        }
        
        // Needed for 1.1 NilLiteralConverable
        public init(nilLiteral: ())
        {
            
        }
        
        // Needed for 1.0 _RawOptionSet
        public static func fromMask(raw: UInt) -> Options {
            return self(raw)
        }
        
        public static func fromRaw(raw: UInt) -> Options? {
            return self(raw)
        }
        
        public func toRaw() -> UInt {
            return value
        }
        
        public var boolValue: Bool {
            return value != 0
        }
        
        public static var allZeros: Options {
        return self(0)
        }
        
        public static func convertFromNilLiteral() -> Options {
            return self(0)
        }
        
        public static var None: Options           { return self(0) }
        public static var PKCS7Padding: Options    { return self(UInt(kCCOptionPKCS7Padding)) }
        public static var ECBMode: Options      { return self(UInt(kCCOptionECBMode)) }
    }
    
    
}