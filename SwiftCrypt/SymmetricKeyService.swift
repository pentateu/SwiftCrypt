//
//  SymmetricKeyService.swift
//  SwiftCrypt
//
//  Created by Rafael Almeida on 16/10/14.
//  Copyright (c) 2014 ISWE. All rights reserved.
//

import Foundation

class SymmetricKeyService: SecKeyService {
    
    //the kSecAttrKeyTypeAES constant is not available in iOS :-(
    let KEY_TYPE_AES: NSNumber  =  2147483649
    
    let keySizeAES128 = 16
    let keySizeAES192 = 24
    let keySizeAES256 = 32
    
    let typeOfWrapPadding = kSecPaddingPKCS1
    
    var symmetricTag:NSData
    var cipherKeySize: Int
    var effectiveKeySize: Int
    
    var symmetricKeyRef: NSData?

    init(symmetricTagIdentifier:String){
        symmetricTag = (symmetricTagIdentifier as NSString).dataUsingEncoding(NSUTF8StringEncoding)!
        
        cipherKeySize = keySizeAES128
        effectiveKeySize = cipherKeySize << 3 //128
        
        super.init(keyType: KEY_TYPE_AES)
        
        symmetricKeyRef = getSymmetricKeyBits()
    }
    
    func deleteSymmetricKey(){
        if(deleteItem(createBaiscKeyQueryParams(symmetricTag))){
            symmetricKeyRef = nil
        }
    }
    
    func generateSymmetricKey(){
        
        deleteSymmetricKey()
        
        let symmetricKeyAttr = createBaiscKeyQueryParams(symmetricTag)
        
        symmetricKeyAttr.setObject(effectiveKeySize, forKey: kSecAttrKeySizeInBits)
        symmetricKeyAttr.setObject(effectiveKeySize, forKey: kSecAttrEffectiveKeySize)
        
        symmetricKeyAttr.setObject(kCFBooleanTrue, forKey: kSecAttrCanEncrypt)
        symmetricKeyAttr.setObject(kCFBooleanTrue, forKey: kSecAttrCanDecrypt)
        
        symmetricKeyAttr.setObject(kCFBooleanFalse, forKey: kSecAttrCanDerive)
        symmetricKeyAttr.setObject(kCFBooleanFalse, forKey: kSecAttrCanSign)
        symmetricKeyAttr.setObject(kCFBooleanFalse, forKey: kSecAttrCanVerify)
        symmetricKeyAttr.setObject(kCFBooleanFalse, forKey: kSecAttrCanWrap)
        symmetricKeyAttr.setObject(kCFBooleanFalse, forKey: kSecAttrCanUnwrap)
        
        let symmetricKey = NSMutableData(length: Int(cipherKeySize))
        var sanityCheck = SecRandomCopyBytes(kSecRandomDefault, UInt(cipherKeySize), UnsafeMutablePointer<UInt8>(symmetricKey.mutableBytes))
        
        if( sanityCheck == noErr){
            symmetricKeyRef = NSData(data: symmetricKey)
            
            prettyPrint(symmetricKeyRef!)
            
            // Add the wrapped key data to the container dictionary.
            symmetricKeyAttr.setObject(symmetricKey, forKey:kSecValueData)
            
            // Add the symmetric key to the keychain.
            sanityCheck = SecItemAdd(symmetricKeyAttr as CFDictionaryRef, nil)
            if( sanityCheck != noErr){
                println("Could not add the symmetric key to the keychain")
            }
        }
        else{
            println("Could not generate the symmetric key")
        }
        
    }
    
    func getSymmetricKeyBits() -> NSData? {
        if(symmetricKeyRef == nil){
            symmetricKeyRef = getKeyBits(symmetricTag)
        }
        return symmetricKeyRef
    }
    
    func prettyPrint(data:NSData){
        
        let strValue = NSString(data: data, encoding:NSUnicodeStringEncoding)
        
        println(strValue)
    }
    
    func wrapSymmetricKey(publicKey: SecKeyRef) -> NSData? {
        var result:NSData?
        
        if let symmetricKey = symmetricKeyRef {
            // Calculate the buffer sizes.
            let contentPointer      = UnsafePointer<UInt8>(symmetricKey.bytes)
            let contentSize         = symmetricKey.length
            
            let cipherBufferSize    = SecKeyGetBlockSize(publicKey)
            let cipherBuffer        = NSMutableData(length: Int(cipherBufferSize))
            let cipherBufferPointer = UnsafeMutablePointer<UInt8>(cipherBuffer.mutableBytes)
            var cipherBufferSizeResult = UInt(cipherBufferSize)
            
            // Encrypt using the public key.
            let sanityCheck = SecKeyEncrypt(publicKey, UInt32(typeOfWrapPadding), contentPointer, UInt(contentSize), cipherBufferPointer, &cipherBufferSizeResult)
            
            if(sanityCheck == noErr){
                println("symmetric key encrypted succesfully!")
                result = NSData(bytes:cipherBuffer.bytes, length:Int(cipherBufferSizeResult))
            }
            else{
                println("could not encrypted symmetric key :-(")
            }
        }
        return result
    }
    
    func unwrapSymmetricKey(privateKey: SecKeyRef, wrappedSymmetricKey:NSData) -> NSData? {
        var result:NSData?
        
        // Calculate the buffer sizes
        let cipherBufferSize    = SecKeyGetBlockSize(privateKey)
        let keyBufferSize       = wrappedSymmetricKey.length
        let keyBuffer           = NSMutableData(length: Int(keyBufferSize))
        let keyBufferPointer    = UnsafeMutablePointer<UInt8>(keyBuffer.mutableBytes)
        let ciphertPointer      = UnsafePointer<UInt8>(wrappedSymmetricKey.bytes)
        var keyBufferSizeResult = UInt(keyBufferSize)
        
        // Decrypt using the private key.
        let sanityCheck = SecKeyDecrypt(privateKey, UInt32(typeOfWrapPadding),
            ciphertPointer,
            UInt(cipherBufferSize),
            keyBufferPointer,
            &keyBufferSizeResult
        )
        
        if(sanityCheck == noErr){
            println("symmetric key decrypted succesfully!")
            result = NSData(bytes:keyBuffer.bytes, length:Int(keyBufferSizeResult))
        }
        else{
            println("could not decrypt symmetric key :-(")
        }
        
        return result
    }
    
}