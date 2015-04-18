//
//  KeyPairService.swift
//  SwiftCrypt
//
//  Created by Rafael Almeida on 12/10/14.
//  Copyright (c) 2014 ISWE. All rights reserved.
//

import Foundation

class KeyPair: SecKeyBase {

    let kSecPrivateKeyAttrsValue = kSecPrivateKeyAttrs.takeUnretainedValue() as! NSCopying
    let kSecPublicKeyAttrsValue = kSecPublicKeyAttrs.takeUnretainedValue() as! NSCopying
    
    //The example uses 512 . I was trying 1024
    let keySize:CFNumberRef = 1024
    
    var privateTag: NSData
    var publicTag: NSData
    
    var publicKeyRef: SecKeyRef?
    var privateKeyRef: SecKeyRef?
    
    init(privateTagIdentifier:String, pulicTagIdentifier:String){
        privateTag = (privateTagIdentifier as NSString).dataUsingEncoding(NSUTF8StringEncoding)!
        publicTag = (pulicTagIdentifier as NSString).dataUsingEncoding(NSUTF8StringEncoding)!
        
        super.init(keyType: kSecAttrKeyTypeRSA)
    }
    
    func createPublicKeyQueryParams() -> NSMutableDictionary {
        return createBaiscKeyQueryParams(publicTag)
    }
    
    func createPrivateKeyQueryParams() -> NSMutableDictionary {
        return createBaiscKeyQueryParams(privateTag)
    }
    
    func deleteKeyPair(){
        deleteItem(createPrivateKeyQueryParams())
        deleteItem(createPublicKeyQueryParams())
    }
    
    func generateKeyPair() {
        
        deleteKeyPair()
        
        // Set top level dictionary for the keypair.
        let keyPairAttr: NSMutableDictionary = NSMutableDictionary()
        keyPairAttr.setObject(keyType, forKey:kSecAttrKeyType as String)
        
        keyPairAttr.setObject(keySize, forKey:kSecAttrKeySizeInBits as String)
        
        // Set the private key dictionary.
        let privateKeyAttr: NSMutableDictionary = NSMutableDictionary()
        privateKeyAttr.setObject(NYES, forKey: kSecAttrIsPermanent as String)
        privateKeyAttr.setObject(privateTag, forKey: kSecAttrApplicationTag as String)
        
        // Set the public key dictionary.
        let publicKeyAttr: NSMutableDictionary = NSMutableDictionary()
        publicKeyAttr.setObject(NYES, forKey: kSecAttrIsPermanent as String)
        publicKeyAttr.setObject(publicTag, forKey: kSecAttrApplicationTag as String)
        
        // Set attributes to top level dictionary.
        keyPairAttr.setObject(privateKeyAttr, forKey:kSecPrivateKeyAttrsValue)
        keyPairAttr.setObject(publicKeyAttr, forKey:kSecPublicKeyAttrsValue)
        
        var uPublicKeyRef: Unmanaged<SecKeyRef>?
        var uPrivateKeyRef: Unmanaged<SecKeyRef>?
        
        // SecKeyGeneratePair returns the SecKeyRefs just for educational purposes.
        let sanityCheck = SecKeyGeneratePair(keyPairAttr as CFDictionaryRef, &uPublicKeyRef, &uPrivateKeyRef)
        
        if(sanityCheck == noErr && uPublicKeyRef?.takeUnretainedValue() != nil && uPrivateKeyRef?.takeUnretainedValue() != nil){
            println("Keys generated with success!");
            
            publicKeyRef = uPublicKeyRef?.takeRetainedValue()
            privateKeyRef = uPrivateKeyRef?.takeRetainedValue()
        }
        else{
            println("Something really bad went wrong with generating the key pair.")
        }
        
    }
    
    func getPublicKeyRef() -> SecKeyRef?{
        if publicKeyRef == nil {
            let query = createBaiscKeyQueryParams(publicTag)
            query.setObject(NYES, forKey: kSecReturnRef as String)
            
            var queryResult:AnyObject? = queryObject(query)
            
            if let queryResultObj:AnyObject = queryResult {
                publicKeyRef = queryResultObj as! SecKeyRef
            }
        }
        return publicKeyRef
    }
    
    func getPrivateKeyRef() -> SecKeyRef?{
        if privateKeyRef == nil {
            let query = createBaiscKeyQueryParams(privateTag)
            query.setObject(NYES, forKey: kSecReturnRef as String)
            
            var queryResult:AnyObject? = queryObject(query)
            
            if let queryResultObj:AnyObject = queryResult {
                privateKeyRef = queryResultObj as! SecKeyRef
            }
        }
        return privateKeyRef
    }
    
    func getPublicKeyBits() -> NSData? {
        return getKeyBits(publicTag)
    }
    
    func getPrivateKeyBits() -> NSData? {
        return getKeyBits(privateTag)
    }

}