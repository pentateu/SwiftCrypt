//
//  SwiftCryptTests.swift
//  SwiftCryptTests
//
//  Created by Rafael Almeida on 12/10/14.
//  Copyright (c) 2014 ISWE. All rights reserved.
//

import UIKit
import XCTest

class SwiftCryptTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func prettyPrint(data:NSData){
        let strValue = NSString(data: data, encoding:NSUnicodeStringEncoding)
        println(strValue)
    }
    
    func testWrapAndUnwrapSymmetricKey(){
        let keyPairService = KeyPairService(privateTagIdentifier: "private.key", pulicTagIdentifier: "public.key")
        keyPairService.generateKeyPair();
        
        let symmetricKeyService = SymmetricKeyService(symmetricTagIdentifier: "symmetric.key")
        symmetricKeyService.generateSymmetricKey()
        
        println("symmetric key (plain): ")
        prettyPrint(symmetricKeyService.getSymmetricKeyBits()!)
        
        let wrappedKey = symmetricKeyService.wrapSymmetricKey(keyPairService.getPublicKeyRef()!)
        
        println("symmetric key (wrappedKey): ")
        prettyPrint(wrappedKey!)
        
        XCTAssert(wrappedKey != nil, "Has symmetricKeyRef")
        XCTAssert(wrappedKey?.length == 128, "Result the right size")
        
        let unwrappedKey = symmetricKeyService.unwrapSymmetricKey(keyPairService.getPrivateKeyRef()!, wrappedSymmetricKey: wrappedKey!)
        
        println("symmetric key (unwrappedKey): ")
        prettyPrint(unwrappedKey!)
        
        var boolCheck:Bool = false
        if let originalKey = symmetricKeyService.getSymmetricKeyBits() {
            boolCheck = originalKey.isEqualToData(unwrappedKey!)
        }
        XCTAssert(boolCheck, "wrappedKey and unwrappedKey are equal")
    }
    
    func assertSymmetricKey(symmetricKeyService:SymmetricKeyService){
        XCTAssert(symmetricKeyService.symmetricKeyRef != nil, "Has symmetricKeyRef")
        XCTAssert(symmetricKeyService.symmetricKeyRef?.length == 16, "The symmetricKeyRef has 16 bytes")
        
        var keyBits = symmetricKeyService.getSymmetricKeyBits()
        XCTAssert(keyBits != nil, "Has symmetricKeyRef")
        XCTAssert(keyBits?.length == 16, "The symmetricKeyRef has 16 bytes")
    }
    
    func testGenerateSymmetricKey() {
        let symmetricKeyService = SymmetricKeyService(symmetricTagIdentifier: "symmetric.key")
        symmetricKeyService.generateSymmetricKey()
        
        assertSymmetricKey(symmetricKeyService)
        
        let anotherInstance = SymmetricKeyService(symmetricTagIdentifier: "symmetric.key")
        
        assertSymmetricKey(anotherInstance)
    }
    
    func testDeleteSymmetricKey() {
        let symmetricKeyService = SymmetricKeyService(symmetricTagIdentifier: "symmetric.key")
        symmetricKeyService.deleteSymmetricKey()
        
        let key = symmetricKeyService.getSymmetricKeyBits()
        
        XCTAssert(key == nil, "Has no key")
    }
    
    func testDeleteKeyPair() {
        let keyPairService = KeyPairService(privateTagIdentifier: "private.key", pulicTagIdentifier: "public.key");
        keyPairService.deleteKeyPair()
        
        let pubKey = keyPairService.getPublicKeyRef()
        
        XCTAssert(pubKey == nil, "Has no public key")
        
        let privateKey = keyPairService.getPrivateKeyRef()
        
        XCTAssert(privateKey == nil, "Has no private key")
    }
    
    func testCreatePublicKeyQueryParams() {
        let keyPairService = KeyPairService(privateTagIdentifier: "private.key", pulicTagIdentifier: "public.key")
        
        let dic = keyPairService.createPublicKeyQueryParams()
        
        XCTAssert(dic.count == 3, "Has right number of items");
        
        XCTAssert(dic.objectForKey(kSecAttrApplicationTag) as NSData == keyPairService.publicTag, "Has correct tag")
    }
    
    func testCreatePrivateKeyQueryParams() {
        let keyPairService = KeyPairService(privateTagIdentifier: "private.key", pulicTagIdentifier: "public.key")
        
        let dic = keyPairService.createPrivateKeyQueryParams()
        
        XCTAssert(dic.count == 3, "Has right number of items");
        
        XCTAssert(dic.objectForKey(kSecAttrApplicationTag) as NSData == keyPairService.privateTag, "Has correct tag")
    }
    
    func testGenerateKeyPair() {
        let keyPairService = KeyPairService(privateTagIdentifier: "private.key", pulicTagIdentifier: "public.key")
            
        keyPairService.generateKeyPair();
        
        XCTAssert(keyPairService.getPublicKeyRef() != nil, "Has public key");
        XCTAssert(keyPairService.getPrivateKeyRef() != nil, "Has private key");
        
        let newInstance = KeyPairService(privateTagIdentifier: "private.key", pulicTagIdentifier: "public.key")
        XCTAssert(newInstance.getPublicKeyRef() != nil, "Has public key");
        XCTAssert(newInstance.getPrivateKeyRef() != nil, "Has private key");
        
    }
    
    func testGetPublicKeyBits(){
        let keyPairService = KeyPairService(privateTagIdentifier: "private.key", pulicTagIdentifier: "public.key")
        keyPairService.generateKeyPair();
        
        let keyBits = keyPairService.getPublicKeyBits()
        XCTAssert(keyBits?.length > 0, "Has some data");
    }
    
    func testGetPrivateKeyBits(){
        let keyPairService = KeyPairService(privateTagIdentifier: "private.key", pulicTagIdentifier: "public.key")
        keyPairService.generateKeyPair();
        
        let keyBits = keyPairService.getPrivateKeyBits()
        XCTAssert(keyBits?.length > 0, "Has some data");
    }
    
    func testGetPrivateKeyRef(){
        let keyPairService = KeyPairService(privateTagIdentifier: "private.key", pulicTagIdentifier: "public.key")
        keyPairService.generateKeyPair();
        
        let keyBits = keyPairService.getPrivateKeyRef()
        XCTAssert(keyBits != nil , "Has key ref");
    }
    
    func testGetPublicKeyRef(){
        let keyPairService = KeyPairService(privateTagIdentifier: "private.key", pulicTagIdentifier: "public.key")
        keyPairService.generateKeyPair();
        
        let keyBits = keyPairService.getPublicKeyRef()
        XCTAssert(keyBits != nil , "Has key ref");
    }
    
    func testMeasureGenerateKeyPair() {
        self.measureBlock() {
            let keyPairService = KeyPairService(privateTagIdentifier: "private.key", pulicTagIdentifier: "public.key")
            
            keyPairService.generateKeyPair();
            
            XCTAssert(keyPairService.getPublicKeyRef() != nil, "Has public key");
            XCTAssert(keyPairService.getPrivateKeyRef() != nil, "Has private key");
        }
    }
    
    func testMeasureGenerateSymmetricKey() {
        self.measureBlock() {
            let symmetricKeyService = SymmetricKeyService(symmetricTagIdentifier: "symmetric.key")
            symmetricKeyService.generateSymmetricKey()
            
            self.assertSymmetricKey(symmetricKeyService)
        }
    }
    
    func testMeasureWrapAndUnwrapSymmetricKey() {
        self.measureBlock() {
            self.testWrapAndUnwrapSymmetricKey()
        }
    }
    
}
