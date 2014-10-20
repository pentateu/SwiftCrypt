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
    
    var image: UIImage?
    var imageData: NSData?
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
        
        image = UIImage(named:"testImage.jpg")
        imageData = UIImageJPEGRepresentation(image, 1)!
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func prettyPrint(data:NSData, encoding:UInt = NSUnicodeStringEncoding) -> NSString{
        let strValue = NSString(data: data, encoding:encoding)
        println(strValue)
        return strValue
    }
    
    func execTestEncryptImage() -> NSData {
        let symmetricKey = SymmetricKey(symmetricTagIdentifier: "symmetric.key").generateSymmetricKey()
        
        var cipher = Cipher(input: imageData!, symmetricKey: symmetricKey)
        
        let encrypted = cipher.encrypt()
        
        let encryptedImage = UIImage(data:encrypted!)
        
        cipher = Cipher(input: encrypted!, symmetricKey: symmetricKey)
        
        let decrypted = cipher.decrypt()!
        
        XCTAssert(decrypted.isEqualToData(imageData!), "encrypted and decrypted images are equal")
        
        return decrypted
    }
    
    func testEncryptImage(){
        let image = UIImage(named:"testImage.jpg")
        
        let imageData = UIImageJPEGRepresentation(image, 1)!
        
        let decrypted = execTestEncryptImage()
        
        let decryptedImage = UIImage(data:decrypted)
    }
    
    func execTestEncryptString(value:String){
        let print = false
        
        let symmetricKey = SymmetricKey(symmetricTagIdentifier: "symmetric.key").generateSymmetricKey()
        
        var cipher = Cipher(input: value, symmetricKey: symmetricKey)
        
        let encrypted = cipher.encrypt()
        
        if print {
            println("Encrypted result")
            prettyPrint(encrypted!)
        }
        
        cipher = Cipher(input: encrypted!, symmetricKey: symmetricKey)
        
        let decrypted = cipher.decrypt()
        
        let decryptedStr = NSString(data: decrypted!, encoding:NSUTF8StringEncoding)
        
        if print {
            println("Decrypted result")
            println(decryptedStr)
        }
        
        let str = value as NSString
        
        XCTAssert(str.isEqualToString(decryptedStr), "encrypted and decrypted values are equal")
    }
    
    func testEncryptWithSmallText(){
        execTestEncryptString("Hellow World!")
    }
    
    func testEncryptWithBigText(){
        
        let bigText = createBigText(100)
        
        execTestEncryptString(bigText)
    }
    
    func createBigText(size:Int) -> String {
        let words = "Neque porro quisquam est qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit..."
        var bigString = words
        
        for index in 1 ... size {
            bigString += words
        }
        
        return bigString
    }
    
    func testWrapAndUnwrapSymmetricKey(){
        let keyPair = KeyPair(privateTagIdentifier: "private.key", pulicTagIdentifier: "public.key")
        keyPair.generateKeyPair();
        
        let symmetricKey = SymmetricKey(symmetricTagIdentifier: "symmetric.key")
        symmetricKey.generateSymmetricKey()
        
        println("symmetric key (plain): ")
        prettyPrint(symmetricKey.getSymmetricKeyBits()!)
        
        let wrappedKey = symmetricKey.wrapSymmetricKey(keyPair.getPublicKeyRef()!)
        
        println("symmetric key (wrappedKey): ")
        prettyPrint(wrappedKey!)
        
        XCTAssert(wrappedKey != nil, "Has symmetricKeyRef")
        XCTAssert(wrappedKey?.length == 128, "Result the right size")
        
        let unwrappedKey = symmetricKey.unwrapSymmetricKey(keyPair.getPrivateKeyRef()!, wrappedSymmetricKey: wrappedKey!)
        
        println("symmetric key (unwrappedKey): ")
        prettyPrint(unwrappedKey!)
        
        var boolCheck:Bool = false
        if let originalKey = symmetricKey.getSymmetricKeyBits() {
            boolCheck = originalKey.isEqualToData(unwrappedKey!)
        }
        XCTAssert(boolCheck, "wrappedKey and unwrappedKey are equal")
    }
    
    func assertSymmetricKey(symmetricKey:SymmetricKey){
        XCTAssert(symmetricKey.symmetricKeyRef != nil, "Has symmetricKeyRef")
        XCTAssert(symmetricKey.symmetricKeyRef?.length == 16, "The symmetricKeyRef has 16 bytes")
        
        var keyBits = symmetricKey.getSymmetricKeyBits()
        XCTAssert(keyBits != nil, "Has symmetricKeyRef")
        XCTAssert(keyBits?.length == 16, "The symmetricKeyRef has 16 bytes")
    }
    
    func testGenerateSymmetricKey() {
        let symmetricKey = SymmetricKey(symmetricTagIdentifier: "symmetric.key")
        symmetricKey.generateSymmetricKey()
        
        assertSymmetricKey(symmetricKey)
        
        let anotherInstance = SymmetricKey(symmetricTagIdentifier: "symmetric.key")
        
        assertSymmetricKey(anotherInstance)
    }
    
    func testDeleteSymmetricKey() {
        let symmetricKey = SymmetricKey(symmetricTagIdentifier: "symmetric.key")
        symmetricKey.deleteSymmetricKey()
        
        let key = symmetricKey.getSymmetricKeyBits()
        
        XCTAssert(key == nil, "Has no key")
    }
    
    func testDeleteKeyPair() {
        let keyPair = KeyPair(privateTagIdentifier: "private.key", pulicTagIdentifier: "public.key");
        keyPair.deleteKeyPair()
        
        let pubKey = keyPair.getPublicKeyRef()
        
        XCTAssert(pubKey == nil, "Has no public key")
        
        let privateKey = keyPair.getPrivateKeyRef()
        
        XCTAssert(privateKey == nil, "Has no private key")
    }
    
    func testCreatePublicKeyQueryParams() {
        let keyPair = KeyPair(privateTagIdentifier: "private.key", pulicTagIdentifier: "public.key")
        
        let dic = keyPair.createPublicKeyQueryParams()
        
        XCTAssert(dic.count == 3, "Has right number of items");
        
        XCTAssert(dic.objectForKey(kSecAttrApplicationTag) as NSData == keyPair.publicTag, "Has correct tag")
    }
    
    func testCreatePrivateKeyQueryParams() {
        let keyPair = KeyPair(privateTagIdentifier: "private.key", pulicTagIdentifier: "public.key")
        
        let dic = keyPair.createPrivateKeyQueryParams()
        
        XCTAssert(dic.count == 3, "Has right number of items");
        
        XCTAssert(dic.objectForKey(kSecAttrApplicationTag) as NSData == keyPair.privateTag, "Has correct tag")
    }
    
    func testGenerateKeyPair() {
        let keyPair = KeyPair(privateTagIdentifier: "private.key", pulicTagIdentifier: "public.key")
            
        keyPair.generateKeyPair();
        
        XCTAssert(keyPair.getPublicKeyRef() != nil, "Has public key");
        XCTAssert(keyPair.getPrivateKeyRef() != nil, "Has private key");
        
        let newInstance = KeyPair(privateTagIdentifier: "private.key", pulicTagIdentifier: "public.key")
        XCTAssert(newInstance.getPublicKeyRef() != nil, "Has public key");
        XCTAssert(newInstance.getPrivateKeyRef() != nil, "Has private key");
        
    }
    
    func testGetPublicKeyBits(){
        let keyPair = KeyPair(privateTagIdentifier: "private.key", pulicTagIdentifier: "public.key")
        keyPair.generateKeyPair();
        
        let keyBits = keyPair.getPublicKeyBits()
        XCTAssert(keyBits?.length > 0, "Has some data");
    }
    
    func testGetPrivateKeyBits(){
        let keyPair = KeyPair(privateTagIdentifier: "private.key", pulicTagIdentifier: "public.key")
        keyPair.generateKeyPair();
        
        let keyBits = keyPair.getPrivateKeyBits()
        XCTAssert(keyBits?.length > 0, "Has some data");
    }
    
    func testGetPrivateKeyRef(){
        let keyPair = KeyPair(privateTagIdentifier: "private.key", pulicTagIdentifier: "public.key")
        keyPair.generateKeyPair();
        
        let keyBits = keyPair.getPrivateKeyRef()
        XCTAssert(keyBits != nil , "Has key ref");
    }
    
    func testGetPublicKeyRef(){
        let keyPair = KeyPair(privateTagIdentifier: "private.key", pulicTagIdentifier: "public.key")
        keyPair.generateKeyPair();
        
        let keyBits = keyPair.getPublicKeyRef()
        XCTAssert(keyBits != nil , "Has key ref");
    }
    
    func testMeasureGenerateKeyPair() {
        self.measureBlock() {
            let keyPair = KeyPair(privateTagIdentifier: "private.key", pulicTagIdentifier: "public.key")
            
            keyPair.generateKeyPair();
            
            XCTAssert(keyPair.getPublicKeyRef() != nil, "Has public key");
            XCTAssert(keyPair.getPrivateKeyRef() != nil, "Has private key");
        }
    }
    
    func testMeasureGenerateSymmetricKey() {
        self.measureBlock() {
            let symmetricKey = SymmetricKey(symmetricTagIdentifier: "symmetric.key")
            symmetricKey.generateSymmetricKey()
            
            self.assertSymmetricKey(symmetricKey)
        }
    }
    
    func testMeasureWrapAndUnwrapSymmetricKey() {
        self.measureBlock() {
            self.testWrapAndUnwrapSymmetricKey()
        }
    }
    
    func testMeasureEncryptWithBigText() {
        self.measureBlock() {
            self.testEncryptWithBigText()
        }
    }
    
    func testMeasureEncryptImage() {
        self.measureBlock() {
            let result = self.execTestEncryptImage()
        }
    }
    
}
