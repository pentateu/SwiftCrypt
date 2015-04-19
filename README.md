SwiftCrypt
==========

Crypto services written in Swift

## How do you Encrypt and Decrypt an Text ?
``` Swift
func testEncryptString(value:String){
        //Create a symmetricKey with the tag: "my.symmetric.key.tag"
        let symmetricKey = SymmetricKey(symmetricTagIdentifier: "my.symmetric.key.tag")
        
        //generates a new Symmetric Key
        symmetricKey.generateSymmetricKey()
        
        //creates a cipher for the text
        var cipher = Cipher(input: value, symmetricKey: symmetricKey)
        
        //encrypts the text
        let encrypted = cipher.encrypt()
        
        println("Encrypted result")
        prettyPrint(encrypted!)
        
        //creates a cipher for the encrypted text
        cipher = Cipher(input: encrypted!, symmetricKey: symmetricKey)
        
        //decrypts the text
        let decrypted = cipher.decrypt()
        
        //turn it into a string
        let decryptedStr = NSString(data: decrypted!, encoding:NSUTF8StringEncoding)
        
        println("Decrypted result")
        println(decryptedStr)
        
        let str = value as NSString
        //make sure they match
        XCTAssert(str == decryptedStr, "encrypted and decrypted values are equal")
    }
```

## How do you Encrypt and Decrypt an Image ?
``` Swift
  func testEncryptImage() -> NSData {
        //load an image file
        let image = UIImage(named:"testImage.jpg")
        let imageData = UIImageJPEGRepresentation(image, 1)!
  
        //Create a symmetricKey with the tag: "my.symmetric.key.tag"
        let symmetricKey = SymmetricKey(symmetricTagIdentifier: "my.symmetric.key.tag")
        
        //generate the SymmetricKey .. since it is a new one
        symmetricKey.generateSymmetricKey()
        
        //creates a cipher for the image
        var cipher = Cipher(input: imageData, symmetricKey: symmetricKey)
        
        //encrypt the contents of the image
        let encrypted = cipher.encrypt()
        
        //an encryptedImage Image is useless ;-)
        let encryptedImage = UIImage(data:encrypted!)
        
        //creates a cipher for the encrypted image
        cipher = Cipher(input: encrypted, symmetricKey: symmetricKey)
        
        //decrypt the image
        let decrypted = cipher.decrypt()!
        
        //make sure the contento of the original is the same as the decrypted !
        XCTAssert(decrypted.isEqualToData(imageData!), "encrypted and decrypted images are equal")
        
        return decrypted
    }
```
