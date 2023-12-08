# Asymmetric Encryption JS Class

This JavaScript class provides methods for asymmetric encryption and decryption using the Web Crypto API. It encapsulates the necessary logic for generating public-private key pairs and using them to encrypt and decrypt data respectively.


(Note: For server-side PHP asymmetric encryption, see [https://github.com/jrmro/AsymmetricEncryption](https://github.com/jrmro/AsymmetricEncryption)).

## Sample Usage

```
async function example(){

    const originalData = "Hello, this is a secret message.";

    const encryptor = new AsymmetricEncryption();

    // Generate a new pair of keys
    const keys = await encryptor.generateKeys();
    console.log('Public key:', keys.publicKey);
    console.log('Private key:', keys.privateKey);

    // Encrypt the data with the public key
    encryptedData = await encryptor.encrypt(originalData, keys.publicKey); 
    console.log('Encrypted Data:', encryptedData);

    // Decrypt the data with the private key
    decryptedData = await encryptor.decrypt(encryptedData, keys.privateKey);
    console.log('Decrypted Data:', decryptedData);

}

example();

```

## Note
* The `generateKey()`, `encrypt()`, and `decrypt()` methods are all asynchronous and return promises. Please handle accordingly.
* The class uses the Web Crypto API [https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
* Handle and store your private key securely. Do not hardcode it in your project.

## Author
Joseph Romero

## License
This code is released under the MIT License.
