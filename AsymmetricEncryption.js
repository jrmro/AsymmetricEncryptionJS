/**
* https://github.com/jrmro/AsymmetricEncryptionJS
* 
* This JavaScript class provides methods for asymmetric encryption and decryption using the Web Crypto API. 
* It encapsulates the necessary logic for generating public-private key pairs and using them to encrypt and decrypt data respectively.
*
* (Note: For server-side PHP asymmetric encryption, see https://github.com/jrmro/AsymmetricEncryption).
*
* Example Usage:
*
* async function example(){
*
*   const originalData = "Hello, this is a secret message.";
*
*   const encryptor = new AsymmetricEncryption();
*   
*   // Generate a new pair of keys
*   const keys = await encryptor.generateKeys();
*   console.log('Public key:', keys.publicKey);
*   console.log('Private key:', keys.privateKey);
*
*   // Encrypt the data with the public key
*   encryptedData = await encryptor.encrypt(originalData, keys.publicKey); 
*   console.log('Encrypted Data:', encryptedData);
*
*   // Decrypt the data with the private key
*   decryptedData = await encryptor.decrypt(encryptedData, keys.privateKey);
*   console.log('Decrypted Data:', decryptedData);
*
* }
*
* example();
*
* @license    MIT License
* @author     Joseph Romero
* @version    1.0.0
* ...
*/

class AsymmetricEncryption {

    async generateKeys() {
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: 'RSA-OAEP',
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: 'SHA-256',
            },
            true,
            ['encrypt', 'decrypt']
        );

        const publicKey = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
        const privateKey = await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey);

        return {
            'publicKey': this.arrayBufferToBase64(publicKey),
            'privateKey': this.arrayBufferToBase64(privateKey),
        };
    }

    async encrypt(data, publicKey) {
        const cryptoKey = await window.crypto.subtle.importKey(
            'spki',
            this.base64ToArrayBuffer(publicKey),
            {
                name: 'RSA-OAEP',
                hash: 'SHA-256',
            },
            true,
            ['encrypt']
        );

        const encrypted = await window.crypto.subtle.encrypt(
            {
                name: 'RSA-OAEP',
            },
            cryptoKey,
            new TextEncoder().encode(data)
        );

        return this.arrayBufferToBase64(encrypted);
    }

    async decrypt(encrypted, privateKey) {
        const cryptoKey = await window.crypto.subtle.importKey(
            'pkcs8',
            this.base64ToArrayBuffer(privateKey),
            {
                name: 'RSA-OAEP',
                hash: 'SHA-256',
            },
            true,
            ['decrypt']
        );

        const decrypted = await window.crypto.subtle.decrypt(
            {
                name: 'RSA-OAEP',
            },
            cryptoKey,
            this.base64ToArrayBuffer(encrypted)
        );

        return new TextDecoder().decode(decrypted);
    }

    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';

        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }

        return btoa(binary);
    }

    base64ToArrayBuffer(base64) {
        const binaryString = window.atob(base64);
        const bytes = new Uint8Array(binaryString.length);

        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }

        return bytes.buffer;
    }
}

