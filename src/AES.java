// References:
// GCM Cipher - https://www.thexcoders.net/aes-encrypt-decrypt-ciphers/
// Key store - https://www.youtube.com/watch?v=qWKwuHgWwtk
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.*;

public class AES
{
    private final String KEY_SPEC_TYPE  = "AES";
    private final String CIPHER_TYPE = "AES/GCM/NoPadding";


    private SecretKey key;

    public String getKeyString()
    {
        return encode(key.getEncoded());
    }

    public void generateKeyAndStore(int keySize) {
        try
        {
            // Generate random key
            KeyGenerator generator = KeyGenerator.getInstance(KEY_SPEC_TYPE);
            generator.init(keySize);
            key = generator.generateKey();

        }
        catch (NoSuchAlgorithmException e)
        {
            System.out.println("Key generate error");
        }
    }

    public void storeToKeyStore(String fileName, String password)
    {
        try
        {
            // Store key for future use
            KeyStore keyStore = KeyStore.getInstance("JCEKS");
            keyStore.load(null, null);
            keyStore.setKeyEntry("keyAlias", key, password.toCharArray(), null);
            OutputStream out = new FileOutputStream(fileName);
            keyStore.store(out, password.toCharArray());
        }
        catch (NoSuchAlgorithmException | KeyStoreException | CertificateException | IOException e)
        {
            System.out.println("Key store error");
        }
    }

    public void loadFromKeyStore(String fileName, String password)
    {
        try
        {
            KeyStore keyStore = KeyStore.getInstance("JCEKS");
            InputStream in = new FileInputStream(fileName);
            keyStore.load(in, password.toCharArray());
            key = (SecretKey) keyStore.getKey("keyAlias", password.toCharArray());
        }
        catch (NoSuchAlgorithmException | KeyStoreException | CertificateException | IOException | UnrecoverableKeyException e)
        {
            System.out.println("Key store error");
        }
    }

    private String encode(byte[] data){
        return Base64.getEncoder().encodeToString(data);
    }

    private byte[] decode(String data){
        try
        {
            return Base64.getDecoder().decode(data);
        }
        catch (IllegalArgumentException e) {
            return new byte[] {};
        }
    }

    /**
     * Encrypt text using AES
     * @param keySize size of random key, must be 128, 192, or 256
     * @param plainText text to be encrypted
     * @return cipher text which consists of IV and encrypted text in order, seperated with a "|"
     */
    public String encrypt(int keySize, String plainText)
    {
        try
        {
            // Generate random key to encrypt file with and store key
            generateKeyAndStore(keySize);

            // Get bytes of plain text that will be encrypted
            byte[] plainTextBytes = plainText.getBytes();

            // Initialize cipher
            Cipher encryptionCipher = Cipher.getInstance(CIPHER_TYPE);
            encryptionCipher.init(Cipher.ENCRYPT_MODE, key);

            // Get encrypted bytes and IV (nonce)
            byte[] encryptedBytes = encryptionCipher.doFinal(plainTextBytes);
            byte[] iv = encryptionCipher.getIV();

            // Return IV appended with encrypted text, seperated with a "|"
            return encode(iv) + "|" + encode(encryptedBytes);
        }
        catch (NoSuchPaddingException | NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | InvalidParameterException e)
        {
            return "Encryption failed - key size must be 128, 192, or 256";
        }
    }

    /**
     * @param cipherText text to be decrypted, contains of IV and encrypted text in order, seperated with a "|"
     * @return plaintext, which is decrypted cipher text
     */
    public String decrypt(String cipherText)
    {
        try
        {
            // Separate IV and text that needs to be decrypted
            String[] cipherTextArr = cipherText.split("\\|");
            byte[] iv = decode(cipherTextArr[0]);
            byte[] cipherTextBytes = decode(cipherTextArr[1]);

            // Specifies the set of parameters required by a Cipher using the Galois/Counter Mode (GCM) mode
            int t_len = 128;
            GCMParameterSpec spec = new GCMParameterSpec(t_len, iv);

            // Initialize cipher
            Cipher decryptionCipher = Cipher.getInstance(CIPHER_TYPE);
            decryptionCipher.init(Cipher.DECRYPT_MODE, key, spec);

            // Get decrypted bytes
            byte[] decryptedBytes = decryptionCipher.doFinal(cipherTextBytes);

            // Return decrypted text
            return new String(decryptedBytes);
        }
        catch ( NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | BadPaddingException | InvalidKeyException | IllegalArgumentException e)
        {
            return "Decryption failed";
        }
    }
}
