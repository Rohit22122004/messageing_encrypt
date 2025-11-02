package com.example.milatary.security;



import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * Utility class for client-side message decryption.
 * This demonstrates how to decrypt messages received from the API.
 */
public class MessageDecryptor {

    /**
     * Complete decryption flow for a received message
     *
     * @param encryptedPrivateKeyFromDB The encrypted private key blob from database (Base64 encoded)
     * @param userPassword The user's password
     * @param encryptedAesKeyBase64 The encrypted AES key from message (Base64)
     * @param cipherTextBase64 The encrypted message (Base64)
     * @return Decrypted message plaintext
     * @throws Exception if decryption fails
     */
    public static String decryptMessage(
            String encryptedPrivateKeyFromDB,
            String userPassword,
            String encryptedAesKeyBase64,
            String cipherTextBase64) throws Exception {

        // Decode the encrypted private key from Base64
        byte[] encryptedPrivateKeyBytes = Base64.getDecoder().decode(encryptedPrivateKeyFromDB);

        return decryptMessage(encryptedPrivateKeyBytes, userPassword, encryptedAesKeyBase64, cipherTextBase64);
    }

    /**
     * Complete decryption flow for a received message (byte array version)
     *
     * @param encryptedPrivateKeyFromDB The encrypted private key blob from database
     * @param userPassword The user's password
     * @param encryptedAesKeyBase64 The encrypted AES key from message (Base64)
     * @param cipherTextBase64 The encrypted message (Base64)
     * @return Decrypted message plaintext
     * @throws Exception if decryption fails
     */
    public static String decryptMessage(
            byte[] encryptedPrivateKeyFromDB,
            String userPassword,
            String encryptedAesKeyBase64,
            String cipherTextBase64) throws Exception {

        // STEP 1: Extract salt from encrypted private key blob (first 16 bytes)
        byte[] salt = new byte[16];
        System.arraycopy(encryptedPrivateKeyFromDB, 0, salt, 0, 16);

        // STEP 2: Derive AES key from password using same parameters as registration
        SecretKey derivedKey = deriveKeyFromPassword(userPassword, salt);

        // STEP 3: Decrypt the private key
        byte[] encryptedPrivKey = new byte[encryptedPrivateKeyFromDB.length - 16];
        System.arraycopy(encryptedPrivateKeyFromDB, 16, encryptedPrivKey, 0, encryptedPrivKey.length);
        byte[] privateKeyBytes = aesGcmDecrypt(derivedKey, encryptedPrivKey);
        PrivateKey privateKey = bytesToPrivateKey(privateKeyBytes);

        // STEP 4: Decrypt the AES key using RSA private key
        byte[] encryptedAesKey = Base64.getDecoder().decode(encryptedAesKeyBase64);
        byte[] aesKeyBytes = rsaDecrypt(privateKey, encryptedAesKey);
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

        // STEP 5: Decrypt the message using AES key
        byte[] cipherText = Base64.getDecoder().decode(cipherTextBase64);
        byte[] plaintext = aesGcmDecrypt(aesKey, cipherText);

        return new String(plaintext);
    }

    /**
     * Derive AES key from password using PBKDF2
     */
    private static SecretKey deriveKeyFromPassword(String password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 150_000, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    /**
     * AES-GCM decryption (expects IV + ciphertext)
     */
    private static byte[] aesGcmDecrypt(SecretKey key, byte[] ivAndCipher) throws Exception {
        // Extract IV (first 12 bytes)
        byte[] iv = new byte[12];
        System.arraycopy(ivAndCipher, 0, iv, 0, 12);

        // Extract ciphertext (remaining bytes)
        byte[] cipherText = new byte[ivAndCipher.length - 12];
        System.arraycopy(ivAndCipher, 12, cipherText, 0, cipherText.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        return cipher.doFinal(cipherText);
    }

    /**
     * RSA-OAEP decryption
     */
    private static byte[] rsaDecrypt(PrivateKey privateKey, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    /**
     * Convert byte array to PrivateKey
     */
    private static PrivateKey bytesToPrivateKey(byte[] bytes) throws Exception {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }
}