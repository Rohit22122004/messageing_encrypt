package com.example.milatary.security;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class CryptoUtils {
    private static final SecureRandom secureRandom = new SecureRandom();

    // Generate RSA keypair
    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048, secureRandom);
        return kpg.generateKeyPair();
    }

    // Generate AES-256 key
    public static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256, secureRandom);
        return kg.generateKey();
    }

    // AES-GCM encrypt (return iv + cipher)
    public static byte[] aesGcmEncrypt(SecretKey key, byte[] plaintext) throws Exception {
        byte[] iv = new byte[12];
        secureRandom.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] cipherText = cipher.doFinal(plaintext);
        byte[] out = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(cipherText, 0, out, iv.length, cipherText.length);
        return out;
    }

    // AES-GCM decrypt (expect iv + cipher)
    public static byte[] aesGcmDecrypt(SecretKey key, byte[] ivAndCipher) throws Exception {
        byte[] iv = new byte[12];
        System.arraycopy(ivAndCipher, 0, iv, 0, 12);
        byte[] cipherText = new byte[ivAndCipher.length - 12];
        System.arraycopy(ivAndCipher, 12, cipherText, 0, cipherText.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        return cipher.doFinal(cipherText);
    }

    // Encrypt AES key with RSA public key
    public static byte[] rsaEncrypt(PublicKey publicKey, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    // Decrypt AES key with RSA private key
    public static byte[] rsaDecrypt(PrivateKey privateKey, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    // Utility: encode/decode keys
    public static byte[] publicKeyToBytes(PublicKey pk) {
        return pk.getEncoded();
    }

    public static PublicKey bytesToPublicKey(byte[] bytes) throws Exception {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public static PrivateKey bytesToPrivateKey(byte[] bytes) throws Exception {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    // Encode keys to Base64
    public static String encodeKeyToBase64(Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    // Decode Base64 to Private/Public key
    public static PrivateKey decodePrivateKey(String base64) throws Exception {
        return bytesToPrivateKey(Base64.getDecoder().decode(base64));
    }

    public static PublicKey decodePublicKey(String base64) throws Exception {
        return bytesToPublicKey(Base64.getDecoder().decode(base64));
    }
    // Derive AES key from password using PBKDF2 (Password-Based Key Derivation Function 2)
    public static SecretKey deriveKeyPBKDF2(char[] password, byte[] salt, int iterations, int keyLen)
            throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLen);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

}
