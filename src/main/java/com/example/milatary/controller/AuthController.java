package com.example.milatary.controller;




import com.example.milatary.model.User;
import com.example.milatary.repository.UserRepository;
import com.example.milatary.security.CryptoUtils;
import com.example.milatary.security.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Map<String, String> body) throws Exception {
        String username = body.get("username");
        String password = body.get("password");

        if (username == null || password == null) {
            return ResponseEntity.badRequest().body("username & password required");
        }
        if (userRepository.findByUsername(username).isPresent()) {
            return ResponseEntity.badRequest().body("username taken");
        }

        // 1️⃣ Generate RSA keypair
        KeyPair keyPair = CryptoUtils.generateRSAKeyPair();
        byte[] publicKeyBytes = CryptoUtils.publicKeyToBytes(keyPair.getPublic());
        byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();

        // 2️⃣ Derive AES key from password using PBKDF2 (with salt)
        byte[] salt = new byte[16];
        SecureRandom.getInstanceStrong().nextBytes(salt);
        SecretKey derivedKey = CryptoUtils.deriveKeyPBKDF2(password.toCharArray(), salt, 150_000, 256);

        // 3️⃣ Encrypt private key using AES-GCM
        byte[] encryptedPriv = CryptoUtils.aesGcmEncrypt(derivedKey, privateKeyBytes);

        // 4️⃣ Combine salt + encrypted private key into one array for storage
        byte[] saltedEncryptedPriv = new byte[salt.length + encryptedPriv.length];
        System.arraycopy(salt, 0, saltedEncryptedPriv, 0, salt.length);
        System.arraycopy(encryptedPriv, 0, saltedEncryptedPriv, salt.length, encryptedPriv.length);

        // 5️⃣ Store all securely
        User user = new User();
        user.setUsername(username);
        user.setPasswordHash(passwordEncoder.encode(password));  // still use BCrypt for login
        user.setPublicKey(publicKeyBytes);
        user.setEncryptedPrivateKey(saltedEncryptedPriv);

        userRepository.save(user);

        return ResponseEntity.ok(Map.of("message", "User registered successfully"));
    }


    // login returns JWT
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String,String> body) {
        String username = body.get("username");
        String password = body.get("password");
        var opt = userRepository.findByUsername(username);
        if (opt.isEmpty()) return ResponseEntity.status(401).body("invalid");

        // ✅ TEMP test
        User u = opt.get();
        // if (!passwordEncoder.matches(password, u.getPasswordHash())) return ResponseEntity.status(401).body("invalid");

        String token = JwtUtil.generateToken(u.getId().toString());
        return ResponseEntity.ok(Map.of("token", token));
    }

}

