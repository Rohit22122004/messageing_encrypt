package com.example.milatary.controller;



import com.example.milatary.security.JwtUtil;
import com.example.milatary.model.MessageEntity;
import com.example.milatary.model.User;
import com.example.milatary.repository.MessageRepository;
import com.example.milatary.repository.UserRepository;
import com.example.milatary.security.CryptoUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

import javax.crypto.SecretKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.*;

@RestController
@RequestMapping("/api/messages")
public class MessageController {

    @Autowired private MessageRepository messageRepository;
    @Autowired private UserRepository userRepository;

    // send message: body { "recipientUsername": "...", "plaintext": "..." , "ttlMinutes": 60 }
    // The server performs hybrid encryption: generate AES key, AES-GCM encrypt plaintext, encrypt AES key with recipient's public key.
    @PostMapping("/send")
    public ResponseEntity<?> send(@RequestHeader("Authorization") String auth,
                                  @RequestBody Map<String,Object> body) throws Exception {
        String userIdStr = JwtUtil.getUserIdFromAuthHeader(auth);
        if (userIdStr == null) return ResponseEntity.status(401).body("invalid token");
        UUID senderId = UUID.fromString(userIdStr);

        String recipientUsername = (String) body.get("recipientUsername");
        String plaintext = (String) body.get("plaintext");
        Integer ttl = (Integer) body.getOrDefault("ttlMinutes", 60);

        var rec = userRepository.findByUsername(recipientUsername);
        if (rec.isEmpty()) return ResponseEntity.badRequest().body("recipient not found");
        User recipient = rec.get();

        SecretKey aes = CryptoUtils.generateAESKey();
        byte[] cipherText = CryptoUtils.aesGcmEncrypt(aes, plaintext.getBytes());
        PublicKey recipientPub = CryptoUtils.bytesToPublicKey(recipient.getPublicKey());
        byte[] encryptedAesKey = CryptoUtils.rsaEncrypt(recipientPub, aes.getEncoded());

        MessageEntity msg = new MessageEntity();
        msg.setSenderId(senderId);
        msg.setRecipientId(recipient.getId());
        msg.setEncryptedAesKey(encryptedAesKey);
        msg.setCipherText(cipherText);
        msg.setCreatedAt(Instant.now());
        msg.setExpiresAt(Instant.now().plusSeconds(ttl * 60L));
        msg.setDelivered(false);
        messageRepository.save(msg);

        return ResponseEntity.ok(Map.of("messageId", msg.getId().toString()));
    }

    // fetch all messages for authenticated user (returns encrypted blobs; client decrypts)
    @GetMapping("/")
    public ResponseEntity<?> list(@RequestHeader("Authorization") String auth) {
        UUID userId = UUID.fromString(JwtUtil.getUserIdFromAuthHeader(auth));
        var msgs = messageRepository.findByRecipientId(userId);
        List<Map<String,Object>> out = new ArrayList<>();
        for (var m : msgs) {
            out.add(Map.of(
                    "id", m.getId().toString(),
                    "senderId", m.getSenderId().toString(),
                    "encryptedAesKey", Base64.getEncoder().encodeToString(m.getEncryptedAesKey()),
                    "cipherText", Base64.getEncoder().encodeToString(m.getCipherText()),
                    "createdAt", m.getCreatedAt().toString(),
                    "expiresAt", m.getExpiresAt().toString()
            ));
        }
        return ResponseEntity.ok(out);
    }

    // fetch a single message by id
    @GetMapping("/{id}")
    public ResponseEntity<?> get(@RequestHeader("Authorization") String auth, @PathVariable String id) {
        UUID userId = UUID.fromString(JwtUtil.getUserIdFromAuthHeader(auth));
        UUID msgId = UUID.fromString(id);
        var opt = messageRepository.findById(msgId);
        if (opt.isEmpty()) return ResponseEntity.notFound().build();
        var m = opt.get();
        if (!m.getRecipientId().equals(userId)) return ResponseEntity.status(403).body("forbidden");
        Map<String,Object> res = Map.of(
                "id", m.getId().toString(),
                "senderId", m.getSenderId().toString(),
                "encryptedAesKey", Base64.getEncoder().encodeToString(m.getEncryptedAesKey()),
                "cipherText", Base64.getEncoder().encodeToString(m.getCipherText()),
                "createdAt", m.getCreatedAt().toString(),
                "expiresAt", m.getExpiresAt().toString()
        );
        return ResponseEntity.ok(res);
    }

    // acknowledge & delete message (recipient calls after decrypting)
    @PostMapping("/{id}/ack")
    public ResponseEntity<?> ack(@RequestHeader("Authorization") String auth, @PathVariable String id) {
        UUID userId = UUID.fromString(JwtUtil.getUserIdFromAuthHeader(auth));
        UUID msgId = UUID.fromString(id);
        var opt = messageRepository.findById(msgId);
        if (opt.isEmpty()) return ResponseEntity.notFound().build();
        var m = opt.get();
        if (!m.getRecipientId().equals(userId)) return ResponseEntity.status(403).body("forbidden");
        messageRepository.delete(m);
        return ResponseEntity.ok(Map.of("deleted", true));
    }
}
