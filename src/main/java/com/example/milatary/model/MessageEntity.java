package com.example.milatary.model;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "messages")
public class MessageEntity {

    @Id
    @GeneratedValue
    private UUID id; // unique id per message

    @Column(nullable = false)
    private UUID senderId;

    @Column(nullable = false)
    private UUID recipientId;

    @Lob
    @Column(nullable = false)
    private byte[] encryptedAesKey; // AES key encrypted with recipient's RSA public key

    @Lob
    @Column(nullable = false)
    private byte[] cipherText; // AES-GCM ciphertext of message

    @Column(nullable = false)
    private Instant createdAt;

    @Column(nullable = false)
    private Instant expiresAt;

    @Column(nullable = false)
    private boolean delivered = false;

    public MessageEntity() {
        // JPA default constructor
    }

    public MessageEntity(UUID senderId, UUID recipientId, byte[] encryptedAesKey,
                         byte[] cipherText, Instant createdAt, Instant expiresAt) {
        this.senderId = senderId;
        this.recipientId = recipientId;
        this.encryptedAesKey = encryptedAesKey;
        this.cipherText = cipherText;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
        this.delivered = false;
    }


    // Getters and Setters

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public UUID getSenderId() {
        return senderId;
    }

    public void setSenderId(UUID senderId) {
        this.senderId = senderId;
    }

    public UUID getRecipientId() {
        return recipientId;
    }

    public void setRecipientId(UUID recipientId) {
        this.recipientId = recipientId;
    }

    public byte[] getEncryptedAesKey() {
        return encryptedAesKey;
    }

    public void setEncryptedAesKey(byte[] encryptedAesKey) {
        this.encryptedAesKey = encryptedAesKey;
    }

    public byte[] getCipherText() {
        return cipherText;
    }

    public void setCipherText(byte[] cipherText) {
        this.cipherText = cipherText;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }

    public boolean isDelivered() {
        return delivered;
    }

    public void setDelivered(boolean delivered) {
        this.delivered = delivered;
    }
}
