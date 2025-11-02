package com.example.milatary.model;

import jakarta.persistence.*;
import java.util.UUID;

@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue
    private UUID id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String passwordHash; // BCrypt hashed password

    // Force Hibernate to use BYTEA instead of OID
    @Column(nullable = false, columnDefinition = "BYTEA")
    private byte[] publicKey;

    @Column(nullable = false, columnDefinition = "BYTEA")
    private byte[] encryptedPrivateKey;

    public User() {}

    public User(String username, String passwordHash, byte[] publicKey, byte[] encryptedPrivateKey) {
        this.username = username;
        this.passwordHash = passwordHash;
        this.publicKey = publicKey;
        this.encryptedPrivateKey = encryptedPrivateKey;
    }

    // Getters & Setters
    public UUID getId() {
        return id;
    }
    public void setId(UUID id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }
    public void setUsername(String username) {
        this.username = username;
    }

    public String getPasswordHash() {
        return passwordHash;
    }
    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }
    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    public byte[] getEncryptedPrivateKey() {
        return encryptedPrivateKey;
    }
    public void setEncryptedPrivateKey(byte[] encryptedPrivateKey) {
        this.encryptedPrivateKey = encryptedPrivateKey;
    }
}
