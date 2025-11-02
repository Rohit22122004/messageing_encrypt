package com.example.milatary.repository;




import com.example.milatary.model.MessageEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

public interface MessageRepository extends JpaRepository<MessageEntity, UUID> {
    List<MessageEntity> findByRecipientId(UUID recipientId);
    List<MessageEntity> findByExpiresAtBefore(Instant time);
}
