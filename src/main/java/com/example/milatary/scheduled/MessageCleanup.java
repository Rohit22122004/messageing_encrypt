package com.example.milatary.scheduled;



import com.example.milatary.repository.MessageRepository;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import java.time.Instant;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;

@Component
public class MessageCleanup {
    @Autowired private MessageRepository messageRepository;

    // every 5 minutes
    @Scheduled(fixedRate = 300_000)
    public void cleanupExpired() {
        var expired = messageRepository.findByExpiresAtBefore(Instant.now());
        if (!expired.isEmpty()) {
            messageRepository.deleteAll(expired);
        }
    }
}

