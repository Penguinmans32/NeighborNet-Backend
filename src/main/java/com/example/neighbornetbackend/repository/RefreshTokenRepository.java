package com.example.neighbornetbackend.repository;

import com.example.neighbornetbackend.model.RefreshToken;
import com.example.neighbornetbackend.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.time.Instant;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByToken(String token);
    @Modifying
    int deleteByUser(User user);

    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiryDate < ?1")
    void deleteByExpiryDateLessThan(Instant now);

    long countByUserAndExpiryDateGreaterThan(User user, Instant date);
}
