package com.spotify.service;

import com.spotify.entity.RefreshToken;
import com.spotify.entity.User;
import com.spotify.repository.RefreshTokenRepository;
import com.spotify.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {
    @Value("${jwt.refresh.expiration}")
    private String refreshTokenDurationMsStr;  // Inject dạng String

    private Long refreshTokenDurationMs;

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;

    @PostConstruct
    public void init() {
        this.refreshTokenDurationMs = Long.parseLong(refreshTokenDurationMsStr);
    }
    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository, UserRepository userRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
    }

    public RefreshToken createRefreshToken(User user, String deviceInfo) {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
        refreshToken.setDeviceId(deviceInfo);
        return refreshTokenRepository.save(refreshToken);
    }

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    public void deleteByUserIdAndDeviceId(Long userId, String deviceId) {
        refreshTokenRepository.deleteByUserIdAndDeviceId(userId, deviceId);
    }

    public boolean validateToken(String token) {
        return findByToken(token)
                .map(refreshToken -> !refreshToken.getExpiryDate().isBefore(Instant.now()))
                .orElse(false);
    }
}
