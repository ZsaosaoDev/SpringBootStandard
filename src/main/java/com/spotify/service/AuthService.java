package com.spotify.service;

import com.spotify.dto.request.LoginRequest;
import com.spotify.dto.request.LogoutRequest;
import com.spotify.dto.request.RegisterRequest;
import com.spotify.dto.response.AuthResponse;
import com.spotify.entity.RefreshToken;
import com.spotify.entity.User;
import com.spotify.enums.RoleEnum;
import com.spotify.exception.EmailAlreadyExistsException;
import com.spotify.repository.RoleRepository;
import com.spotify.repository.UserRepository;
import com.spotify.security.CustomUserDetailsService;
import com.spotify.util.DeviceUtil;
import com.spotify.util.JwtUtil;
import com.spotify.util.ValidationUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.concurrent.TimeUnit;


import java.util.concurrent.TimeUnit;

@Service
public class AuthService {
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;
    private final CustomUserDetailsService userDetailsService;
    private final RoleRepository roleRepository;
    private final RefreshTokenService refreshTokenService;
    private final JwtBlacklistService jwtBlacklistService;
    private final VerificationService verificationService;
    private final StringRedisTemplate redisTemplate;

    private static final long TEMP_PASSWORD_EXPIRATION = 10; // 10 minutes

    public AuthService(UserRepository userRepository, JwtUtil jwtUtil, AuthenticationManager authenticationManager,
                       PasswordEncoder passwordEncoder, CustomUserDetailsService userDetailsService,
                       RoleRepository roleRepository, RefreshTokenService refreshTokenService,
                       StringRedisTemplate redisTemplate,VerificationService verificationService) {
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
        this.userDetailsService = userDetailsService;
        this.roleRepository = roleRepository;
        this.refreshTokenService = refreshTokenService;
        this.jwtBlacklistService = new JwtBlacklistService(redisTemplate);
        this.verificationService = verificationService;
        this.redisTemplate = redisTemplate;
    }

    public void storeTemporaryPassword(String email, String encodedPassword) {
        redisTemplate.opsForValue().set(getPasswordKey(email), encodedPassword, TEMP_PASSWORD_EXPIRATION, TimeUnit.MINUTES);
    }

    public String retrieveTemporaryPassword(String email) {
        String password = redisTemplate.opsForValue().get(getPasswordKey(email));
        if (password != null) {
            redisTemplate.delete(getPasswordKey(email));
        }
        return password;
    }

    private String getPasswordKey(String email) {
        return "temp_password:" + email;
    }

    public AuthResponse login(LoginRequest request, HttpServletRequest httpRequest) {
        validateEmail(request.getEmail());
        authenticateUser(request.getEmail(), request.getPassword());

        User user = getUserByEmail(request.getEmail());
        String accessToken = jwtUtil.generateAccessToken(userDetailsService.loadUserByUsername(request.getEmail()));
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user, DeviceUtil.getDeviceType(httpRequest));

        return new AuthResponse(accessToken, refreshToken.getToken(), "User logged in successfully!");
    }

    public String initiateRegistration(String email, String password) {
        if (userRepository.findByEmail(email).isPresent()) {
            throw new EmailAlreadyExistsException("Email already exists!");
        }
        validateEmail(email);

        // Lưu mật khẩu tạm thời vào Redis với thời gian hết hạn
        storeTemporaryPassword(email, passwordEncoder.encode(password));

        // Gửi mã xác thực qua email
        verificationService.sendVerificationCode(email);

        return "Verification code sent successfully! Please verify your email.";
    }

    public AuthResponse completeRegistration(String email, String verificationCode, HttpServletRequest httpRequest) {
        if (!verificationService.verifyCode(email, verificationCode)) {
            throw new IllegalArgumentException("Invalid or expired verification code!");
        }

        // Lấy lại mật khẩu đã lưu tạm thời từ Redis
        String encodedPassword = retrieveTemporaryPassword(email);
        if (encodedPassword == null) {
            throw new IllegalArgumentException("No registration request found. Please start over.");
        }

        User newUser = createUser(email, encodedPassword);
        String accessToken = jwtUtil.generateAccessToken(userDetailsService.loadUserByUsername(newUser.getEmail()));
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(newUser, DeviceUtil.getDeviceType(httpRequest));

        return new AuthResponse(accessToken, refreshToken.getToken(), "User registered successfully!");
    }

    public AuthResponse logout(String authorizationHeader, LogoutRequest logoutRequest, HttpServletRequest request) {
        String accessToken = extractToken(authorizationHeader);
        validateToken(accessToken);
        validateEmail(logoutRequest.getEmail());

        if (jwtBlacklistService.isTokenBlacklisted(accessToken)) {
            return new AuthResponse(null, null, "The user has already successfully logged out.");
        }

        User user = getUserByEmail(logoutRequest.getEmail());
        refreshTokenService.deleteByUserIdAndDeviceInfo(user.getId(), DeviceUtil.getDeviceType(request));
        jwtBlacklistService.blacklistToken(accessToken, jwtUtil.getExpirationFromToken(accessToken).getTime() - System.currentTimeMillis());

        return new AuthResponse(null, null, "User logged out successfully!");
    }

    private void validateEmail(String email) {
        if (!ValidationUtil.isValidEmail(email)) {
            throw new IllegalArgumentException("Invalid email format!");
        }
    }

    private void authenticateUser(String email, String password) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));
    }

    private User getUserByEmail(String email) {
        return userRepository.findByEmail(email).orElseThrow(() -> new RuntimeException("User not found!"));
    }

    private User createUser(String email, String password) {
        User user = new User();
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        user.setRoles(Set.of(roleRepository.findByName(RoleEnum.USER).orElseThrow(() -> new RuntimeException("Role not found"))));
        return userRepository.save(user);
    }

    private String extractToken(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            throw new RuntimeException("Invalid token format");
        }
        return authorizationHeader.substring(7);
    }

    private void validateToken(String token) {
        if (!jwtUtil.validateToken(token)) {
            throw new RuntimeException("Invalid or expired token!");
        }
    }


}
