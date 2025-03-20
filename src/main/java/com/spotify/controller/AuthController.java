package com.spotify.controller;

import com.spotify.dto.request.*;
import com.spotify.dto.response.AuthResponse;
import com.spotify.exception.EmailAlreadyExistsException;
import com.spotify.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.transaction.Transactional;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest request, HttpServletRequest httpRequest) {
        try {
            return ResponseEntity.ok(authService.login(request, httpRequest));
        } catch (BadCredentialsException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new AuthResponse(null, null, "Invalid username or password!"));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new AuthResponse(null, null, e.getMessage()));
        }
    }

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@RequestBody RegisterRequest request, HttpServletRequest httpRequest) {
        try {
            // Bắt đầu quá trình đăng ký bằng cách gửi mã xác thực
            String message = authService.initiateRegistration(request.getEmail(), request.getPassword());
            return ResponseEntity.status(HttpStatus.OK).body(new AuthResponse(null, null, message));
        } catch (EmailAlreadyExistsException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new AuthResponse(null, null, e.getMessage()));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new AuthResponse(null, null, e.getMessage()));
        }
    }

    @PostMapping("/register/verify")
    public ResponseEntity<AuthResponse> verifyRegistration(@RequestBody VerificationRequest verificationCode, HttpServletRequest httpRequest) {
        try {
            // Hoàn tất đăng ký sau khi xác minh mã
            AuthResponse response = authService.completeRegistration(verificationCode.getEmail(), verificationCode.getVerificationCode(), httpRequest);
            return ResponseEntity.status(HttpStatus.CREATED).body(response);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new AuthResponse(null, null, e.getMessage()));
        }
    }


    @PostMapping("/logout")
    @Transactional
    public ResponseEntity<AuthResponse> logout(@RequestHeader(name = "Authorization", required = false) String authorizationHeader,
                                               @RequestBody LogoutRequest logoutRequest,
                                               HttpServletRequest request) {
        try {
            return ResponseEntity.ok(authService.logout(authorizationHeader, logoutRequest, request));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new AuthResponse(null, null, "Logout failed: " + e.getMessage()));
        }
    }
}