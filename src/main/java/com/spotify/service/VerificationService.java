package com.spotify.service;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import java.util.Random;
import java.util.concurrent.TimeUnit;

@Service
public class VerificationService {
    private final StringRedisTemplate redisTemplate;
    private final JavaMailSender mailSender;
    private static final long EXPIRATION_TIME = 5; // 5 minutes

    public VerificationService(StringRedisTemplate redisTemplate, JavaMailSender mailSender) {
        this.redisTemplate = redisTemplate;
        this.mailSender = mailSender;
    }

    public void sendVerificationCode(String email) {
        String code = generateVerificationCode();
        redisTemplate.opsForValue().set(getRedisKey(email), code, EXPIRATION_TIME, TimeUnit.MINUTES);
        sendEmail(email, code);
    }

    public boolean verifyCode(String email, String code) {
        String storedCode = redisTemplate.opsForValue().get(getRedisKey(email));
        if (storedCode != null && storedCode.equals(code)) {
            redisTemplate.delete(getRedisKey(email));
            return true;
        }
        return false;
    }

    private String generateVerificationCode() {
        return String.format("%06d", new Random().nextInt(1000000));
    }

    private void sendEmail(String email, String code) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);
            helper.setTo(email);
            helper.setSubject("Your Verification Code");
            helper.setText("Your verification code is: " + code);
            mailSender.send(message);
        } catch (MessagingException e) {
            throw new RuntimeException("Failed to send verification email", e);
        }
    }

    private String getRedisKey(String email) {
        return "verification_code:" + email;
    }
}
