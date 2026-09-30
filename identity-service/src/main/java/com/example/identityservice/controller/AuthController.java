package com.example.identityservice.controller;

import com.example.identityservice.dto.LoginRequest;
import com.example.identityservice.dto.LoginResponse;
import com.example.identityservice.entity.User;
import com.example.identityservice.repo.UserRepository;
import com.example.identityservice.service.AuthService;
import com.example.identityservice.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;

    @PostMapping("/register")
    public User register(
            @RequestBody User user
    ) {
        User saved = authService.register(user);

        saved.setPassword(null);

        return saved;
    }
    @GetMapping("/test-token")
    public String testToken(
            @RequestParam String username
    ) {

        User user = userRepository.findByUsername(username)
                .orElseThrow(() ->
                        new RuntimeException("Khong tim thay user")
                );

        return jwtUtil.generateToken(user);
    }
    @PostMapping("/login")
    public LoginResponse login(
            @RequestBody LoginRequest request
    ) {

        String token =
                authService.login(request);

        return new LoginResponse(token);
    }
}