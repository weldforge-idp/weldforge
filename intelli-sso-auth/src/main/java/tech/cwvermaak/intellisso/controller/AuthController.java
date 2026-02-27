package tech.cwvermaak.intellisso.controller;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import tech.cwvermaak.intellisso.model.User;
import tech.cwvermaak.intellisso.model.dto.JwtResponseDto;
import tech.cwvermaak.intellisso.model.dto.LoginRequestDto;
import tech.cwvermaak.intellisso.model.dto.RegisterRequestDto;
import tech.cwvermaak.intellisso.model.dto.UserResponseDto;
import tech.cwvermaak.intellisso.repository.UserRepository;
import tech.cwvermaak.intellisso.service.AuthService;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final UserRepository userRepository;

    @PostMapping("/register")
    public ResponseEntity<JwtResponseDto> register(@RequestBody RegisterRequestDto request, HttpServletResponse response) {
        return ResponseEntity.ok(authService.register(request, response));
    }

    @PostMapping("/login")
    public ResponseEntity<JwtResponseDto> login(@RequestBody LoginRequestDto request, HttpServletResponse response) {
        return ResponseEntity.ok(authService.login(request, response));
    }

    @GetMapping("/me")
    public ResponseEntity<UserResponseDto> currentUser(@AuthenticationPrincipal String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        return ResponseEntity.ok(UserResponseDto.builder()
                .id(user.getId())
                .name(user.getName())
                .email(user.getEmail())
                .imageUrl(user.getImageUrl())
                .provider(user.getProvider())
                .role(user.getRole() != null ? user.getRole().getName() : null)
                .build());
    }
}
