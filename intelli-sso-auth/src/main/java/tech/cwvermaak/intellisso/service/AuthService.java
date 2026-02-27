package tech.cwvermaak.intellisso.service;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import tech.cwvermaak.intellisso.model.AuthProvider;
import tech.cwvermaak.intellisso.model.User;
import tech.cwvermaak.intellisso.model.dto.JwtResponseDto;
import tech.cwvermaak.intellisso.model.dto.LoginRequestDto;
import tech.cwvermaak.intellisso.model.dto.RegisterRequestDto;
import tech.cwvermaak.intellisso.repository.UserRepository;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final TwilioService twilioService;

    public JwtResponseDto register(RegisterRequestDto request, HttpServletResponse response) {
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new RuntimeException("Email already in use");
        }
        if (userRepository.findByUsername(request.getName()).isPresent()) {
            throw new RuntimeException("Username already in use");
        }

        User user = User.builder()
                .username(request.getName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .provider(AuthProvider.LOCAL)
                .providerId("local")
                .build();

        userRepository.save(user);

        // Send verification SMS/WhatsApp (example)
        // twilioService.sendSms(user.getCellPhoneNumber(), "Welcome to IntelliSSO! Please verify your number.");

        return generateTokens(user.getUsername(), response);
    }

    public JwtResponseDto login(LoginRequestDto request, HttpServletResponse response) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getIdentifier(), request.getPassword())
        );

        // Retrieve the user to get the username (in case they logged in with email)
        User user = userRepository.findByUsernameOrEmail(request.getIdentifier(), request.getIdentifier())
                .orElseThrow(() -> new RuntimeException("User not found"));

        return generateTokens(user.getUsername(), response);
    }

    private JwtResponseDto generateTokens(String username, HttpServletResponse response) {
        String accessToken = jwtService.generateAccessToken(username);
        String refreshToken = jwtService.generateRefreshToken(username);

        Cookie refreshCookie = new Cookie("refresh_token", refreshToken);
        refreshCookie.setHttpOnly(true);
        refreshCookie.setSecure(true); // Set to true in production (requires HTTPS)
        refreshCookie.setPath("/api/auth/refresh");
        refreshCookie.setMaxAge((int) (jwtService.getRefreshTokenExpirationTime() / 1000));
        response.addCookie(refreshCookie);

        return JwtResponseDto.builder()
                .token(accessToken)
                .expiresIn(jwtService.getExpirationTime())
                .build();
    }
}
