package de.seba.auth_service.controller;

import de.seba.auth_service.config.JwtTokenProvider;
import de.seba.auth_service.model.User;
import de.seba.auth_service.service.AuthService;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Date;
import java.util.Map;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

  private final AuthService authService;
  private final JwtTokenProvider jwtTokenProvider;

  public AuthController(AuthService authService, JwtTokenProvider jwtTokenProvider) {
    this.authService = authService;
    this.jwtTokenProvider = jwtTokenProvider;
  }

  @GetMapping("/login")
  public String home() {
    return "Welcome to the authentication site";
  }

  @PostMapping("/register")
  public ResponseEntity<?> register(@RequestBody User user) {
    authService.registerUser(user.getUsername(), user.getPassword());
    return ResponseEntity.ok("Registration successful");
  }

  @PostMapping("/login")
  public ResponseEntity<?> login(@RequestBody User user, HttpServletResponse response) {
    User authenticatedUser = authService.authenticate(user.getUsername(), user.getPassword());
    String token = jwtTokenProvider.generateToken(authenticatedUser.getUsername());
    ResponseCookie cookie = ResponseCookie.from("token", token)
        .httpOnly(true)
        .sameSite("Lax")
        .path("/")
        .maxAge(3600)
        .build();

    response.setHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    return ResponseEntity.ok(
        Map.of("message", "Login successful", "username", authenticatedUser.getUsername()));
  }

  @PostMapping("/validate")
  public ResponseEntity<?> validateToken(@CookieValue(value = "token") String cookieToken) {
    if (cookieToken == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("No token provided");
    }
    if (jwtTokenProvider.validateToken(cookieToken)) {
      String username = jwtTokenProvider.getUsernameFromToken(cookieToken);
      Date expiresAt = jwtTokenProvider.getExpirationFromToken(cookieToken);
      return ResponseEntity.ok(Map.of("username", username, "expiresAt", expiresAt));
    }
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid or expired token");
  }
}
