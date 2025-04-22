package de.seba.auth_service.controller;

import de.seba.auth_service.dto.request.LoginUserRequest;
import de.seba.auth_service.dto.request.RegisterUserRequest;
import de.seba.auth_service.dto.response.AuthUserResponse;
import de.seba.auth_service.dto.response.LoginUserResponse;
import de.seba.auth_service.dto.response.RegisterUserResponse;
import de.seba.auth_service.util.JwtTokenProvider;
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
  public ResponseEntity<?> register(@RequestBody RegisterUserRequest registerUserRequest) {
    User registeredUser = authService.registerUser(registerUserRequest);
    RegisterUserResponse registerUserResponse = new RegisterUserResponse(
        registeredUser.getUsername(), "Registration successful");
    return ResponseEntity.ok(registerUserResponse);
  }

  @PostMapping("/login")
  public ResponseEntity<?> login(@RequestBody LoginUserRequest loginUserRequest, HttpServletResponse response) {
    User authenticatedUser = authService.loginUser(loginUserRequest);
    String token = jwtTokenProvider.generateToken(authenticatedUser.getUsername());
    ResponseCookie cookie = ResponseCookie.from("token", token)
        .httpOnly(true)
        .sameSite("Lax")
        .path("/")
        .maxAge(3600)
        .build();

    response.setHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    LoginUserResponse loginUserResponse = new LoginUserResponse(authenticatedUser.getUsername(),
        "Login successful");
    return ResponseEntity.ok(loginUserResponse);
  }

  @PostMapping("/validate")
  public ResponseEntity<?> validateToken(@CookieValue(value = "token") String cookieToken) {
    if (cookieToken == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("No token provided");
    }
    if (jwtTokenProvider.validateToken(cookieToken)) {
      String username = jwtTokenProvider.getUsernameFromToken(cookieToken);
      Date expiresAt = jwtTokenProvider.getExpirationFromToken(cookieToken);
      AuthUserResponse authUserResponse = new AuthUserResponse(username, expiresAt);
      return ResponseEntity.ok(authUserResponse);
    }
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid or expired token");
  }
}
