package de.seba.auth_service.service;

import de.seba.auth_service.model.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

  private final UserService userService;
  private final PasswordEncoder passwordEncoder;

  public AuthService(UserService userService, PasswordEncoder passwordEncoder) {
    this.userService = userService;
    this.passwordEncoder = passwordEncoder;
  }

  public void registerUser(String username, String password) {
    if (userService.findByUsername(username).isPresent()) {
      throw new RuntimeException("User already exists");
    }
    User user = new User();
    user.setUsername(username);
    user.setPassword(passwordEncoder.encode(password));
    userService.saveUser(user);
  }

  public User authenticate(String username, String password) {
    User user = userService.findByUsername(username)
        .orElseThrow(() -> new RuntimeException("User not found"));
    if (passwordEncoder.matches(password, user.getPassword())) {
      return user;
    }
    throw new RuntimeException("Invalid credentials");
  }

}
