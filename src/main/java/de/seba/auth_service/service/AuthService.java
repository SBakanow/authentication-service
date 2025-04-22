package de.seba.auth_service.service;

import de.seba.auth_service.dto.request.LoginUserRequest;
import de.seba.auth_service.dto.request.RegisterUserRequest;
import de.seba.auth_service.exception.InvalidCredentialsException;
import de.seba.auth_service.exception.UserAlreadyExistsException;
import de.seba.auth_service.exception.UserNotFoundException;
import de.seba.auth_service.model.User;
import jakarta.validation.Valid;
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

  public User registerUser(@Valid RegisterUserRequest registerUserRequest) {
    if (userService.existsByUsername(registerUserRequest.getUsername())) {
      throw new UserAlreadyExistsException("User already exists");
    }

    String encodedPassword = passwordEncoder.encode(registerUserRequest.getPassword());
    User user = new User(registerUserRequest.getUsername(), encodedPassword);
    userService.saveUser(user);
    return user;
  }

  public User loginUser(@Valid LoginUserRequest loginUserRequest) {
    User user = userService.findByUsername(loginUserRequest.getUsername())
        .orElseThrow(() -> new UserNotFoundException("User not found"));
    if (!passwordEncoder.matches(loginUserRequest.getPassword(), user.getPassword())) {
      throw new InvalidCredentialsException("Invalid credentials");
    }
    return user;
  }
}
