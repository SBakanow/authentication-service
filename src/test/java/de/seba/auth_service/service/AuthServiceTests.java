package de.seba.auth_service.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import de.seba.auth_service.dto.request.LoginUserRequest;
import de.seba.auth_service.dto.request.RegisterUserRequest;
import de.seba.auth_service.exception.InvalidCredentialsException;
import de.seba.auth_service.exception.UserAlreadyExistsException;
import de.seba.auth_service.exception.UserNotFoundException;
import de.seba.auth_service.model.User;
import de.seba.auth_service.repository.UserRepository;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

@ExtendWith(MockitoExtension.class)
class AuthServiceTests {

  @InjectMocks
  private AuthService authService;

  @Mock
  private UserService userService;

  @Mock
  private UserRepository userRepository;

  @Mock
  private PasswordEncoder passwordEncoder;

  private static String username;
  private static String password;
  private static String encodedPassword;
  private static User mockUser;
  private static Validator validator;

  @BeforeAll
  static void setUpTestData() {
    username = "testUser";
    password = "password";
    encodedPassword = "encodedPassword";
    mockUser = new User(username, encodedPassword);

    try (ValidatorFactory factory = Validation.buildDefaultValidatorFactory()) {
      validator = factory.getValidator();
    }
  }

  @Test
  @DisplayName("Should register a new user successfully when username is unique")
  void registerUser_ShouldReturnUser_WhenUserIsNotAlreadyRegistered() {
    RegisterUserRequest registerUserRequest = new RegisterUserRequest(username, password);

    when(userService.existsByUsername(username)).thenReturn(false);
    when(passwordEncoder.encode(password)).thenReturn(encodedPassword);
    when(userService.saveUser(any(User.class))).thenReturn(mockUser);

    User registeredUser = authService.registerUser(registerUserRequest);

    assertNotNull(registeredUser, "Expected a successfully registered user");
    assertEquals(username, registeredUser.getUsername(),
        "The username should be '" + username + "'");
    assertEquals(encodedPassword, registeredUser.getPassword(),
        "The password should be '" + encodedPassword + "'");

    verify(userService, times(1)).existsByUsername(username);
    verify(userService, times(1)).saveUser(any(User.class));
    verify(passwordEncoder, times(1)).encode(password);
  }

  @Test
  @DisplayName("Should throw UserAlreadyExistsException when username is already taken")
  void registerUser_ShouldThrowException_WhenUsernameAlreadyExists() {
    RegisterUserRequest registerUserRequest = new RegisterUserRequest(username, password);

    when(userService.existsByUsername(username))
        .thenReturn(false)
        .thenReturn(true);

    authService.registerUser(registerUserRequest);

    UserAlreadyExistsException exception = assertThrows(UserAlreadyExistsException.class, () -> {
      authService.registerUser(registerUserRequest);
    });
    assertEquals("User already exists", exception.getMessage(),
        "Expected error message: 'User already exists'");

    verify(userService, times(2)).existsByUsername(username);
    verify(userService, times(1)).saveUser(any(User.class));
  }

  @Test
  @DisplayName("Should fail validation when username is null")
  void registerUser_ShouldThrowValidationError_WhenUsernameIsNull() {
    RegisterUserRequest registerUserRequest = new RegisterUserRequest(null, password);

    Set<ConstraintViolation<RegisterUserRequest>> violations = validator.validate(
        registerUserRequest);
    assertFalse(violations.isEmpty(), "Expected validation errors for null username");

    ConstraintViolation<RegisterUserRequest> violation = violations.iterator().next();
    assertEquals("Username is required", violation.getMessage(),
        "Expected validation message for null username");
  }

  @Test
  @DisplayName("Should fail validation when username is empty")
  void registerUser_ShouldThrowValidationError_WhenUsernameIsEmpty() {
    RegisterUserRequest registerUserRequest = new RegisterUserRequest("", password);

    Set<ConstraintViolation<RegisterUserRequest>> violations = validator.validate(
        registerUserRequest);
    assertFalse(violations.isEmpty(), "Expected validation errors for empty username");

    ConstraintViolation<RegisterUserRequest> violation = violations.iterator().next();
    assertEquals("Username is required", violation.getMessage(),
        "Expected validation message for empty username");
  }

  @Test
  @DisplayName("Should fail validation when password is null")
  void registerUser_ShouldThrowValidationError_WhenPasswordIsNull() {
    RegisterUserRequest registerUserRequest = new RegisterUserRequest(username, null);

    Set<ConstraintViolation<RegisterUserRequest>> violations = validator.validate(
        registerUserRequest);
    assertFalse(violations.isEmpty(), "Expected validation errors for null password");

    ConstraintViolation<RegisterUserRequest> violation = violations.iterator().next();
    assertEquals("Password is required", violation.getMessage(),
        "Expected validation message for null password");
  }

  @Test
  @DisplayName("Should fail validation when password is empty")
  void registerUser_ShouldThrowValidationError_WhenPasswordIsEmpty() {
    RegisterUserRequest registerUserRequest = new RegisterUserRequest(username, "");

    Set<ConstraintViolation<RegisterUserRequest>> violations = validator.validate(
        registerUserRequest);
    assertFalse(violations.isEmpty(), "Expected validation errors for empty password");

    ConstraintViolation<RegisterUserRequest> violation = violations.iterator().next();
    assertEquals("Password is required", violation.getMessage(),
        "Expected validation message for empty password");
  }

  @Test
  @DisplayName("Should authenticate user successfully when credentials are valid")
  void loginUser_ShouldAuthenticateUser_WhenCredentialsAreValid() {
    LoginUserRequest loginUserRequest = new LoginUserRequest(username, password);

    when(userService.findByUsername(username)).thenReturn(Optional.of(mockUser));
    when(passwordEncoder.matches(password, encodedPassword)).thenReturn(true);

    User loggedInUser = authService.loginUser(loginUserRequest);

    assertNotNull(loggedInUser, "Authenticated user should not be null");
    assertEquals(username, loggedInUser.getUsername(), "Usernames should match");

    verify(userService, times(1)).findByUsername(username);
    verify(passwordEncoder, times(1)).matches(password, encodedPassword);
  }

  @Test
  @DisplayName("Should throw InvalidCredentialsException when password is incorrect")
  void loginUser_ShouldThrowException_WhenPasswordIsIncorrect() {
    LoginUserRequest loginUserRequest = new LoginUserRequest(username, password);

    when(userService.findByUsername(username)).thenReturn(Optional.of(mockUser));
    when(passwordEncoder.matches(password, encodedPassword)).thenReturn(false);

    InvalidCredentialsException exception = assertThrows(InvalidCredentialsException.class, () -> {
      authService.loginUser(loginUserRequest);
    });
    assertEquals("Invalid credentials", exception.getMessage(),
        "Expected error message: 'Invalid credentials'");

    verify(userService, times(1)).findByUsername(username);
    verify(passwordEncoder, times(1)).matches(password, encodedPassword);
  }

  @Test
  @DisplayName("Should throw UserNotFoundException when username does not exist")
  void loginUser_ShouldThrowException_WhenUsernameDoesNotExist() {
    LoginUserRequest loginUserRequest = new LoginUserRequest(username, password);

    when(userService.findByUsername(username)).thenReturn(Optional.empty());

    UserNotFoundException exception = assertThrows(UserNotFoundException.class, () -> {
      authService.loginUser(loginUserRequest);
    });
    assertEquals("User not found", exception.getMessage(),
        "Expected error message: 'User not found'");

    verify(userService, times(1)).findByUsername(username);
    verify(passwordEncoder, never()).matches(anyString(), anyString());
  }
}
