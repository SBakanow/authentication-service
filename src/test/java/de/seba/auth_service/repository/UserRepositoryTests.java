package de.seba.auth_service.repository;

import static org.junit.jupiter.api.Assertions.*;

import de.seba.auth_service.model.User;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.ActiveProfiles;

@ActiveProfiles("test")
@DataJpaTest
class UserRepositoryTests {

  @Autowired
  private UserRepository userRepository;

  @BeforeEach
  void setUp() {
    User user = new User("testUser", "encodedPassword");
    userRepository.save(user);
  }

  @Test
  @DisplayName("Should return user when username exists")
  void findByUsername_ShouldReturnUser_WhenUserExists() {
    Optional<User> foundUser = userRepository.findByUsername("testUser");

    assertTrue(foundUser.isPresent(), "User should exist");
    assertEquals("testUser", foundUser.get().getUsername());
  }

  @Test
  @DisplayName("Should return empty when username does not exist")
  void findByUsername_ShouldReturnEmpty_WhenUserDoesNotExist() {
    Optional<User> foundUser = userRepository.findByUsername("nonExistingUser");

    assertFalse(foundUser.isPresent(), "User should not exist");
  }

  @Test
  @DisplayName("Should return true when username exists")
  void existsByUsername_ShouldReturnTrue_WhenUserExists() {
    boolean exists = userRepository.existsByUsername("testUser");

    assertTrue(exists, "User should exist");
  }

  @Test
  @DisplayName("Should return false when username does not exist")
  void existsByUsername_ShouldReturnFalse_WhenUserDoesNotExist() {
    boolean exists = userRepository.existsByUsername("nonExistingUser");

    assertFalse(exists, "User should not exist");
  }
}
