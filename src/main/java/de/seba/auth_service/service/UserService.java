package de.seba.auth_service.service;

import de.seba.auth_service.model.User;
import de.seba.auth_service.repository.UserRepository;
import java.util.Optional;
import org.springframework.stereotype.Service;

@Service
public class UserService {

  private final UserRepository userRepository;

  public UserService(UserRepository userRepository) {
    this.userRepository = userRepository;
  }

  public Optional<User> findByUsername(String username) {
    return userRepository.findByUsername(username);
  }

  public void saveUser(User user) {
    userRepository.save(user);
  }
}
