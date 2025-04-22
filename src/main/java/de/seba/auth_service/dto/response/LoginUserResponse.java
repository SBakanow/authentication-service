package de.seba.auth_service.dto.response;

public class LoginUserResponse {

  private String username;

  private String message;

  public LoginUserResponse() {

  }

  public LoginUserResponse(String username, String message) {
    this.username = username;
    this.message = message;
  }

  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public String getMessage() {
    return message;
  }

  public void setMessage(String message) {
    this.message = message;
  }
}
