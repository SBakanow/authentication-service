package de.seba.auth_service.dto.response;

import java.util.Date;

public class AuthUserResponse {

  private String username;

  private Date expiresAt;

  public AuthUserResponse() {

  }

  public AuthUserResponse(String username, Date expiresAt) {
    this.username = username;
    this.expiresAt = expiresAt;
  }

  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public Date getExpiresAt() {
    return expiresAt;
  }

  public void setExpiresAt(Date expiresAt) {
    this.expiresAt = expiresAt;
  }
}
