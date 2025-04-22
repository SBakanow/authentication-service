package de.seba.auth_service.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;
import org.springframework.stereotype.Component;

@Component
public class JwtTokenProvider {

  private final Key secretKey;
  private final long validityInMilliseconds = 3600000;

  public JwtTokenProvider() {
    this.secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);
  }

  public String generateToken(String username) {
    Date now = new Date();
    Date validity = new Date(now.getTime() + validityInMilliseconds);

    return Jwts.builder().setSubject(username).setIssuedAt(now).setExpiration(validity)
        .signWith(secretKey).compact();
  }

  public boolean validateToken(String token) {
    try {
      Claims claims = Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token)
          .getBody();
      Date expiration = claims.getExpiration();
      return expiration != null && expiration.after(new Date());
    } catch (Exception e) {
      return false;
    }
  }

  public String getUsernameFromToken(String token) {
    return Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token).getBody()
        .getSubject();
  }

  public Date getExpirationFromToken(String token) {
    return Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token).getBody()
        .getExpiration();
  }
}
