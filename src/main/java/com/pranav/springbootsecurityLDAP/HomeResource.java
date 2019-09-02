package com.pranav.springbootsecurityLDAP;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeResource {

  @GetMapping("/")
  public String home() {
        return ("<h1>Welcome</h1>");
    }

  @GetMapping("/user")
  @PreAuthorize("hasRole('ROLE_USER')")
  public String user() {
    return ("<h1>Welcome user</h1>");
  }

  @GetMapping("/admin")
  @PreAuthorize("hasRole('ROLE_ADMIN')")
  public String admin() {
    return ("<h1>Welcome Admin</h1>");
  }
}
