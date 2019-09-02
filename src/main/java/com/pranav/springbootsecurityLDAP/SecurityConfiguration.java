package com.pranav.springbootsecurityLDAP;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;


@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {


  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth
      .ldapAuthentication()
      .userDnPatterns("uid={0},ou=people")
      .groupSearchBase("ou=groups")
      .authoritiesMapper(authoritiesMapper())
      .contextSource()
      .url("ldap://localhost:8389/dc=pranavshukla,dc=com")
      .and()
      .passwordCompare()
      .passwordEncoder(new LdapShaPasswordEncoder())
      .passwordAttribute("userPassword");
  }
  /*@Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.inMemoryAuthentication()
      .withUser("blah")
      .password("blah")
      .roles("USER")
      .and()
      .withUser("admin")
      .password("admin")
      .roles("ADMIN");
  }*/

  /*@Bean
  public PasswordEncoder getPasswordEncoder(){
            return NoOpPasswordEncoder.getInstance();
  }*/

  @Bean
  public GrantedAuthoritiesMapper authoritiesMapper(){
    SimpleAuthorityMapper simpleAuthorityMapper = new SimpleAuthorityMapper();
    simpleAuthorityMapper.setConvertToUpperCase(true);
    simpleAuthorityMapper.setDefaultAuthority("USER");
    return simpleAuthorityMapper;
  }


  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests()
      .antMatchers("/").permitAll()
      .and().formLogin();

  }
 /* @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests()
      .antMatchers("/admin").hasRole("ADMIN")
      .antMatchers("/user").hasAnyRole("USER","ADMIN")
      .antMatchers("/").permitAll()
      .and().formLogin();

  }*/
}
