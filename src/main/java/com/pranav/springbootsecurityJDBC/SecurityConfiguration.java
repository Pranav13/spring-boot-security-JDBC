package com.pranav.springbootsecurityJDBC;

import com.pranav.springbootsecurityJDBC.auth.JDBCUserDetailService;
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


@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

  @Autowired
  JDBCUserDetailService landonUserDetailService;

  @Bean
  public DaoAuthenticationProvider authenticationProvider(){
    DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
    provider.setUserDetailsService(landonUserDetailService);
    provider.setPasswordEncoder(new BCryptPasswordEncoder());
    provider.setAuthoritiesMapper(authoritiesMapper());
    return provider;
  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.authenticationProvider(authenticationProvider());
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
