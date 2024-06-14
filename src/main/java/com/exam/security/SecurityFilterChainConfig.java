package com.exam.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityFilterChainConfig {
	
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
		http.authorizeRequests().antMatchers("/home","/login","/signup","/webjars/**","images/**").permitAll().anyRequest().authenticated();
		http.formLogin().loginPage("/login").loginProcessingUrl("auth").usernameParameter("userid").passwordParameter("passwd").failureForwardUrl("/login_fail").defaultSuccessUrl("/login_success",true);
		http.csrf().disable();
		http.logout().logoutUrl("/logout").logoutSuccessUrl("home");
		//.successForwardUrl("/login_success")
		return http.build();
	}
}
