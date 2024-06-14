package com.exam.security;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import com.exam.dto.Member;
import com.exam.service.MemberService;

@Component
public class AuthProvider implements AuthenticationProvider {
	
	@Autowired
	MemberService memberService;
	
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		String userid = (String)authentication.getPrincipal();
		String passwd = (String)authentication.getCredentials();
		
		Member mem = memberService.findById(userid);
		String encrptPw = mem.getPasswd();
		
		UsernamePasswordAuthenticationToken token=null;
		if(mem!=null && new BCryptPasswordEncoder().matches(passwd, encrptPw)) {
			List<GrantedAuthority> list = new ArrayList<>();
			list.add(new SimpleGrantedAuthority("USER"));
			mem.setPasswd(passwd);
			token = new UsernamePasswordAuthenticationToken(mem, null, list);
			return token;
		}
		throw new BadCredentialsException("비밀번호가 일치하지 않습니다.");
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return true;
	}

}
