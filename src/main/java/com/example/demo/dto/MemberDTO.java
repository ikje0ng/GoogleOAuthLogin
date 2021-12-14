package com.example.demo.dto;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Map;

@Getter
@Setter
public class MemberDTO extends User implements OAuth2User {
    private String email;
    private String password;
    private String auth;

    //추가(oauth2user에서 사용하기 위함)
    private Map<String,Object> attr;

    public MemberDTO(
            String email,
            String password,
            Collection<? extends GrantedAuthority> authorities,
            Map<String,Object>attr
    )
    {
        super(email, password, authorities);
        this.email = email;
        this.password=password;
        this.attr=attr;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attr;
    }

    @Override
    public String getName() {
        return email;
    }
}

