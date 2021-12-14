package com.example.demo.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.persistence.*;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

//UserDetails : 사용자의 정보를 담는 인터페이스


@Entity
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(name = "tbl_member")
//UserDetails: 사용자에 대한 정보를 담는 용도
public class Member implements UserDetails {

    @Id //PK
    @GeneratedValue(strategy= GenerationType.IDENTITY) //자동증가
    private Long num;

    @Column(name="email",unique=true) //unique:중복값 허용 X
    private String email;

    @Column(name="password")
    private String password;

    @Column(name="auth") //역할정보
    private String auth;

    //생성자 생성 (@Builder : 위치 바꿔도 상관없이 마음대로 사용하겠다.)
    @Builder
    public Member(String email, String password, String auth){
        this.email=email;
        this.password=password;
        this.auth=auth;
    }

    //시큐리티에서 사용
    //Collection : 역할 정보를 db로부터 가져올 때 사용 (중복 허용하지 않은 Hashset형을 사용함)
    //GrantedAuthority : 시큐리티에서 기본적으로 제공하는 클래스형만 제네릭타입으로 지정 가능
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        //제네릭타입의 컬렉션 객체 생성 (DB로부터 역할 저장용)
        Set<GrantedAuthority> roles = new HashSet();

        //반복문을 통해 받은 녀석을 DB를 가지고 올수 있도록 (콤바를 기준으로 잘라내 role로 들어가도록)
        for(String role : auth.split(","))//전달받은 role문자열을 ,(콤마)기준으로 분할해서 각 role에 전달
        {
            //SimpleGrantedAuthority객체에 초기값을 역할명으로 전달하고 위에서 생성한 set의 roles에 추가
            //(SimpleGrantedAuthority:기본으로 제공)
            roles.add(new SimpleGrantedAuthority(role));
        }
        return roles;
    }

    
    //UserDetails로부터 물려받은 것
    @Override
    public String getUsername() {
        return email;
    }

    public String getPassword(){
        return password;
    }

    //사용가능한가?  > true로 지정
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
