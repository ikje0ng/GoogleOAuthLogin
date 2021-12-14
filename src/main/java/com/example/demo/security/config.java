package com.example.demo.security;

import com.example.demo.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class config extends WebSecurityConfigurerAdapter {

    //멤버변수
    @Autowired
    private final MemberService service;

    //암호화해서 저장
    @Bean
    PasswordEncoder passwordencoder(){
        //특정한 암호화 객체 생성
        return new BCryptPasswordEncoder();
    }

    

    //로그인 요청하게 되면 서비스의 UserDetails에서 email정보 받고 입력한 이메일과 저장된 이메일 비교
    //(loadUserByUsername은 시큐리티 configur가 사용)
    @Override //인증관련 작업
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        //id는 서비스를 통해 받아옴, member서비스에서 만들어 둔 (loadUserByUsername) 여기서 id를 찾음
        auth.userDetailsService(service).passwordEncoder(passwordencoder());

        //계정을 직접 넣는 작업 임의로 작성
//        //기본 패스워드는 암호화된 패스워드 넣어줘야 됨(인코더되서 암호화되서 전달되기 때문)
//        auth.inMemoryAuthentication().withUser("user1")
//                .password("$2a$10$wlilyJ.DVpWBvbIWmHTJ2ORgA.BTc2XhuuDltNFm4P3zJ8Uw3MRYS")
//                .roles("USER")
//                .and()
//                .withUser("user2")
//                .roles("ADMIN")
//                .password("$2a$10$wlilyJ.DVpWBvbIWmHTJ2ORgA.BTc2XhuuDltNFm4P3zJ8Uw3MRYS");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //접근 권한 요청
        http.authorizeRequests()
                //로그인 페이지 모두 접근 가능
                .antMatchers("/login","/join","/joinproc").permitAll()
                //일반 유저 페이지 (특정한 그룹에 포함되어 있어야 가능(Role값 = USER역할을 하고 있는 계정)
                .antMatchers("/member").hasRole("USER")
                //관리자 페이지는 ADMIN을 갖고 있어야 함
                .antMatchers("/admin").hasRole("ADMIN")
                //나머지 리퀘스트는 전부 다 권한이 있는 경우만 허용
                .anyRequest().authenticated();


        //로그인(기본 디폴트 활성화(어떤 url을 입력하던 간 login으로 가도록))
        http.formLogin() // < 얘만 작성하면 기본폼만 적용됨
                //지정된 로그인 폼 사용
                .loginPage("/login")
                //로그인 성공하면 기본적으로 이동될 페이지 넣음(컨트롤러에 메인페이지로 이동되도록 맵핑했음)
                .defaultSuccessUrl("/");

        //로그아웃
        http.logout()
                .logoutSuccessUrl("/login") //로그아웃 성공시 리다이렉트 주소
                .invalidateHttpSession(true);//세션제거

        //oAuth2 인증
        http.oauth2Login()
                .loginPage("/login")
                .defaultSuccessUrl("/");


        //시큐리티는 csrf공격 방어하기 위해(토큰 값을 전달하지 않도록 잠깐 꺼 놓은 것)
        http.csrf().disable();
    }




}
