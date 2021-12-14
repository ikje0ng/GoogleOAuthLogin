package com.example.demo.service;

import com.example.demo.dto.MemberDTO;
import com.example.demo.entity.Member;
import com.example.demo.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Service
@Log4j2
@RequiredArgsConstructor
public class OauthUserService extends DefaultOAuth2UserService {

    //Repo, Encoder 추가(계정에 대한 정보 저장 작업을 위한)
    private final MemberRepository memberrepo;
    private final PasswordEncoder passwordEncoder;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        log.info("------OAuth-loadUser------------");
        log.info("userRequest : " + userRequest);
        //등록정보를 꺼내서 그 중에서 클라이언트 여러 정보들 중 이름 꺼냄
        log.info("ClientName : " + userRequest.getClientRegistration().getClientName());
        log.info("ClientId : " + userRequest.getClientRegistration().getClientId());

        //상위 클래스(DefaultOAuth2UserService) 생성자 중 loadUser의 함수를 받아서 (userRequest) 확인
        OAuth2User oauth2user = super.loadUser(userRequest);
        //email
        log.info("EMail : " + oauth2user.getAttribute("email"));
        log.info(oauth2user.getAttributes());

        //DB에 google계정 저장
        Member member = saveSocialMember(oauth2user.getAttribute("email"));

        //Email 정보 제대로 보여주게 하기
        //Role꺼내기(시큐리티에 맞게)
        Set<GrantedAuthority> set = new HashSet<>();
        //member.getAuth() : DB에서 꺼내온 Auth 
        SimpleGrantedAuthority role = new SimpleGrantedAuthority(member.getAuth());
        //DB에서 꺼내온 Auth set에 추가
        set.add(role);

        //DTO에 Entity 내용 저장
        MemberDTO dto = new MemberDTO(
                member.getEmail(),
                member.getPassword(),
                set,
                oauth2user.getAttributes()
        );

        //DTO리턴 (리턴될 수 있는 이유는 상속관계를 만들어뒀기 때문)
        return dto;
    }


    //DB에 google계정 저장용 함수(loadUser에서 사용)
    private Member saveSocialMember(String email){
        //email이 있는지 없는지 찾음
        Optional<Member> result = memberrepo.findByEmail(email);
        if(result.isPresent()){
            return result.get();    //있으면 바로 리턴 (없으면 아래 작업에서 저장하고 리턴)
        }
        //현재 DB에 해당 계정 저장 안 되어있음

        //Entity에 정보 저장(전달받은 email 넣어주고 password는 암호화(encode)시켜 넣어줌)
        Member member = Member.builder()
                .email(email)
                //비밀번호는 1111로 지정
                //구글로그인 한번 하고 나면 링크 안 누르고 계정 입력 후 비번 1111입력하면 로그인 됨
                .password(passwordEncoder.encode("1111"))
                .auth("ROLE_USER")  //역할은 ROLE_USER로 지정
                .build();
        //DB에 저장
        memberrepo.save(member);
        return member;
    }

}
