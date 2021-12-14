package com.example.demo.service;

import com.example.demo.dto.MemberDTO;
import com.example.demo.entity.Member;
import com.example.demo.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class MemberService implements UserDetailsService {

    @Autowired //레포지토리 연결
    private final MemberRepository memberrepo;

    //시큐리티에서 사용할 데이터를 재정의
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        System.out.println("EMAIL !! : " + email) ;
        //email이 있는지 없는지 찾음 (시큐티리에서 계정 검증하기 위한 작업 email이 db에 있다면 담아서 전달)
        Optional<Member> result = memberrepo.findByEmail(email);
        //받아온 값이 있다면 result.get()해서 1개를 꺼내오고
        if(result.isPresent())
            return result.get();
        //받아온 값이 없다면 예외 객체를 던져서 처리
        else
            throw new UsernameNotFoundException("Check Email");
    }



    //폼으로부터 전달 받은 데이터를 암호화해서 다시 저장하는 용도
    public void save(MemberDTO dto){

        //객체 생성
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

        //패스워드 암호화 하기(전달된 dto에서 암호화 되지 않은 데이터를 암호화 시키고 다시 넣어주는 작업(encode()사용))
        dto.setPassword(encoder.encode(dto.getPassword()));

        //DTO-Entity (이전과 다르게 인터페이스 생략했기 때문에 여기서 만들어줘야함)
        Member member = Member.builder()
                .email(dto.getEmail())
                .auth(dto.getAuth())
                .password(dto.getPassword())
                .build();

        //DB에 저장 (sava : JPA에서 기본 제공)
        memberrepo.save(member);
    }
}
