package com.example.demo.repository;

import com.example.demo.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member,Long> {

    //email을 조건절로 계정 찾기 (email을 찾아서 해당 행 데이터를 가져옴)
    Optional<Member> findByEmail(String email);
}
