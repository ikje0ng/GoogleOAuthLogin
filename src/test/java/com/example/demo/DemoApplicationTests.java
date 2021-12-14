package com.example.demo;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootTest
class DemoApplicationTests {

    @Autowired //참조변수에 대한 객체가 생성되서 전달 됨
    private PasswordEncoder passwordencoder;

    @Test
    public void func1(){
        //encode메서드 사용 (문자열 데이터의 형태를 해쉬 알고리즘에 의해서 알 수 없는 특정한 값으로 반환 - db값 삽입)
        String pwd="1234";
        System.out.println(passwordencoder.encode(pwd));

        //외부에서 입력한 데이터와 저장되어있는 데이터 비교 후 result에 저장(true, false결과 반환)
        //(rawPassWord : 입력받은 비번, 저장된 비번)
        boolean result = passwordencoder.matches("1234",passwordencoder.encode(pwd));
        System.out.println("결과 확인 : " + result);
    }

}
