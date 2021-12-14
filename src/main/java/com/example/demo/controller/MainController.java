package com.example.demo.controller;

import com.example.demo.dto.MemberDTO;
import com.example.demo.service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Controller
@RequiredArgsConstructor
public class MainController {

    //서비스는 하단에서 작업처리
    private final MemberService service;

    @GetMapping("/login")
    public String loginpage(){
        return "/login.html";
    }
    @GetMapping("/member")
    public String memberpage(){
        return "/member.html";
    }
    @GetMapping("/admin")
    public String adminpage(){
        return "/admin.html";
    }
    @GetMapping("/")
    public String mainpage(){
        return "/main.html";
    }
    @GetMapping("/join")
    public String joinpage(){
        return "/join.html";
    }

    @PostMapping("/joinproc")
    public String joinprocpage(MemberDTO dto){
        //서비스를 이용해서 전달받은 DTO를 DB로 저장(회원가입 했을 때)
        service.save(dto);
        //저장 후 login.html로 이동
        return "redirect:/login.html";
    }

    @GetMapping("/logout")
    public String logoutpage(HttpServletRequest req, HttpServletResponse resp){
        //로그아웃 처리(핸들러)
        new SecurityContextLogoutHandler().logout(req,resp, SecurityContextHolder.getContext().getAuthentication());
        //로그인페이지로 이동(Http비우고 처리)
        return "redirect:/login.html";
    }
}
//SecurityContextHolder : Userdetails 에서 정의한 내용 저장
//유저에 대한 정보를 꺼내올 수 있음(인증관련 꺼내서 로그아웃)
