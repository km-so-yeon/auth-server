package com.auth_server.auth.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AuthController {

    /**
     * 로그인 화면 리턴
     * @return 로그인 화면
     */
    @GetMapping("/login")
    public String login() {
        return "login";
    }
}
