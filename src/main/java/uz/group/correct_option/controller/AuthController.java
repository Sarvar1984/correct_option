package uz.group.correct_option.controller;

import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth/login")
public class AuthController {

    @PostMapping("/log")
    public HttpEntity<?>log(){
        return ResponseEntity.ok("log bajarildi");
    }

    @PostMapping("/reg")
    public HttpEntity<?>register(){
        return ResponseEntity.ok("reg bajarildi");
    }

}
