package cn.felord.resource.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Map;

@RestController
@RequestMapping("/res")
public class ResourceApi {



    @GetMapping("/foo")
    public Map<String,String> foo(@AuthenticationPrincipal Jwt jwt){
        System.out.println("jwt = " + jwt.getClaims());
        return Collections.singletonMap("hello","world");
    }
}
