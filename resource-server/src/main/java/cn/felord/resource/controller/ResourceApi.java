package cn.felord.resource.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Map;

@RestController
@RequestMapping("/res")
public class ResourceApi {



    @GetMapping("/foo")
    public Map<String,Object> foo(@CurrentSecurityContext(expression="authentication") Authentication authentication){
        return Collections.singletonMap("hello",authentication.getAuthorities());
    }
}
