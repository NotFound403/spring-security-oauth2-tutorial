package cn.felord.spring.security.oauth2.server;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/oauth2")
public class UserInfoController {

    @GetMapping("/user")
    public Authentication oauth2Userinfo() {
        Authentication authentication =   SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            throw new RuntimeException("这个地方想办法处理401");
        }
        return authentication;
    }

}
