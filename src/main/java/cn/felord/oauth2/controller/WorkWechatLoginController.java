package cn.felord.oauth2.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Map;

@RestController
@RequestMapping("/wwechat")
public class WorkWechatLoginController {


    @GetMapping("/callback")
    public Map<String, Object> login(@RegisteredOAuth2AuthorizedClient("work-wechat-scan")
     OAuth2AuthorizedClient oAuth2AuthorizedClient) {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("authentication = " + authentication);
        return Collections.singletonMap("result",oAuth2AuthorizedClient);
    }
}
