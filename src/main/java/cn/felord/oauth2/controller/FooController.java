package cn.felord.oauth2.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * 测试OAuth2的控制器
 *
 * @author felord.cn
 */
@RestController
public class FooController {

    /**
     * 获取当前的OAuth2 Client对象实例{@link OAuth2AuthorizedClient}
     * 和当前认证对象实例{@link Authentication}
     *
     * @param giteeOauth2client the gitee Oauth2 client
     * @return the map
     */
    @GetMapping("/foo/hello")
    public Map<String, Object> foo(@RegisteredOAuth2AuthorizedClient
                                           OAuth2AuthorizedClient giteeOauth2client) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Map<String, Object> map = new HashMap<>(2);
        map.put("giteeOauth2client", giteeOauth2client);
        map.put("authentication", authentication);
        return map;
    }

    /**
     * 默认登录成功跳转页为 /  防止404状态
     *
     * @return the map
     */
    @GetMapping("/")
    public Map<String, String> index() {
        return Collections.singletonMap("msg", "oauth2Login success!");
    }
}
