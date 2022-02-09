package cn.felord.oauth2.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * The type Foo controller.
 *
 * @author felord.cn
 */
@RestController
@RequestMapping("/foo")
public class FooController {

    /**
     * Foo map.
     *
     * @param client the client
     * @return the map
     */
    @GetMapping("/hello")
    public Map<String, Object> foo(@RegisteredOAuth2AuthorizedClient("gitee") OAuth2AuthorizedClient client) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Map<String, Object> map = new HashMap<>(2);
        map.put("client", client);
        map.put("authentication", authentication);
        return map;
    }
}
