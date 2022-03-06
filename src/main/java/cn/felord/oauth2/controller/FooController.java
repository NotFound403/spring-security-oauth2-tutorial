package cn.felord.oauth2.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Map;

/**
 * 测试OAuth2的控制器
 *
 * @author felord.cn
 */
@RestController
public class FooController {

    /**
     * 获取当前认证对象实例{@link Authentication}
     *
     * @return the map
     */
    @GetMapping("/foo/hello")
    public Map<String, Object> foo() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return Collections.singletonMap("authentication",authentication);
    }

    /**
     * 默认登录成功跳转页为 /  防止404状态
     *
     * @return the map
     */
    @GetMapping("/")
    public Map<String, String> index() {
        return Collections.singletonMap("msg", "login success!");
    }
}
