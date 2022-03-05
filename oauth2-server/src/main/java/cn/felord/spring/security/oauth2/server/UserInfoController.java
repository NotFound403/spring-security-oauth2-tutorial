package cn.felord.spring.security.oauth2.server;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 用户信息接口
 *
 * @author felord.cn
 */
@RestController
@RequestMapping("/oauth2")
public class UserInfoController {
    /***
     * 获取用户信息，需要根据业务设计，这里仅供演示
     *
     * 需要{@code  SCOPE_userinfo}权限
     * @return authentication info
     */
    @GetMapping("/user")
    public Authentication oauth2Userinfo() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            throw new RuntimeException("这个地方想办法处理401");
        }
        return authentication;
    }

}
