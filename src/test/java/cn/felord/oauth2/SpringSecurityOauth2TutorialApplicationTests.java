package cn.felord.oauth2;

import cn.felord.oauth2.wechat.WechatOAuth2UserService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.GenericTypeResolver;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;

@SpringBootTest
class SpringSecurityOauth2TutorialApplicationTests {

    @Test
    void contextLoads() {
    }

    public static void main(String[] args) {


        Class<WechatOAuth2UserService> clazz = WechatOAuth2UserService.class;



        Class<?>[] classes = GenericTypeResolver.resolveTypeArguments(clazz, OAuth2UserService.class);

        System.out.println("classes = " + classes[0]);
    }
}
