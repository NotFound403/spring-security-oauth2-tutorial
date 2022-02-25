package cn.felord.oauth2.wechat;

import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.*;

/**
 * 微信授权的OAuth2User用户信息
 *
 * @author  felord.cn
 * @since 2021/8/12 17:37
 */
@Data
public class WechatOAuth2User implements OAuth2User {
    private  Set<GrantedAuthority> authorities;
    private String openid;
    private String nickname;
    private Integer sex;
    private String province;
    private String city;
    private String country;
    private String headimgurl;
    private List<String> privilege;
    private String unionid;


    @Override
    public Map<String, Object> getAttributes() {
       //todo 这里放一些有用的额外参数
        return Collections.emptyMap();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        //todo 微信用户你想赋权的可以在这里或者set方法中实现。
        return this.authorities;
    }

    @Override
    public String getName() {
        // todo 根据业务需要调整
        return openid;
    }
}
