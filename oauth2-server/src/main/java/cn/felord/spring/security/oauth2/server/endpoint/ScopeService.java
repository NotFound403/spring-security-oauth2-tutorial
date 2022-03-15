package cn.felord.spring.security.oauth2.server.endpoint;

import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 模拟查询scope信息
 *
 * @author felord.cn
 */
@Component
public class ScopeService {
    private static final Map<String, OAuth2Scope> SCOPES = new HashMap<>();

    static {
        OAuth2Scope scope = new OAuth2Scope();
        scope.setScope("message.read");
        scope.setDescription("应用将能够获取你的个人信息读取权限");
        OAuth2Scope scope1 = new OAuth2Scope();
        scope1.setScope("message.write");
        scope1.setDescription("应用将能够对你的个人信息进行写、修改、删除操作");

        SCOPES.put(scope.getScope(), scope);
        SCOPES.put(scope1.getScope(), scope1);

    }

    /**
     * 模拟持久化接口
     *
     * @param names
     * @return
     */
    public Set<OAuth2Scope> findScopesByNames(Set<String> names) {
        return names.stream()
                .map(SCOPES::get)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
    }

}
