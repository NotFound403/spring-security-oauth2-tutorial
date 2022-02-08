package cn.felord.oauth2.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Map;

/**
 * @author felord.cn
 */
@RestController
@RequestMapping("/foo")
public class FooController {

    @GetMapping("/hello")
    public Map<String,String> foo(){
        return Collections.singletonMap("hello","oauth2");
    }
}
