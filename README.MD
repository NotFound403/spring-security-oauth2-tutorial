## Spring Security OAuth2相关教程


#### Spring Authorization Server自定义授权确认页面DEMO

- 依次启动授权服务器、客户端
- 打开浏览器，然后F12，清理网络日志
- 浏览器访问`http://127.0.0.1:8082/foo/bar`
- 你会观察到一个302重定向到授权服务器登录页面

PKCE:
```
http://localhost:9000/oauth2/authorize?response_type=code&client_id=felord&scope=message.read message.write&state=46ge_TeI-dHuAnyv67nVmCcAmFgCVSZAqjTi9Om-1aA=&redirect_uri=http://127.0.0.1:8082/foo/bar&code_challenge=KJlktPdfHdPPenXDN3HARjV6pzM7ljfHs-L-bFao3zM&code_challenge_method=S256
```

详细说明参见[Spring Security 与 OAuth2](https://blog.csdn.net/qq_35067322/category_11691173.html)专题教程

<img src="tutorial.png" style="zoom:75%;" />