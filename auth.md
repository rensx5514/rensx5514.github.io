# kubernetes 认证与鉴权与准入控制器


## 1. 认证与鉴权基本介绍
### 几种常见的认证方式
- 证书认证 
- 账户密码认证
- token认证 (JWT token webhook  Oauth2、OpenID token -> OIDC)
- HTTP Basic认证 (key and pwd)
- Authenticating Proxy (http X-Remote-Use)
### 关于认证的个人理解
认证的主要目的是通过检查对象提供的身份凭据，来确认输入对象的具体身份从而为后续的操作做信用保证。 认证是构建应用系统整个信用体系最基础的一个环节，只有通过认证的对象才有访问资源的基本资格。
### 鉴权的基本策略
- ABAC
- RBAC
- Node
## 2.  kubernetes 认证方式
### 认证插件处理流程
kubernetes的认证、授权、准入功能主要由apiserver提供，其中这三个模块分别叫做authentication、authorized、admission 。其中前两个插件authn和authz则在apiserver的config中由默认的handler chain注册并完成对所有api资源的处理。具体流程如下:

```
func DefaultBuildHandlerChain(apiHandler http.Handler, c *Config) http.Handler {
	handler := filterlatency.TrackCompleted(apiHandler)  
	handler = genericapifilters.WithAuthorization(handler, c.Authorization.Authorizer, c.Serializer)  
	handler = filterlatency.TrackStarted(handler, "authorization")
	// ...
	handler = genericapifilters.WithAudit(handler, c.AuditBackend, c.AuditPolicyRuleEvaluator, c.LongRunningFunc)
	// ...
	handler = genericapifilters.WithAuthentication(handler, c.Authentication.Authenticator, failedHandler, c.Authentication.APIAudiences)
}
```
这里可以看到通过apifilters结构将对应的组件Authz和Authn加入到所有资源的handler处理流程中，这里以Authn举例可与看到
```
func withAuthentication(handler http.Handler, auth authenticator.Request, failed http.Handler, apiAuds authenticator.Audiences, metrics recordMetrics) http.Handler {  
  
   return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {  
      // ... 
      resp, ok, err := auth.AuthenticateRequest(req)  
      defer func() {  
         metrics(req.Context(), resp, ok, err, apiAuds, authenticationStart, authenticationFinish)  
      }()  
      // ..
      if !audiencesAreAcceptable(apiAuds, resp.Audiences) {  
         err = fmt.Errorf("unable to match the audience: %v , accepted: %v", resp.Audiences, apiAuds)  
         klog.Error(err)  
         failed.ServeHTTP(w, req)  
         return  
      }  
      // authorization header is not required anymore in case of a successful authentication.  
      req.Header.Del("Authorization")  
   })  
}
```

这里有需要找到在哪里对apiserver的认证和授权方法进行的初始化，如下可以看到在kubeapiserver中的buildGenericConfig函数对关键的authn和authz进行了初始化
```
func buildGenericConfig(  
   s *options.ServerRunOptions,  
   proxyTransport *http.Transport,  
)(...){
	// ...
	// Authentication.ApplyTo requires already applied OpenAPIConfig and EgressSelector if present
	if lastErr = s.Authentication.ApplyTo(&genericConfig.Authentication, genericConfig.SecureServing, genericConfig.EgressSelector, genericConfig.OpenAPIConfig, genericConfig.OpenAPIV3Config, clientgoExternalClient, versionedInformers); lastErr != nil {  
	   return  
	}  
	  
	genericConfig.Authorization.Authorizer, genericConfig.RuleResolver, err = BuildAuthorizer(s, genericConfig.EgressSelector, versionedInformers)  
	if err != nil {  
	   lastErr = fmt.Errorf("invalid authorization config: %v", err)  
	   return  
	}
	// ...
}
```

认证、授权和准入控制器组件分别在pkg/kubeapiserver/组件名称/下
```
func (config Config) New() (authenticator.Request, *spec.SecurityDefinitions, error) {  
   var authenticators []authenticator.Request  
   var tokenAuthenticators []authenticator.Token  
   securityDefinitions := spec.SecurityDefinitions{}  
  
   // front-proxy, BasicAuth methods, local first, then remote  
   // Add the front proxy authenticator if requested   if config.RequestHeaderConfig != nil {  
      requestHeaderAuthenticator := headerrequest.NewDynamicVerifyOptionsSecure(  
         config.RequestHeaderConfig.CAContentProvider.VerifyOptions,  
         config.RequestHeaderConfig.AllowedClientNames,  
         config.RequestHeaderConfig.UsernameHeaders,  
         config.RequestHeaderConfig.GroupHeaders,  
         config.RequestHeaderConfig.ExtraHeaderPrefixes,  
      )  
      authenticators = append(authenticators, authenticator.WrapAudienceAgnosticRequest(config.APIAudiences, requestHeaderAuthenticator))  
   }  
  
   // X509 methods  
   if config.ClientCAContentProvider != nil {  
      certAuth := x509.NewDynamic(config.ClientCAContentProvider.VerifyOptions, x509.CommonNameUserConversion)  
      authenticators = append(authenticators, certAuth)  
   }
   // ...
}
```

### 用户及用户组
kubernetes集群有两类用户，一种叫做普通账户，另一种叫做服务账户。
- 普通账户
一类用户由外部维护，kubernetes仅在认证阶段识别读取用户名称，kubernetes本身无法保存用户的任何信息，以证书认证举例，Kubernetes 使用证书中的 'subject' 的通用名称（Common Name）字段 （例如，"/CN=bob"）来确定用户名，Organization 来确定用户组，然后基于内部的授权系统(默认一般为RBAC)来负责给该用户添加访问资源的权限。Proxy认证和BasicAuth则会从http header中读取用户和用户组关键字。
- 服务账户
另外一类账户为服务账户由kubernetes管理并保存用户的基本信息，服务账户一般含有命名空间的约束，并且可以被自动创建并将服务账户的凭据(一般是存储在secret的Token字段)挂载到Pod中。
- 两个特殊用户
特殊管理员用户: 集群默认提供一个system:admin的管理员账户的授权，该用户可以通过集权默认的管理员授权进行任何资源的访问。
特殊匿名用户:当访问apiserver中提供的资源而不通过任何的身份认证时，该用户被视为匿名用户 system:anonymous
### x509 证书认证
- 证书认证基本概念
- x509规范
- 数据包分析证书交换
- *一图读懂k8s基础组件证书认证流程*
- kubernetes 自动证书轮转
- kubernetes 手动证书轮转
### token 认证
>  *bootstrap* token属于Bearer Token的一种，主要包含token ID和 token secret, 默认使用的用户和用户组为`system:bootstrap:<token id>`、 `system:bootstrappers` ，其中也可以通过auth-extra-groups字段为 bootstrap token 指定额外的用户组 。
> 除了身份认证，token还可以用做签名configmap, 从而实现通过使用后被签名的configmap完成认证。其中最典型的就是使用kubeadm 部署集群时保留的cluster-info中含有这个该签名认证，签名算法使用的是JWS签名，具体流程见参考3
> 
> *OpenID Conect Token* 通过使用Oauth2的服务器对请求进行认证，然后将请求通过赋予Bear Token的方式在apiserver获得认证结果
> 
> Static token 这以apiserver 的参数 --token-auth-file=file 指定一个csv文件包含具体的token列表，api请求通过携带列表中符合列表的token来进行认证，一般格式为{token id, group, user}
>
> 
### basic auth 认证
通过在启动的时候提供 --basic-authfile=file来实现，basic auth file主要是包含一系列的包含用户名、密码的文件列表

### 认证例子
## 3. kubernetes 鉴权方式
#### ABAC
通过 --authorization-policy-file=file指定策略文件，通过指定用户对资源的权限列表，在用户访问时进行授权。其中使用ABAC需要考虑服务账户等配置，服务账户的默认名称如下
```
system:serviceaccount:<namespace>:<serviceaccountname>
```

### RBAC
#### Node
节点鉴权是一种特殊用途的鉴权模式，专门对 kubelet 发出的 API 请求进行鉴权。节点鉴权器会检查kubelet对apiserver的访问请求，其中包括读取 services、endpoints、nodes、pods、secrets、configmaps、pvc以及绑定到pod相关的其他持久卷，写入则包括节点及节点状态、Pod及Pod状态、事件，其中Node授权方式主要和`NodeRestriction`准入控制器配合使用，`NodeRestriction`通过实现对访问ip的检查来限制只允许本地节点执行本地的权限。
#### AlwaysAllow 
#### AlwaysDeny
#### Webhook
##### 查看资源访问权限的方式
> 	方式一： 检查pod确认用户->确认用户组->找到对应的权限绑定(clusterRolebinding、rolebinding) -> 找到对应角色 -> 确认资源权限
> 	
> 
> 	方式二：

## 4. kubernetes 准入控制器
#### PSA  （1.21）
PSA的全名叫做PodSecurityAdmission
#### NamespaceLifecycle
#### LimitRanger
#### PodNodeSelector
#### AlwaysDeny
#### 默认启用的准入控制器插件
```
CertificateApproval, CertificateSigning, CertificateSubjectRestriction, DefaultIngressClass, DefaultStorageClass, DefaultTolerationSeconds, LimitRanger, MutatingAdmissionWebhook, NamespaceLifecycle, PersistentVolumeClaimResize, PodSecurity, Priority, ResourceQuota, RuntimeClass, ServiceAccount, StorageObjectInUseProtection, TaintNodesByCondition, ValidatingAdmissionWebhook
```


## 参考
[1] [Authenticating | Kubernetes](https://kubernetes.io/docs/reference/access-authn-authz/authentication/)
[2] [一文带你彻底厘清 Kubernetes 中的证书工作机制 - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/142990931)
[3] [使用启动引导令牌（Bootstrap Tokens）认证 | Kubernetes](https://kubernetes.io/zh-cn/docs/reference/access-authn-authz/bootstrap-tokens/)
[4] [Kubernetes 认证 _ Kubernetes(K8S)中文文档_Kubernetes中文社区](http://docs.kubernetes.org.cn/51.html)
[5] [使用 ABAC 鉴权 | Kubernetes](https://kubernetes.io/zh-cn/docs/reference/access-authn-authz/abac/)
[6] [使用准入控制器 | Kubernetes](https://kubernetes.io/zh-cn/docs/reference/access-authn-authz/admission-controllers/)
