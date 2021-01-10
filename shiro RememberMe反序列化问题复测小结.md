# Shiro RememberMe反序列化问题复测小结

# 前言

几个月前处理了一起某客户处产生的Shiro反序列化漏洞问题，暂时做一下记录，并简单说明一下在和第三方厂商相关人员沟通中产生的问题

# Shiro反序列化概述

Shiro提供了RememberMe的功能，即在关闭浏览器之后重新打开仍能记住登录状态，下次访问时无需重新登录即可访问

漏洞成因详见：https://paper.seebug.org/shiro-rememberme-1-2-4/

其实该漏洞由于设置不当引起，任何版本的shiro使用默认秘钥均会引起反序列化问题，可直接获取root权限

![image-20210110132913284](https://github.com/index2014/notes/blob/main/img/shiro2.png?raw=true)

![image-20210110133117299](https://github.com/index2014/notes/blob/main/img/shiro4.jpg?raw=true)

# Shiro的RememberMe功能配置

Shiro版本shiro-core-1.4.0.jar

用户这里使用的xml对shiro功能进行配置

Source Code is following:

```xml
     <!-- 30天 -->

  <bean id="rememberMeCookie" class="org.apache.shiro.web.servlet.SimpleCookie">

​    <constructor-arg value="rememberMe"/>

​    <property name="httpOnly" value="true"/>

​    <property name="maxAge" value="2592000"/>

​    <property name="domain" value=""/>

​    <property name="path" value="/"/>

  </bean>

 

  <!-- rememberMe管理器 -->

  <!-- rememberMe cookie加密的密钥 建议每个项目都不一样 默认AES算法 密钥长度（128 256 512 位）-->

  <bean id="rememberMeManager" class="org.apache.shiro.web.mgt.CookieRememberMeManager">

​    <property name="cipherKey"

​         value="#{T(org.apache.shiro.codec.Base64).decode('4AvVhmFLUs0KTA3Kprsdag==')}"/>

​    <property name="cookie" ref="rememberMeCookie"/>

  </bean>

​     <!-- 原配置-->

​     <bean id="sessionDAO" class="net.ntvu.common.shiro.RedisSessionDAO">

​       <property name="redisManager" ref="redisManager" />

​       <property name="keyPrefix" value="${redis.session.prefix}" />

​     </bean>

​     <!-- 原配置-->
```

注册SecurityManager

```xml
  <!-- 安全管理器 -->

  <bean id="securityManager" class="org.apache.shiro.web.mgt.DefaultWebSecurityManager">

​    <property name="realm" ref="userRealm"/>

​    <property name="sessionManager" ref="sessionManager"/>

​          <property name="cacheManager" ref="cacheManager"></property>

​    <property name="rememberMeManager" ref="rememberMeManager"/>

  </bean>

 

  <!-- 相当于调用SecurityUtils.setSecurityManager(securityManager) -->

  <bean class="org.springframework.beans.factory.config.MethodInvokingFactoryBean">

​    <property name="staticMethod" value="org.apache.shiro.SecurityUtils.setSecurityManager"/>

​    <property name="arguments" ref="securityManager"/>

  </bean>
```

添加到filter

```xml
     <bean id="shiroFilter" class="org.apache.shiro.spring.web.ShiroFilterFactoryBean">

​          <property name="securityManager" ref="securityManager" />

​          <!-- The 'filters' property is not necessary since any declared javax.servlet.Filter

​              bean defined will be automatically acquired and available via its beanName 

​              in chain definitions, but you can perform overrides or parent/child consolidated 

​              configuration here if you like: -->

​          <property name="filters">

​              <map>

​                   <entry key="login" value-ref="login"></entry>

​              </map>

​          </property>

​          <property name="filterChainDefinitions">

​              <value>

​                   /login/in = anon

​                   /dist/** = anon

​                   /xgapp/** = anon

​                   /fw/columns = anon

​                   /app/** = anon

​                   /ComDictionary/query = anon

​                   /app/file/qrcode = anon

​                   /ComDictionary/** = anon

​                   /login/forCas = anon

​                   /login//forAuth = anon

​                   /stest/** = anon

​                   /wx/** = anon

​                   /ajssdk/ticket = anon

​                   /index.jsp = anon

​                   <!-- /** = authc 部分页面必须要用户登陆才允许使用 -->

​                   /** = login

​                   

​              </value>

​          </property>

​     </bean>
```

# 问题发现

已经可以从源代码中发现问题，配置rememberme管理器时，使用了默认秘钥

```xml
 <!-- rememberMe cookie加密的密钥 建议每个项目都不一样 默认AES算法 密钥长度（128 256 512 位）-->

  <bean id="rememberMeManager" class="org.apache.shiro.web.mgt.CookieRememberMeManager">

​    <property name="cipherKey"

​         value="#{T(org.apache.shiro.codec.Base64).decode('4AvVhmFLUs0KTA3Kprsdag==')}"/>

​    <property name="cookie" ref="rememberMeCookie"/>

  </bean>
```

# 给出的解决方案

修改其中秘钥为私有秘钥，或者使用动态秘钥生成器

添加动态秘钥生成器：

```java
public class GenerateCipherKey {

 

  /**

   \* 随机生成秘钥，参考org.apache.shiro.crypto.AbstractSymmetricCipherService#generateNewKey(int)

   \* @return

   */

  public static byte[] generateNewKey() {

​    KeyGenerator kg;

​    try {

​      kg = KeyGenerator.getInstance("AES");

​    } catch (NoSuchAlgorithmException var5) {

​      String msg = "Unable to acquire AES algorithm. This is required to function.";

​      throw new IllegalStateException(msg, var5);

​    }

 

​    kg.init(128);

​    SecretKey key = kg.generateKey();

​    byte[] encoded = key.getEncoded();

​    return encoded;

  }

}
```

将配置文件修改为：

```xml
<bean id="rememberMeManager" class="org.apache.shiro.web.mgt.CookieRememberMeManager">

​          <property name="cipherKey" value="#{T(com.xxx.xxx.xxx.xxx.GenerateCipherKey).generateNewKey()}"></property>

​          <property name="cookie" ref="rememberMe"></property>

​     </bean>
```

最终解决方案：

修改为私有固定秘钥，如若密钥被泄露，仍然有安全问题

# 和第三方沟通中产生的问题

从代码的注释中，可以得知第三方人员是完全照抄的代码段，该代码段中提及的修改，第三方人员并没有注意到

在给出方案后，要求第三方进行漏洞修补修补时，第三方人员一再怀疑我方提出的修补方案，并且表示不知道为什么要进行修改

下图为第三方在默认环境下给出的关闭服务脚本

![img](https://github.com/index2014/notes/blob/main/img/shiro3.jpg?raw=true)

第三方给出的shutdown.sh

脚本中第三方人员写入了删除tomcat工作目录下关于第三方提供的web应用程序所有文件的命令：

```bash
rm -rf /opt/xgxt/tomcat/webapps/*

rm -rf /opt/xgxt/tomcat2/webapps/*
```

虽说发现及时未对漏洞修补带来影响，但是这样的行为实在是让人心寒

幸好第三方人员最后还是在我方的一再催促下针对给出的修复意见进行了修复

# 一般化建议

推荐各甲方公司/单位在系统上线前进行上线前安全检查，代码审计工作

严格审查第三方人员资质，签署保密协议，要求其具有一定安全意识