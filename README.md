# *JWT实现原理 (基于pyjwt框架源码)*

## *JWT的生成规则*

- `Header`

  ```python
  # 算法和token类型，对此json调用 base64url函数 加密，这就是token的第一段
  {
    "alg": "HS256", #算法类型
    "typ": "JWT"    #token类型
  }
  ```

- `Payload`

  ```python
  #再次调用 base64url 函数加密，这就是token的第二段
  {
    "id": "1234567890", #自定义字段
    "name": "John Doe", #自定义字段
    "exp": 1516239022   #token过期时间
    ...
  }
  ```

- `Signature`

  ```python
  #把前两段的base密文通过.拼接起来，然后对其进行HS256加密，再然后对hs256密文进行
  #base64url加密，最终得到token的第三段。
  base64url(
      HMACSHA256(
        base64UrlEncode(header) + "." + base64UrlEncode(payload),
        salt(秘钥加盐)
      )
  )
  ```

- `Header.Payload.Signnature`

## *PYjwt认证流程*

```python
一般在认证成功后，把jwt生成的token返回给用户，以后用户再次访问时候需要携带token，此时jwt需要对token进行超时及合法性校验。

获取token之后，会按照以下步骤进行校验：
将token分割成 header_segment、payload_segment、crypto_segment 三部分

jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

signing_input, crypto_segment = jwt_token.rsplit(b'.', 1)
header_segment, payload_segment = signing_input.split(b'.', 1)

对第一部分header_segment进行base64url解密，得到header
对第二部分payload_segment进行base64url解密，得到payload
对第三部分crypto_segment进行base64url解密，得到signature

对第三部分signature部分数据进行合法性校验

拼接前两段密文，即：signing_input
从第一段明文中获取加密算法，默认：HS256
使用 算法+盐 对signing_input 进行加密，将得到的结果和 signature密文进行比较。
```

# *JWT + DRF快速认证*

## 创建*token*

- `调用jwt.encode函数`

## *py jwt验证 jwt*

- `调用jwt.decode函数`

- `返回payload or 异常信息`

## *认证组件 (当然也可以在中间件使用)*

```python
from rest_framework.authentication import BaseAuthentication

class JwtQueryParamAuthentication(BaseAuthentication):
    """
    用户需要在url中通过参数进行传输token，
    """

    def authenticate(self, request):
        token = request.query_params.get('token')
        #调用jwt.decode()函数验证token
        payload = parse_payload(token)  				
        if not payload['status']:
            raise exceptions.AuthenticationFailed(payload)

        # request.user = payload
        # request.auth = token
        # user_id = payload["user_id"] 也可以去数据库查到user对象并赋值给 request.user
        return (payload, token)
```

## *全局配置*

```python
#RDF APIView 源码默认设置认证类 
"DEFAULT_Authentication_CLASS"

REST_FRAMEWORK = {
    "DEFAULT_Authentication_CLASS": 'jwt-auth类的路径',
}

#当然某些域名不需要认证的话,只需要在视图中
Authentication_CLASS = []
```

