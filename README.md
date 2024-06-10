# API 호출

(리다이렉트할 리소스 서버 URL 예시: http://localhost:3030)

## 코드발급 URL

http://localhost:8080/oauth2/authorize?response_type=code&client_id=oidc-client&scope=openid&redirect_uri=http://localhost:3000


## 토큰 요청

```
POST http://localhost:8080/oauth2/token
```

- Authorization 설정(Basic Auth)
  - username: oidc-client
  - password: secret
- body 설정(x-www-form-urlencoded)
  - grant_type: authorization_code
  - code: 코드발급 URL에서 받은 코드
  - scope: openid
  - redirect_uri: http://localhost:3000


## 토큰 갱신

```
POST http://localhost:8080/oauth2/token
```

- Authorization 설정(Basic Auth)
  - username: oidc-client
  - password: secret
- body 설정(x-www-form-urlencoded)
  - grant_type: refresh_token
  - refresh_token: 토큰 요청 URL에서 받은 refresh token


## 유저 정보 조회

```
GET http://localhost:8080/userinfo
```

- Authorization 설정(Bearer)
    - 위에서 받은 access_token 설정