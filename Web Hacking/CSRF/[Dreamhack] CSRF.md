## Cross Site Request Forgery (CSRF)

CSRF는 임의 이용자의 권한으로 임의 주소에 HTTP 요청을 보낼 수 있는 취약점입니다. 공격자는 임의 이용자의 권한으로 서비스 기능을 사용해 이득을 취할 수 있습니다.

예를 들어, 이용자의 계정으로 임의 금액을 송금해 금전적인 이득을 취하거나 비밀번호를 변경해 계정을 탈취할 수 있습니다.


<br>


## Cross Site Request Forgery 동작

CSRF 공격에 성공하기 위해서는 공격자가 작성한 악성 스크립트를 이용자가 실행해야 합니다. 이용자에 메일을 보내거나 게시판에 글을 작성해 이용자가 이를 조회하도록 유도하는 방법이 있습니다.

공격 스크립트는 HTML이나 javascript로 작성할 수 있는데, img 태그 또는 form 태그로 작성하는 방식이 있습니다. 이 두 개의 태그를 사용해 HTTP 요청을 보내면 HTTP 헤더인 Cookie에 이용자의 인증 정보가 포함됩니다.

#

### HTML img 태그 공격 코드 예시

![image](https://user-images.githubusercontent.com/81484874/191702620-ac3d7b71-06a5-44cb-befc-6e2869cdc59b.png)

```html
<img src='http://bank.dreamhack.io/sendmoney?to=dreamhack&amount=1337' width=0px height=0px>
```

* amount가 1337이 되도록 하는 악성 스크립트 입니다.
* 이미지 크기를 줄이는 옵션을 이용해 이용자에게 걸리지 않고 임의 페이지에 요청을 보낼수 있습니다.

#

### Javascript 공격 코드 예시

```javascript
/* 새 창 띄우기 */
window.open('http://bank.dreamhack.io/sendmoney?to=dreamhack&amount=1337');
/* 현재 창 주소 옮기기 */
location.href = 'http://bank.dreamhack.io/sendmoney?to=dreamhack&amount=1337';
location.replace('http://bank.dreamhack.io/sendmoney?to=dreamhack&amount=1337');
```

새로운 창을 띄우고, 현재 창의 주소를 옮기는 행위가 가능합니다.


<br>


### XSS와 CSRF 차이

XSS는 인증 정보인 세션 및 쿠키 탈취를 목적으로 하는 공격입니다.

CSRF는 이용자가 임의 페이지에 HTTP 요청을 보내는 것을 목적으로 하는 공격입니다. 또한, 공격자는 악성 스크립트가 포함된 페이지에 접근한 이용자의 권한으로 웹 서비스의 임의 기능을 실행할 수 있습니다.


#
---
#

> 출처: https://dreamhack.io/
