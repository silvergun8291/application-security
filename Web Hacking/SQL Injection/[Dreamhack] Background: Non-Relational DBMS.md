## 비관계형 데이터베이스

NoSQL은 SQL을 사용하지 않고 복잡하지 않은 데이터를 저장해 단순 검색 및 추가 검색 작업에 매우 최적화되어 있습니다. 또한 키-값을 사용해 데이터를 저장합니다.


<br>
<br>


## MongoDB

MongoDB는 JSON 형태인 Document를 저장하며, 다음과 같은 특징을 갖고 있습니다.

1. 스키마를 따로 정의하지 않아 각 Collection에 대한 정의가 필요하지 않습니다.
2. JSON 형식으로 쿼리를 작성할 수 있습니다.
3. _id 필드가 Primary Key 역할을 합니다.

<br>

```sql
$ mongo
> db.user.insert({uid: 'admin', upw: 'secretpassword'})
WriteResult({ "nInserted" : 1 })
> db.user.find({uid: 'admin'})
{ "_id" : ObjectId("5e71d395b050a2511caa827d"), "uid" : "admin", "upw" : "secretpassword" }
```

* MongoDB에서 데이터를 삽입하고, 조회하는 쿼리의 예시입니다.


<br>


MongoDB에서 status의 값이 "A"이고 qty의 값이 30보다 작은 데이터를 조회하는 쿼리는

```sql
> db.inventory.find( { $and: [ { status: "A" }, { qty: { $lt: 30 } } ] } )
```

<br>


### MongoDB 연산자

**Comparison**

| Name | Description |
| --- | --- |
| $eq | 지정된 값과 같은 값을 찾습니다. |
| $in | 배열 안의 값들과 일치하는 값을 찾습니다. |
| $ne | 지정된 값과 같지 않은 값을 찾습니다. |
| $nin | 배열 안의 값들과 일치하지 않은 값을 찾습니다. |

#

**Logical**

| Name | Description |
| --- | --- |
| $and | 각각의 쿼리를 모두 만족하는 문서가 반환됩니다. |
| $not | 쿼리 식의 효과를 반전시킵니다. 쿼리식과 일치하지 않는 문서를 반환합니다. |
| $or | 각각의 쿼리 중 하나 이상 만족하는 문서가 반환됩니다. |

#

**Element**

| Name | Description |
| --- | --- |
| $exists | 지정된 필드가 있는 문서를 찾습니다. |
| $type | 지정된 필드가 지정된 유형인 문서를 선택합니다.

#

**Evaluation**

| Name | Description |
| --- | --- |
| $expr | 쿼리 언어 내에서 집계 식을 사용할 수 있습니다. |
| $regex | 지정된 정규식과 일치하는 문서를 선택합니다. |
| $text | 지정된 텍스트를 검색합니다. |

<br>

### 기본 문법

**SELECT**

```sql
db.account.find()
```

```sql
db.account.find(
{user_id: "admin"}
)
```

```sql
db.account.find(
{ user_id: "admin" },
{ user_idx:1, _id:0 }
)
```

#

**INSERT**

```sql
db.account.insert({
user_id: "guest",
user_pw: "guest"
})
```

#

**DELETE**

```sql
db.account.remove()
```

```sql
db.account.remove( {user_id: "guest"} )
```

#

**UPDATE**

```sql
db.account.update(
{user_idx: 2},
{ $set: { user_id: "guest2" } }
)
```


<br>
<br>


## Redis

키-값의 쌍을 가진 데이터를 저장합니다. 메모리 기반 DBMS라서 읽고 쓰는 작업이 다른 DBMS 보다 훨씬 빠릅니다. 그래서 서비스에서 임시 데이터를 캐싱하는 용도로 주로 사용합니다.


**데이터 조회 및 조작 명령어**

| 명령어 | 구조 | 설명 |
| --- | --- | --- |
| GET | GET key | 데이터 조회 |
| MGET | MGET key \[key ...] | 여러 데이터를 조회 |
| SET | SET key value | 새로운 데이터 추가 |
| MSET | MSET key value \[key value ...] | 여러 데이터를 추가 |
| DEL | DEL key \[key ...] | 데이터 삭제 |
| EXISTS | EXISTS key \[key ...] | 데이터 유무 확인 |
| INCR | INCR key | 데이터 값에 1 더함 |
| DECR | DECR key | 데이터 값에 1 뺌 |


<br>
<br>


## CouchDB

JSON 형태인 Document를 저장합니다. 이는 웹 기반의 DBMS로, REST API 형식으로 요청을 처리합니다.

#

**HTTP 요청으로 레코드 업데이트, 조회**

| 메소드 | 기능 설명 |
| --- | --- |
| POST | 새로운 레코드를 추가합니다. |
| GET | 레코드를 조회합니다. |
| PUT | 레코드를 업데이트합니다. |
| DELETE | 레코드를 삭제합니다. |

**CouchDB 레코드 업데이트 및 조회 예시**

```bash
$ curl -X PUT http://{username}:{password}@localhost:5984/users/guest -d '{"upw":"guest"}'
{"ok":true,"id":"guest","rev":"1-22a458e50cf189b17d50eeb295231896"}
$ curl http://{username}:{password}@localhost:5984/users/guest
{"_id":"guest","_rev":"1-22a458e50cf189b17d50eeb295231896","upw":"guest"}
```

### 특수 구성 요소

_문자로 시작하는 URL, 필드는 특수 구성요소를 나타냅니다.
다음은 각 구성 요소에 대한 설명입니다.

#

**SERVER**

| 요소 | 설명 |
| --- | --- |
| / | 인스턴스에 대한 메타 정보를 반환합니다. |
| /_all_dbs | 인스턴스의 데이터베이스 목록을 반환합니다. |
| /_utils | 관리자 페이지로 이동합니다. |

#

**Database**

| 요소 | 설명 |
| --- | --- |
| /db | 지정된 데이터베이스에 대한 정보를 반환합니다. |
| /{db}/_all_docs | 지정된 데이터베이스에 포함된 모든 Document를 반환합니다. |
| /{db}/_find | 지정된 데이터베이스에서 JSON 쿼리에 해당하는 모든 Document를 반환합니다. |



