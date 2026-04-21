---
id_prefix: DESER
grep_patterns:
  - "pickle\\.loads\\s*\\("
  - "pickle\\.load\\s*\\("
  - "yaml\\.load\\s*\\("
  - "Marshal\\.load\\s*\\("
  - "unserialize\\s*\\("
  - "ObjectInputStream"
  - "readObject\\s*\\("
  - "XMLDecoder"
  - "XStream\\.fromXML\\s*\\("
  - "BinaryFormatter"
  - "node-serialize"
  - "cryo\\.parse\\s*\\("
  - "jsonpickle\\.decode\\s*\\("
  - "maybe_unserialize\\s*\\("
  - "shelve\\.open\\s*\\("
  - "activateDefaultTyping"
  - "enableDefaultTyping"
  - "@JsonTypeInfo"
  - "GenericJackson2JsonRedisSerializer"
  - "fastjson"
  - "parseObject\\s*\\("
  - "SnakeYaml"
  - "new Yaml\\s*\\("
  - "BinaryFormatter\\.Deserialize"
  - "TypeNameHandling"
  - "phpggc"
---

> ## 핵심 원칙: "역직렬화로 의도하지 않은 동작이 발생하지 않으면 취약점이 아니다"
>
> `JSON.parse()`는 데이터만 표현하므로 코드 실행으로 이어지지 않는다 (단, prototype pollution 별도 점검). 취약한 역직렬화는 **객체/타입 정보를 포함하는 직렬화 포맷** (Java ObjectInputStream, Python pickle, PHP unserialize, Ruby Marshal, .NET BinaryFormatter, node-serialize, YAML unsafe loader 등)에서 발생한다.

## Sink 의미론

Deserialization sink는 "사용자 제어 바이트가 타입/객체 정보를 복원하는 디코더에 입력되는 지점"이다. 핵심 구분: 디코더가 **임의 클래스 인스턴스화 + 메서드 호출**을 허용하는가.

| 언어 | 위험 sink | 비고 |
|---|---|---|
| Java | `ObjectInputStream.readObject/readUnshared`, `XMLDecoder.readObject`, `XStream.fromXML` (화이트리스트 없음), `SnakeYAML.load` (unsafe Loader), `Kryo.readClassAndObject` (등록 없음) | gadget chain (CommonsCollections, Spring AOP) 활용 |
| Python | `pickle.loads/load`, `cPickle.loads`, `shelve.open`, `yaml.load` (Loader 미지정 또는 unsafe), `marshal.loads`, `jsonpickle.decode` | `__reduce__` 메서드로 RCE |
| PHP | `unserialize`, `maybe_unserialize` | `__wakeup`/`__destruct` 매직 메서드 체인 (POP chain) |
| Ruby | `Marshal.load`, `YAML.load` (vs `safe_load`) | `_load`/`init_with` 체인 |
| Node.js | `node-serialize` `unserialize`, `cryo.parse` | `_$$ND_FUNC$$_` 패턴 |
| .NET | `BinaryFormatter.Deserialize`, `ObjectStateFormatter.Deserialize` (ViewState), `Json.NET TypeNameHandling.All/Auto`, `LosFormatter`, `SoapFormatter` | Microsoft 사용 중단 권고 |
| Go | `encoding/gob.Decoder.Decode` (interface 타입 등록 시 임의 타입 가능) | `encoding/json`은 안전. `gob`은 등록된 타입에 한정 — 등록 범위 확인 |
| Rust | `bincode`/`serde` 정의된 타입만 — 비교적 안전 | `serde-pickle`, `rmp-serde` (MessagePack)는 옵션 의존. `untagged` enum 위험 |

## Source-first 추가 패턴

- HTTP 쿠키에 base64 직렬화 페이로드 (Java/PHP 레거시 세션)
- `Content-Type: application/x-java-serialized-object` (RMI, JMX)
- ViewState (.NET WebForms `__VIEWSTATE`)
- 메시지 큐 (Kafka/RabbitMQ/SQS) consumer가 외부 메시지 역직렬화
- 캐시(Redis/Memcached)에서 읽은 직렬화 값 + 캐시 키가 사용자 제어
- 파일 업로드 후 `pickle.load(f)` (사용자 데이터 저장 → 후속 처리)
- JWT custom 페이로드를 base64 디코딩 후 unserialize
- 채팅/게임 클라이언트 ↔ 서버 바이너리 프로토콜
- gRPC binary 메시지 (proto 기반은 안전이나 Any 필드는 별도 확인)
- WebSocket binary frame 본문
- Express `cookie-session` / Rails `Marshal` cookie session-store (서명 키 노출 시 위험)

## 자주 놓치는 패턴 (Frequently Missed)

- **YAML `load` 기본 인자**: PyYAML 5.1 미만은 `Loader` 미지정 시 unsafe. `yaml.safe_load` 필수.
- **Jackson `enableDefaultTyping()`** 또는 `@JsonTypeInfo`: JSON처럼 보여도 polymorphic typing이 켜져 있으면 RCE.
- **Json.NET `TypeNameHandling.All`/`Auto`**: `$type` 필드로 임의 타입 인스턴스화.
- **XStream**: 화이트리스트(`addPermission`) 없이 `fromXML` → 다수 CVE.
- **Spring 메시지 컨버터** (`ObjectInputStream` 기반 RMI/HTTP invoker).
- **SnakeYAML `Yaml().load(...)`**: 명시적 `SafeConstructor` 없으면 RCE (CVE-2022-1471).
- **Kryo without `setRegistrationRequired(true)`**.
- **PHP phar deserialization**: `file_exists("phar://...")` 만으로도 unserialize 트리거.
- **.NET BinaryFormatter는 deprecated이지만 잔존 코드**: WCF/Remoting/ViewState.
- **JWT none algo + 역직렬화 페이로드**: jwt-scanner와 겹치지만 페이로드가 클래스 정보를 담은 경우.
- **gadget chain 라이브러리 의존성**: `commons-collections`/`commons-beanutils`가 classpath에 있는지 확인 — 영향도 평가에 사용.
- **`ObjectInputStream` 서브클래스로 `resolveClass` 오버라이드한 화이트리스트**: 화이트리스트가 충분히 좁은지 확인.
- **Apache Commons Configuration2 `Lookups`**: 인터폴레이션이 RCE로 (Log4Shell 변형 — JNDI lookup).
- **Ruby Rails `cookie_store` + `Marshal` serializer**: Rails 4 미만 기본 Marshal — `secret_key_base` 노출 시 RCE. Rails 4+ 기본 JSON.
- **NodeJS `Object.assign`/`_.merge` deep clone**: 함수 prototype을 가진 객체로 indirect call.
- **JEP 290 (Java 9+) `ObjectInputFilter`**: 등록 안 하면 기본 무필터. 등록해도 패턴이 너무 넓으면 우회.

## 안전 패턴 (FP Guard)

- **JSON-only 데이터** (Jackson `disableDefaultTyping`, Json.NET 기본 `TypeNameHandling.None`).
- **`yaml.safe_load`** (Python).
- **YAML `SafeConstructor`** (SnakeYAML).
- **HMAC 서명 검증 후 역직렬화**: 사용자가 페이로드를 변조 못 함 (서명 키 안전 가정).
- **`Marshal.load` 입력이 trusted 파일** (서버가 직접 생성한 캐시 파일).
- **타입 화이트리스트** (`XStream.addPermission(NoTypePermission.NONE); xstream.allowTypes(...)`).
- **Kryo `setRegistrationRequired(true)` + 명시적 등록**.
- **Protocol Buffers / Avro / Thrift schema-bound**: 미리 정의된 schema 외 타입 불가.
- **Java JEP 290 `ObjectInputFilter`** (Java 9+): 글로벌 또는 스트림별 필터 등록 + 충분히 좁은 패턴.
- **MessagePack / CBOR with `untrusted=false`** 명시 옵션.
- **Go `encoding/json` (interface 미사용)**: 정의된 구조체로만 unmarshal — 타입 정보 외부 입력 불가.

## 우회 가능 패턴

방어 처리가 보이지만 우회 가능한 경우 후보 사유에 우회 방식을 함께 기록한다.

| 방어 코드 | 우회 가능성 | 우회 방식 |
|---|---|---|
| 타입 화이트리스트가 root type만 (`Object`, `Map`) | 가능 | 화이트리스트 통과 후 nested gadget으로 chain |
| Java JEP 290 `ObjectInputFilter` 패턴이 광범위 (`*`, `java.util.*`) | 가능 | Commons Collections 등 `java.util.HashMap.Entry` 같은 nested 클래스로 chain |
| `_wakeup` 차단했지만 `_destruct` 미차단 (PHP) | 가능 | 다른 매직 메서드(`__destruct`, `__toString`)로 POP chain |
| HMAC 서명 검증 + 키가 코드 하드코딩 | 가능 | 키 노출 시 임의 페이로드 서명. ENV/KMS 사용 권장 |
| 추상 클래스 화이트리스트 | 가능 | 등록된 abstract의 임의 subclass로 우회 — concrete 클래스 단위로 화이트리스트 필요 |
| polymorphic typing이 `LaissezFaireSubTypeValidator` (Jackson 2.10+) | 가능 | 사실상 무필터 — `BasicPolymorphicTypeValidator` + `allowIfBaseType` 좁게 설정 필요 |

## 후보 판정 의사결정

| 조건 | 판정 |
|---|---|
| 위 표의 위험 sink + 사용자 입력 도달 + 화이트리스트/서명 없음 | 후보 |
| Jackson/Json.NET polymorphic typing 활성 + 외부 입력 | 후보 (라벨: `POLYMORPHIC`) |
| YAML `load` (Loader 미지정) + Python | 후보 |
| HMAC 서명 검증 확인 (key 별도 관리) | 제외 |
| 화이트리스트 적용 확인 (충분히 좁음) | 제외 |
| 입력이 trusted 내부 출처만 (예: 서버가 만든 캐시 파일) | 제외, 단 캐시 키가 사용자 제어이면 후보 |
| `BinaryFormatter` 잔존 (.NET) + 외부 입력 | 후보 (라벨: `DEPRECATED_FORMATTER`) |

## 후보 판정 제한

default typing 또는 다형성 역직렬화가 활성화된 경우만 후보. 비활성화가 확인되면 제외.
