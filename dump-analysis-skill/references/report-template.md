## 크래시 덤프 분석 결과

### 예외 정보

| 항목 | 값 |
|---|---|
| 예외 코드 | `{{EXCEPTION_CODE}}` - `{{EXCEPTION_NAME}}` |
| 폴트 주소 | `{{FAULT_ADDRESS}}` |
| 심볼 품질 | {{SYMBOL_QUALITY}} |

---

### 콜 스택 (Thread {{THREAD_ID}})

| 프레임 | 모듈 | 함수 |
|---|---|---|
{{STACK_ROWS}}

---

### 크래시 원인

{{ROOT_SUMMARY}}

- 문제 위치: {{PROBLEM_LOCATION}}
{{PROBLEM_CODE_BLOCK}}
{{CONTEXT_CODE_BLOCK}}
{{ROOT_DETAIL}}

---

### 호출 흐름 요약

```text
{{CALL_FLOW}}
```

### 수정 방법

{{FIX_METHOD}}
