# 📋 프로젝트 인수인계 요약 (새 세션용)

> 새 세션에서 이 파일을 열어보면 바로 이어서 작업할 수 있습니다.
> **다음 할 일: 어느 탭을 어떻게 수정할지 사용자에게 확인 → 진행.**

## 개요
FortiGate 방화벽 점검용 **단일 HTML 도구**를 개발 중. 이번엔 **다른 탭 기능을 수정**하려고 함.

## 저장소 / 브랜치
- **Repo:** `swnam30/ai` (GitHub)
- **작업 브랜치:** `claude/port-scanner-exe-b25kju` (이 브랜치에서 계속 작업/커밋/푸시)
- GitHub 작업은 `gh` CLI 없음 → **GitHub MCP 툴**(`mcp__github__*`) 사용

## 파일 구성
```
FortiGate_점검도구.html   ← 메인 (단일 HTML 도구, ~5500줄). <script> 시작: 약 937줄
port_scanner.py           ← ⑦탭 연동용 포트 스캐너 (별도 exe)
.github/workflows/build-exe.yml  ← Windows exe 자동 빌드(CI)
build.bat / start-bridge.bat / register-protocol.bat
README.md / .gitignore / HANDOFF.md(이 파일)
```

## HTML 탭 구조 (`switchTab(name)` 함수, 배열 정의 약 1053줄)
| 탭 | name | 패널 id | 위치(대략) | 상태 |
|---|---|---|---|---|
| ① 민감정보 치환 | `anonymize` | `tab-anonymize` | 262 | 완성 |
| ② 정책 뷰어 | `viewer` | `tab-viewer` | 306 | 완성 |
| ③ Event Log 분석 | `log` | `tab-log` | 358 | 완성 |
| ④ 점검보고서 | `report` | `tab-report` | 461 | 개발중 |
| ⑤ Config 변환 | `convert` | `tab-convert` | 666 | PAN-OS·JunOS·**ScreenOS** 지원 |
| ⑥ 멀티벤더 뷰어 | `multivendor` | `tab-multivendor` | 761 | 개발중 |
| ⑦ 포트 분석 | `portanalysis` | `tab-portanalysis` | 803 | 완료 |

- 탭 헤더(클릭 UI): 약 252~258줄
- 탭 추가/변경 시 `switchTab`의 `names` 배열(~1053)·`panels` 배열(~1057)도 같이 수정
- 줄 번호는 편집에 따라 변하므로 `grep`으로 앵커를 다시 확인할 것

## 지난 세션에서 완료한 것 (⑦ 포트 분석 탭 — 참고용, 이미 완료)
- `port_scanner.py`(exe)와 HTML을 **로컬 브리지 서버**(`--serve`, 기본 `127.0.0.1:8765`)로 연동.
  HTML `fetch` → exe 스캔 → 결과 표시. (브라우저는 로컬 프로그램 직접 실행 불가하므로 이 구조)
- 브리지 엔드포인트: `/health`, `/scan`, `/sweep`, `/sweep_start`, `/sweep_status` (CORS + PNA 헤더)
- 기능: 단일 포트 스캔(nmap 유사, TCP connect), 포트 위험도 DB 213개(`PA_DB`),
  호스트 식별(TTL·NetBIOS(UDP137)·SNMP(UDP161)·배너), **대역 스윕**(사용중/빈 IP 판별,
  실시간 격자+폴링, 팬텀포트 오탐 자동 제외).
- exe는 **GitHub Actions(windows-latest)**에서 빌드 → Actions 탭 Artifacts `PortScanner-windows-exe`.
  (러너 배정이 큐에서 지연될 수 있음 — 실패 시 Re-run. 워크플로에 timeout-minutes 설정됨)

## ⚠️ 작업 규칙
- **HTML 파일이 실제 산출물** → 수정 후 `SendUserFile`로 사용자에게 파일 전달.
- HTML 수정 후 **Chromium(Playwright)로 `file://` e2e 검증** 흐름 유지:
  - `pip install playwright` (python), 브라우저: `/opt/pw-browsers/chromium-1194/chrome-linux/chrome`
  - `p.chromium.launch(executable_path=...)` 로 페이지 로드 → `switchTab(...)` → 기능 확인, `pageerror` 수집
- 커밋 메시지에 모델 식별자 넣지 말 것. 끝에 `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` 유지.
- 푸시: `git push -u origin claude/port-scanner-exe-b25kju` (네트워크 실패 시 지수백오프 재시도).
- PR은 사용자가 명시적으로 요청할 때만 생성.
- HTML 편집 시: `<!DOCTYPE>`/`<head>` 등 기존 구조 유지, ID 충돌 주의, 전역 변수/함수는 `<script>`(937줄~) 내에 추가.

## 지난 세션 완료 (⑤ Config 변환 — ScreenOS 추가)
- **NetScreen ScreenOS(SSG/ISG) → FortiGate 변환** 신규 구현. 소스 라디오 활성화.
- 함수: `convertScreenOS(text)` (+ 헬퍼 `_soTok`/`_soName`/`_soMipName`). JunOS와 동일하게
  단일 파일 → 다중 섹션(system/interface/zone/address/addrgrp/service/svcgrp/policy/routing/nat/unmapped) 반환.
- 변환 매핑: `set address`→firewall address, `set group address`→addrgrp, `set service`(+ 연속)→service custom
  (tcp/udp-portrange, src 1-65535 생략), `set group service`→service group, `set policy id`(서브블록 src/dst/service 병합,
  `nat src`→`set nat enable`, `disable`→`set status disable`, `permit/deny`, `tunnel`→accept+IPsec 주석)→firewall policy,
  `set route`→router static, zone→system zone(ethernet0/N→portN 매핑).
- **MIP(양방향 1:1 NAT)**: `set interface … mip`→`firewall vip` + `set nat-source-vip enable`.
  ScreenOS MIP은 인바운드 DNAT + 아웃바운드 SNAT(공인 IP)를 자동 수행 → FortiGate에선
  VIP에 `nat-source-vip enable`(기본 꺼짐)을 켜야 매핑 호스트 아웃바운드가 VIP 외부 IP로 SNAT됨.
  IP Pool은 오히려 우선순위(Pool>VIP-extip)로 오버라이드하므로 사용하지 않음. 참고:
  Fortinet KB "Mapping VIP outbound connections (Source NAT)".
- **인코딩**: ScreenOS config는 EUC-KR/CP949 → `handleConvertFiles`가 ArrayBuffer로 읽어 UTF-8 실패 시 `TextDecoder('euc-kr')` 재디코딩.
- 좌우 diff/CSV 정렬: `detectConvertFileType`·`CONVERT_TYPE_META`·`runConversion`·`parseOrigBlocks`(screenos 분기)·`downloadConvert`에 screenos 배선.
- e2e 검증: 실제 SSG550 config(9,868줄)로 Chromium 업로드→변환, pageerror 0. 한글 오브젝트명·VPN명 복원 확인.
- **커버리지 전수 검증 완료** (독립 파서로 원본 재파싱 → 이름 단위 대조): 주소 4004(FQDN 22 포함)·
  주소그룹 70·서비스 107·서비스그룹 1·정책 186(disable 28)·MIP→VIP 39·라우팅 15·인터페이스 3·Zone 3 — 전 항목 일치.
  검증 과정에서 수정한 버그: ①주소그룹명을 존(t[3])으로 잘못 읽던 것 → t[4]로 수정(70개 그룹 복원),
  ②FQDN(도메인) 주소 22개 침묵 누락 → `set type fqdn`으로 변환 추가, ③zone screen(DoS) 옵션 52줄 → 미변환 안내로 분리.
  잔여 침묵 무시 73줄은 clock/ntp/vrouter/log/flow 등 정책 마이그레이션과 무관한 시스템 설정.
- 미구현(수동): IPsec VPN(IKE/phase), DIP, 관리자/SNMP/인증 → unmapped 섹션 + 경고로 안내.
- **전체 Config 대조 뷰**(`out.full`, 기본 탭): 좌=원본 config 전체(줄 순서 유지), 우=각 줄의 변환 결과.
  변환됨=녹색 FG 블록, 상위 블록에 흡수된 연속줄=회색 "↑포함", 미변환=주황 "! 미변환(카테고리)",
  변환 대상 아님(clock/ntp 등)=공란. 마이그레이션 누락을 한 화면에서 검증. `showConvertSection`에 `type==='full'` 분기,
  객체별 좌우 라인수 패딩으로 정렬(연동 스크롤 호환). fgMaps=parseFGBlocksForType로 재사용.
- **CSV export 버그 수정**: `downloadConvertCSV`가 unmapped item의 없는 `it.lines`를 참조해 예외로 버튼 무반응 → `it.lines?` 가드.

## 다음 작업
**수정할 탭과 원하는 변경 내용을 사용자에게 확인한 뒤 진행.**
(예: "④ 점검보고서 탭에 ~~ 기능 추가", "② 정책 뷰어에서 ~~ 수정")
