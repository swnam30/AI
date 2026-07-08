@echo off
REM ============================================================
REM  PortScanner - HTML 연동 브리지 서버 실행
REM  이 창을 켜 둔 상태에서 HTML 점검 도구 ⑦ 탭의
REM  "실시간 스캔" 을 사용하세요. (종료: 이 창에서 Ctrl+C)
REM ============================================================
setlocal

REM 같은 폴더에 PortScanner.exe 가 있으면 그것을, 없으면 python 소스를 실행
if exist "%~dp0PortScanner.exe" (
    "%~dp0PortScanner.exe" --serve
) else if exist "%~dp0dist\PortScanner.exe" (
    "%~dp0dist\PortScanner.exe" --serve
) else (
    python "%~dp0port_scanner.py" --serve
)

pause
