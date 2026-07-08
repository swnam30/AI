@echo off
REM ============================================================
REM  PortScanner  -  Windows EXE 빌드 스크립트
REM  Python 3.8+ 및 인터넷 연결 필요 (PyInstaller 자동 설치)
REM ============================================================
setlocal

echo [1/3] PyInstaller 설치 확인...
python -m pip install --upgrade pyinstaller
if errorlevel 1 (
    echo [!] PyInstaller 설치 실패. Python 이 설치되어 있는지 확인하세요.
    pause
    exit /b 1
)

echo.
echo [2/3] EXE 빌드 중 (단일 파일)...
python -m PyInstaller --onefile --console --name PortScanner port_scanner.py
if errorlevel 1 (
    echo [!] 빌드 실패.
    pause
    exit /b 1
)

echo.
echo [3/3] 완료!
echo   생성된 파일: dist\PortScanner.exe
echo.
echo   사용 예:
echo     dist\PortScanner.exe               (대화형 메뉴)
echo     dist\PortScanner.exe 192.168.1.1   (바로 스캔)
echo     dist\PortScanner.exe 192.168.1.1 -p all
echo.
pause
