# SSL Certificate Checker 1.0

Windows 11 x64용 설치 불필요 GUI입니다. 배포된 `SSLCertificateChecker.exe`를 실행하면 됩니다. 관리자 권한이나 별도 .NET 설치가 필요하지 않도록 런타임을 포함한 단일 파일로 빌드했습니다. 최초 실행 시 일부 런타임 파일을 사용자 임시 폴더에 풉니다. 코드 서명은 하지 않았습니다.

다운로드: [GitHub Release v1.0.0](https://github.com/lee4830/CertCheck/releases/tag/v1.0.0). 실행파일만 받거나, 사용법과 라이선스가 포함된 `SSLCertificateChecker-win-x64.zip`을 받아 압축을 푸세요. [검증 보고서](VERIFICATION.md)에 직접 확인한 범위와 제한을 기록했습니다.

## 사용

1. 서버 도메인 또는 IP와 포트(기본 443)를 입력합니다. URL이나 `도메인:포트` 대신 각 입력란을 사용하세요.
2. 필요하면 `SNI / 검증 이름`에 DNS 이름을 입력합니다. 예를 들어 IP로 접속하면서 이 칸에 실제 서비스 도메인을 넣을 수 있습니다. 비우면 접속 도메인/IP를 검증합니다.
3. `TLS SNI 전송`을 끄면 SNI 확장을 생략하되 이름 검증은 계속 수행합니다. IP를 기본 검증 이름으로 사용할 때는 SNI를 자동 생략합니다. 이름은 SAN으로 검증하며 CN만 있는 구형 인증서는 일치로 처리하지 않습니다.
4. `인증서 조회`를 누릅니다. 검증 실패와 TLS 연결 완료 여부를 구분해서 표시합니다. 인증서를 받기 전에 DNS/TCP/TLS가 실패하면 인증서가 없을 수 있습니다. TLS 서명·알고리즘 오류나 클라이언트 인증 요구 등도 연결을 막을 수 있습니다.
5. 결과와 두 체인 탭, DNS 탭을 확인합니다. 체인 목록의 인증서를 클릭하면 상세를 볼 수 있습니다. 루트 인증서는 서버가 보통 보내지 않습니다. 목록 이름만으로 마지막 인증서를 루트로 간주하지 마세요.
6. `결과 복사`는 화면에 표시된 조회 시점의 보고서를 복사합니다. `내보내기`에서 JSON, 텍스트, 실제 서버 전송 체인 전체 PEM, 선택 인증서 DER(CER)을 저장합니다. CER은 체인 탭에서 고른 인증서를 저장하며 다른 탭에서는 서버 첫 번째 인증서를 저장합니다.
7. 이력은 최근 50개를 보관합니다. 같은 접속 설정의 이전 결과는 새 결과로 교체합니다. `저장 결과 열기`는 당시 결과를 표시하고, `입력에 적용` 후 조회하면 새로 연결합니다. 표시된 D-day는 조회 당시 기준이며 실시간 카운트다운이 아닙니다.

## 결과 해석

- 만료 시각은 PC 시간대와 무관하게 UTC+09:00(KST)로 표시합니다. D-day는 남은 전체 24시간의 수입니다. 24시간 미만이면 D-Day, 정확한 만료 시각에 도달하면 만료됨입니다. 30일 이내 주황색, 7일 이내 또는 검증 실패는 빨간색입니다. PC 시계가 정확해야 합니다.
- 실제 서버 전송 체인은 **같은 TLS 연결**의 Certificate 메시지에서 수집한 순서입니다. Windows 검증 체인은 받은 인증서와 로컬 Windows 저장소/캐시를 사용해 별도로 구성합니다. 중간 인증서가 캐시에 있으면 서버 누락이 가려질 수 있으므로 전송 체인을 함께 보세요.
- AIA 중간 인증서 다운로드는 비활성입니다. 기본 폐기 검사는 **수행 안 함**이며 정상 표시가 폐기 여부를 보증하지 않습니다. 온라인 폐기 검사를 선택하면 Windows가 CRL/OCSP 등을 요청할 수 있고, 네트워크에 따라 확인 불가/오류가 날 수 있습니다.
- 입력한 제한 시간(1~60초)은 DNS/TCP/TLS 단계에 적용됩니다. Windows 검증은 별도 백그라운드 작업이며 온라인 조회 시간 제한은 각 조회에 5초를 지정합니다. 전체 작업의 엄격한 상한은 아닙니다. 진행 중인 Windows 검증은 즉시 취소할 수 없고 완료 후 결과를 표시합니다. 화면은 계속 조작할 수 있습니다.
- DNS 탭은 응답한 IP 후보와 실제 접속 주소를 나눠 보여줍니다. 후보 모두에 연결하는 검사는 아닙니다. IPv6와 IPv4가 함께 있으면 운영체제 및 네트워크에 따라 선택됩니다.
- 진단을 위해 인증서 신뢰 오류가 있어도 TLS 인증서 수집을 진행하지만 HTTP 요청 등 서비스 데이터는 보내지 않습니다. TLS 연결의 암호학적 검사는 TLS 라이브러리가 수행합니다. 이 프로그램의 수집 동작이 다른 앱의 인증서 검증 설정을 바꾸지는 않습니다.

## 저장과 지원 범위

이력: `%LOCALAPPDATA%\SSLCertificateChecker\history.json`. 인증서 공개 정보, 도메인/IP, 결과를 평문 JSON으로 저장합니다. 이력 전체 삭제 버튼으로 제거할 수 있습니다. 깨진 이력은 경고와 함께 불러오지 않습니다. 여러 인스턴스에서 동시에 저장할 때는 마지막 저장 내용이 우선할 수 있습니다.

Windows 11 x64, 직접 TLS 1.2/1.3을 우선 지원합니다. STARTTLS(SMTP/LDAP 업그레이드), HTTP CONNECT 프록시, 클라이언트 인증서 로그인, TLS 1.0/1.1, 여러 IP 일괄 검사는 지원하지 않습니다. 사내망/방화벽/프록시가 필수인 네트워크에서는 연결되지 않을 수 있습니다. Windows ARM64/32비트 및 .NET 미설치의 깨끗한 PC에서는 직접 검증하지 않았습니다. 기타 미검증 사항은 VERIFICATION.md를 참조하세요.

## 소스 빌드

Windows x64, .NET 10 SDK와 최초 NuGet 복원용 인터넷이 필요합니다. 실행 사용자에게 SDK는 필요하지 않습니다.

```powershell
./build.ps1
```

실행 정책이 스크립트를 막는 환경에서는 설정 변경 없이 아래 명령을 각각 실행할 수 있습니다.

```powershell
dotnet restore Gui/Gui.csproj --locked-mode
dotnet run --project Tests/Tests.csproj -c Release
dotnet publish Gui/Gui.csproj -c Release -r win-x64 --self-contained true --no-restore -o dist
```

결과: `dist/SSLCertificateChecker.exe`. Core.pdb 등 디버그 파일은 실행에 필요하지 않습니다. Core는 입력/수집/검증/저장, Gui는 화면, Tests는 로컬 실제 TLS 서버를 사용하는 통합 테스트입니다. BouncyCastle.Cryptography 2.7.0은 잠금 파일에 고정되어 있습니다.

## 선택 CLI

```powershell
$p = Start-Process ./SSLCertificateChecker.exe -ArgumentList '--probe example.com 443 - result.json' -Wait -PassThru
$p.ExitCode
```

순서: `--probe HOST PORT SNI OUTPUT_JSON`. SNI 자리에 `-`를 쓰면 접속 이름을 사용하며 IP는 SNI를 생략합니다. 인자에 공백이 있는 경로는 일반 Windows 인용 규칙을 적용하세요. CLI의 폐기 검사는 기본 비활성입니다. 콘솔창은 뜨지 않습니다.

종료 코드: 0=TLS 완료 및 이름/OS 검증 정상(폐기 미검사), 2=TLS 완료이나 검증 실패, 1=연결/처리 실패, 64=인자 형식 오류. 결과 JSON에도 상세 상태를 기록합니다.

## 구현 참고 / 라이선스

- [Bouncy Castle 소스](https://github.com/bcgit/bc-csharp): 관리형 TLS와 수신 인증서 수집.
- [Microsoft X509Chain](https://learn.microsoft.com/dotnet/api/system.security.cryptography.x509certificates.x509chain): Windows 인증서 체인 구성 및 검증.
- [Microsoft 단일 파일 배포](https://learn.microsoft.com/dotnet/core/deploying/single-file/overview): 런타임 포함 단일 파일 배포.

배포본의 licenses 폴더에 Bouncy Castle 및 .NET 라이선스/고지를 포함했습니다. 소스 라이선스는 LICENSE.txt를 참조하세요.
