# 오픈소스 반입 심사 사례

| 항목 | 내용 |
|---|---|
| 문서 ID | OSS-REV-001 |
| 작성일 | 2026-11-27 |
| 관련 정책 | OSS-POL-001 |
| 관련 체크리스트 | OSS-CHK-001 |
| 대상 서비스 | OSS Security Gate PoC |

## 1. 심사 목적

실제 사용 중인 직접 의존성을 대상으로
보안 취약점, 라이선스, 사용 목적 및
잔여 위험을 종합적으로 검토한다.

## 2. Requests 반입 심사

| 항목 | 검토 내용 |
|---|---|
| 신청 ID | INTAKE-001 |
| 패키지명 | requests |
| 신청 버전 | 2.34.2 |
| 이전 버전 | 2.19.1 |
| PURL | pkg:pypi/requests@2.34.2 |
| 사용 목적 | HTTP 통신 기능 |
| 의존성 유형 | DIRECT |
| 선언 라이선스 | Apache-2.0 |
| SCA 탐지 레코드 | 0 |
| SBOM 등록 | 완료 |
| 심사 상태 | PENDING_REVIEW |

### 공식 출처

- https://pypi.org/project/requests/2.34.2/
- https://github.com/psf/requests
- https://github.com/psf/requests/blob/main/LICENSE
- https://github.com/psf/requests/blob/main/NOTICE

### 보안 검토

기존 버전에서 발견된 알려진 취약점에 대응하여
패키지 버전을 업데이트하였다.

애플리케이션 소스코드에서는 TLS 인증서 검증을
활성화한 상태로 Session 객체를 생성한다.

현재 실습에서는 실제 외부 HTTP 요청을
수행하지 않으므로 네트워크 통신 및 TLS의
동적 검증까지 완료한 것은 아니다.

### 라이선스 검토

설치 패키지의 선언 정보와 공식 저장소의
Apache-2.0 라이선스 종류가 일치한다.

재배포 시 라이선스 사본, 관련 고지 및
변경사항 표시 의무를 검토해야 한다.

특정 설치 버전의 라이선스 원문 대조와
배포 형태별 의무 검토는 추가로 필요하다.

### 잔여 위험

- 실제 네트워크 통신 환경 미검증
- 패키지 해시 및 서명 검증 미수행
- 악성 패키지 별도 검사 미수행
- 유지보수 및 지원 정책 상세 검토 필요
- 전이 의존성 라이선스 검토 필요

### 심사 결론

보안 취약점 검사 및 SBOM 등록은 완료하였다.
그러나 필수 검토 항목이 남아 있으므로
최종 반입 승인을 보류한다.

## 3. PyYAML 반입 심사

| 항목 | 검토 내용 |
|---|---|
| 신청 ID | INTAKE-002 |
| 패키지명 | PyYAML |
| 신청 버전 | 6.0.4 |
| 이전 버전 | 5.3 |
| PURL | pkg:pypi/pyyaml@6.0.4 |
| 사용 목적 | YAML 설정 데이터 처리 |
| 의존성 유형 | DIRECT |
| 선언 라이선스 | MIT |
| SCA 탐지 레코드 | 0 |
| SBOM 등록 | 완료 |
| 심사 상태 | PENDING_REVIEW |

### 공식 출처

- https://pypi.org/project/PyYAML/6.0.4/
- https://github.com/yaml/pyyaml
- https://github.com/yaml/pyyaml/blob/main/LICENSE
- https://github.com/yaml/pyyaml/security

### 보안 검토

기존 버전의 안전하지 않은 역직렬화 관련
취약점에 대응하여 패키지를 업데이트하였다.

실습 애플리케이션에서는 yaml.safe_load를
사용하여 설정 데이터를 처리하도록 구성하였다.

단순한 버전 업데이트뿐만 아니라
라이브러리의 안전한 사용 방식도 검토하였다.

### 라이선스 검토

설치 패키지의 선언 정보와 공식 저장소의
MIT 라이선스 종류가 일치한다.

재배포 시 저작권 고지 및 라이선스 문구의
보존 여부를 검토해야 한다.

특정 설치 버전의 라이선스 원문 대조는
추가로 필요하다.

### 잔여 위험

- 신뢰할 수 없는 YAML 입력에 대한 동적 검증 미수행
- 패키지 해시 및 서명 검증 미수행
- 악성 패키지 별도 검사 미수행
- 유지보수 및 지원 정책 상세 검토 필요

### 심사 결론

보안 취약점 검사 및 SBOM 등록은 완료하였다.
그러나 필수 검토 항목이 남아 있으므로
최종 반입 승인을 보류한다.

## 4. 종합 심사 결과

| 심사 항목 | Requests | PyYAML |
|---|---|---|
| 패키지 식별 | PASS | PASS |
| SCA 검사 | PASS | PASS |
| SBOM 등록 | PASS | PASS |
| 선언 라이선스 식별 | PASS | PASS |
| 공식 라이선스 종류 대조 | PASS | PASS |
| 설치 버전 라이선스 원문 대조 | PENDING | PENDING |
| 패키지 무결성 검증 | PENDING | PENDING |
| 악성 패키지 검사 | PENDING | PENDING |
| 유지보수 위험 검토 | PENDING | PENDING |
| 최종 반입 승인 | HOLD | HOLD |

## 5. 검증 증적

- security/scan_results/remediated_scan.json
- security/scan_results/remediated_metadata.json
- sbom/remediated_sbom_enriched.json
- docs/governance/oss_inventory.csv
- reports/cve_triage.md
- reports/sbom_enrichment.txt
- reports/sbom_license_coverage.txt

## 6. 심사 한계

본 문서는 개인 학습용 PoC의 반입 심사 사례이다.
실제 조직의 승인 담당자가 검토하거나 승인한
문서가 아니며 법적 적합성을 보증하지 않는다.

SCA 검사 통과와 최종 반입 승인을 구분하여
미확인 위험에 대한 검토 필요성을 명시하였다.
