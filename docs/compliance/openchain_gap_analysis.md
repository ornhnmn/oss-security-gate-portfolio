# OpenChain 국제표준 Gap Analysis

| 항목 | 내용 |
|---|---|
| 문서 ID | OSS-COMP-001 |
| 버전 | 1.0.0 |
| 작성일 | 2026-11-27 |
| 평가 대상 | OSS Security Gate PoC |
| 평가 유형 | 개인 프로젝트 사전 격차 분석 |
| 참조 표준 | ISO/IEC 5230:2020, ISO/IEC 18974:2023 |
| 인증 상태 | NOT CERTIFIED |

## 1. 분석 목적

오픈소스 라이선스 준수 및 보안 보증에 관한
국제표준의 주요 요구 영역을 검토하고,
개인 프로젝트의 구현 내용과 비교하였다.

현재 확보한 기술적 통제와 관리적 통제를
식별하고 조직 환경에서 추가적으로 필요한
개선 과제를 도출하는 것을 목적으로 한다.

## 2. 참조 표준

### ISO/IEC 5230:2020

오픈소스 라이선스 준수 프로그램의
핵심 요구사항을 정의하는 국제표준이다.

### ISO/IEC 18974:2023

오픈소스 보안 보증 프로그램의
핵심 요구사항을 정의하는 국제표준이다.

두 표준은 정책, 책임, 구성요소 관리 및
관련 절차의 체계적인 운영을 고려한다.

## 3. 평가 범위 및 기준

평가 대상은 개인 PoC에서 구현한
Python 패키지 공급망 보안 관리 체계이다.

| 상태 | 정의 |
|---|---|
| IMPLEMENTED | 관련 기술 기능 구현 및 검증 |
| PARTIAL | 일부 기능 또는 증적만 확보 |
| DOCUMENTED | 정책 또는 절차 초안 작성 |
| GAP | 구현 및 운영 증적 부족 |

본 평가 기준은 프로젝트 자체 기준이며
공식 OpenChain 인증 평가 등급이 아니다.

## 4. ISO/IEC 5230 Gap Analysis

| ID | 검토 영역 | 현재 상태 | 주요 증적 | 개선 과제 |
|---|---|---|---|---|
| LC-01 | OSS 관리 정책 | DOCUMENTED | oss_management_policy.md | 승인 및 정책 전파 |
| LC-02 | 담당자 역할 및 책임 | DOCUMENTED | oss_management_policy.md | 실제 조직 담당자 지정 |
| LC-03 | 담당자 역량 및 교육 | PARTIAL | developer_security_guide.md | 교육 시행 및 기록 |
| LC-04 | 프로그램 적용 범위 | DOCUMENTED | oss_management_policy.md | 조직 및 서비스 범위 확정 |
| LC-05 | 외부 문의 대응 | GAP | 없음 | 문의 채널 및 담당자 정의 |
| LC-06 | 구성요소 식별 및 관리 | IMPLEMENTED | SBOM, oss_inventory.csv | 전체 구성요소 식별 확대 |
| LC-07 | 라이선스 식별 | PARTIAL | remediated_sbom_enriched.json | 원문 및 버전별 검토 |
| LC-08 | 라이선스 의무 관리 | PARTIAL | oss_intake_review.md | 배포 형태별 의무 이행 |
| LC-09 | 준수 산출물 관리 | GAP | 없음 | 고지문 및 라이선스 제공 절차 |
| LC-10 | 기여 정책 | GAP | 없음 | 외부 OSS 기여 절차 |
| LC-11 | 적합성 선언 및 유지 | GAP | 없음 | 전체 요구사항 검토 및 승인 |

위 항목은 표준의 주요 영역을 재구성한
프로젝트 자체 평가 항목이다.

## 5. ISO/IEC 18974 Gap Analysis

| ID | 검토 영역 | 현재 상태 | 주요 증적 | 개선 과제 |
|---|---|---|---|---|
| SA-01 | 보안 관리 정책 | DOCUMENTED | policy.yaml, OSS 관리 정책 | 정책 승인 및 전파 |
| SA-02 | 역할 및 책임 | DOCUMENTED | oss_management_policy.md | 실제 담당자 및 자원 확보 |
| SA-03 | 역량 및 교육 | PARTIAL | developer_security_guide.md | 교육 및 역량 검증 |
| SA-04 | 적용 범위 | DOCUMENTED | oss_management_policy.md | 조직 범위 및 대상 서비스 확정 |
| SA-05 | 표준 보안 절차 | PARTIAL | SCA, CI/CD, 대응 정책 | 조직 전체 적용 및 운영 |
| SA-06 | 외부 보안 문의 대응 | GAP | 없음 | 보안 신고 및 대응 채널 |
| SA-07 | 구성요소 식별 | IMPLEMENTED | SBOM, Inventory Validation | OS 및 내장 구성요소 확대 |
| SA-08 | 알려진 취약점 탐지 | IMPLEMENTED | pip-audit, SCA JSON | 추가 생태계 및 탐지 도구 적용 |
| SA-09 | 위험 및 영향도 분석 | PARTIAL | cve_triage.md, severity.yaml | 전체 발견 항목 영향도 검토 |
| SA-10 | 취약점 조치 및 재검증 | IMPLEMENTED | 조치 전후 SCA 및 CI 결과 | 동적 검증 및 운영 영향 분석 |
| SA-11 | 위험 수용 및 예외 관리 | PARTIAL | exception_manager.py | 실제 승인 및 권한 검증 |
| SA-12 | 배포 이후 취약점 관리 | DOCUMENTED | vulnerability_response_policy.md | 정기 검사 및 모니터링 |
| SA-13 | 취약점 공개 및 대응 | GAP | 없음 | 취약점 신고 및 공개 절차 |
| SA-14 | 적합성 선언 및 유지 | GAP | 없음 | 전체 요구사항 검토 및 승인 |

## 6. 주요 기술적 성과

### 6.1. 소프트웨어 구성요소 관리

실제 컨테이너에 설치된 Python 패키지를
대상으로 SBOM을 생성하였다.

패키지 인벤토리, SCA 및 SBOM의
정합성을 검증하였다.

라이선스 정보가 누락된 SBOM을 확인하고
설치 패키지 메타데이터를 활용하여
라이선스 표현식을 보강하였다.

라이선스 메타데이터 포함률을
0/8에서 8/8로 개선하였다.

다만 라이선스 원문 검토 및
법적 의무 이행까지 완료한 것은 아니다.

### 6.2. 알려진 취약점 관리

컨테이너 실행 환경에서 원본 탐지 레코드
56건을 식별하고 중복 제거를 통해
29개의 고유 탐지 레코드를 관리하였다.

의존성 업데이트 및 불필요한 패키지
제거 이후 SCA를 재수행하였다.

조치 후 검사에서 알려진 Python 패키지
취약점 탐지 레코드는 0건이었다.

주요 CVE 3건에 대한 상세 분석을 수행하였으며
나머지 탐지 레코드의 심각도와 영향도에 대한
개별 검토는 추가로 필요하다.

### 6.3. 정책 기반 보안 검증

심각도별 보안 정책 및 예외 유효성
검증 기능을 구현하였다.

GitHub Actions에서 정책 위반 시
Workflow가 실패하도록 구성하였다.

조치 전 BLOCK 및 조치 후 PASS 결과를
확인하였다.

## 7. 주요 격차 및 개선 우선순위

| 우선순위 | 개선 과제 |
|---|---|
| P1 | 전체 구성요소에 대한 라이선스 원문 및 의무 검토 |
| P1 | 필수 상태 검사 및 병합 통제 적용 |
| P1 | 신규 취약점의 정기 검사 및 모니터링 |
| P1 | UNKNOWN 탐지 레코드의 개별 심각도 검토 |
| P2 | 패키지 해시 및 출처 검증 |
| P2 | OS 패키지 및 vendored 구성요소 식별 |
| P2 | 실제 조직 승인 및 위험 수용 체계 |
| P2 | 보안 문의 및 취약점 신고 절차 |
| P3 | 개발자 교육 및 역량 검증 기록 |
| P3 | 전체 요구사항 기반 정식 적합성 평가 |

## 8. 종합 평가

본 프로젝트는 OSS 식별, SCA, SBOM,
취약점 조치, 예외 관리 및 CI/CD 보안 검증에
관한 기술적 기반을 구현하였다.

라이선스 정보 보강과 관리대장 생성을 통해
오픈소스 거버넌스의 기초 산출물을 확보하였다.

그러나 조직 차원의 라이선스 의무 이행,
실제 승인 체계, 교육, 지속적인 모니터링 및
정식 적합성 평가가 추가적으로 필요하다.

ISO/IEC 5230 및 ISO/IEC 18974의
인증 또는 적합성 선언을 수행하지 않았다.

## 9. 공식 참조 자료

확인일: 2026-11-27

- ISO/IEC 5230:2020
  https://www.iso.org/standard/81039.html

- ISO/IEC 18974:2023
  https://www.iso.org/standard/86450.html

- OpenChain License Compliance
  https://openchainproject.org/license-compliance

- OpenChain Security Assurance
  https://openchainproject.org/security-assurance

- OpenChain Adoption Guide
  https://openchainproject.org/get-started

- OpenChain License Compliance Specification
  https://github.com/OpenChain-Project/License-Compliance-Specification

- OpenChain Security Assurance Specification
  https://github.com/OpenChain-Project/Security-Assurance-Specification

## 10. 분석의 한계

본 문서는 공개된 공식 자료를 참고하여
주요 요구 영역과 프로젝트 산출물을
비교한 사전 격차 분석이다.

전체 세부 요구사항을 대상으로 한
공식 적합성 심사 또는 인증 결과가 아니다.

실제 금융기관의 내부 정책이나
법적 규제 준수를 보증하지 않는다.
