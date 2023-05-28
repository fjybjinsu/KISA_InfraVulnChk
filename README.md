# KISA_InfraVulnChk
# 1. 개요
KISEC 강의를 수강 후 주통기 전 항목에 대한 취약점 진단 자동화 스크립트를 만들면서, 스크립트 작성 능력 향상과 서버 관리에 대한 공부를 위한 목적으로 UNIX 계열 서버 전체 73개 항목에 대한 스크립트를 작성

# 2. 기술 스택
Bash Shell Script

# 3. 제작 동기
- KISEC 취약점 진단 강의에서 실습하지 않은 내용 학습 및 자동화 시도
- 정보보안기사 시스템 보안 영역 추가 학습

# 4. 역할
- 양진수 1인 개발

# 5 배운 것
- Bash Shell의 문법을 숙달하여 다양한 방식으로 문자열을 조작하는데 자신감을 얻었음
- 서버 보안과 관련된 설정들을 심도 있게 학습할 수 있었음

# 6 보완할 점
- KISEC 강의에서의 CentOS7 이미지를 기반으로 제작하였고, 몇 가지 사용하지 않는 서비스들을 설치하고 테스트한다고 시간이 소요
- 현재 보유 서버 이미지를 기준으로는 정상 동작하지만, 다양한 테스트 케이스를 고려해서 테스트 희망
- 추후 PYTHON을 기반으로 양호/취약/검토 파일들을 플래그로 설정하여 GUI 환경에서 제작 가능 시도 요망

# 7. 실행 방법 및 프로그램 설명(상세 내용 캡처 화면 참고)
- 터미널에서 infra.sh를 실행
- 실행 시 터미널에 항목 별로 진행 상황 표시
- 완료 시, vuln_날짜시간.txt라는 최종 결과 파일 및 result라는 디렉토리가 출력
- result에는 결과가 길어 가독성에 영향을 주는 항목들을 별도 리다이렉션한 항목들 작성
- good.txt 파일은 진단 결과가 '양호'한 항목들만 작성
- bad.txt 파일은 진단 결과가 '취약'한 항목들만 작성
- check.txt 파일은 진단 결과가 '검토'인 항목들만 작성

# 6. 코드 예시
## 실행 결과 vuln_날짜시간.txt 파일 내용
![image](https://github.com/fjybjinsu/KISA_InfraVulnChk/assets/85774577/5d1db54f-441f-4476-9fb3-38dd3c603ca2)
![image](https://github.com/fjybjinsu/KISA_InfraVulnChk/assets/85774577/3d786195-c5fa-48f9-b09a-0baf78a09cc9)

## 터미널 진행 상황 출력
![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/2718e0c1-e16c-4e41-86c7-a066ffb28bf0/Untitled.png)

## 실행 후 생성된 디렉토리 및 결과 파일
![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/30e753e7-289c-44a4-8444-d181c25d84a2/Untitled.png)

## result 디렉토리 내부 상세 결과 및 결과 분류 파일
![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/e1041ca9-e9b8-434a-9487-3812a64a9e07/Untitled.png)

## 진단 결과 '양호' 항목(good.txt)
![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/ab43235e-6979-4c06-af4a-9e3e9ecce98a/Untitled.png)

## 진단 결과 '검토' 항목(check.txt)
![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/4206e402-697c-4beb-8a5a-f2d3a45c7d86/Untitled.png)

## 진단 결과 '취약' 항목(bad.txt)
![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/c6975bf1-b4a7-4e93-9937-637effcdbe6c/Untitled.png)
