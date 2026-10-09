# 로뎀가드 현장 운용 가이드

## 구성 개요

```
┌─────────────────────┐          ┌──────────────────────────┐
│  🏢 사무실 Mac mini  │◄─ VPN ──►│  🏭 고객사 MacBook Pro    │
│  M4 64GB (상시 구동)  │          │  M1 16GB (현장 휴대)      │
│                     │          │                          │
│  ✅ PostgreSQL      │          │  ✅ Field Agent (수집만)   │
│  ✅ Redis           │          │  ✅ Inspector (SSH/WinRM) │
│  ✅ MinIO           │          │  ✅ SQLite (오프라인 버퍼)  │
│  ✅ Ollama LLM      │          │  ❌ DB/LLM/보고서 없음    │
│  ✅ FastAPI         │          │                          │
│  ✅ 대시보드         │          │  고객 서버 SSH 직접 접근    │
│  ✅ 판정 엔진       │          │                          │
│  ✅ 보고서 생성      │          │                          │
└─────────────────────┘          └──────────────────────────┘
```

## 사전 준비

### 1. Mac mini (사무실) - 한 번만 설정

```bash
# 프로젝트 클론
git clone <repo-url> ~/rotemguard
cd ~/rotemguard

# 환경 설정
cp .env.example .env
# .env에서 비밀번호 설정

# Docker 풀스택 시작
docker compose up -d

# Python 환경
python -m venv .venv
source .venv/bin/activate
pip install -e .

# 서버 시작
uvicorn src.api.main:app --host 0.0.0.0 --port 8800

# Tailscale 설치 (VPN)
# https://tailscale.com/download/mac
# 로그인 후 IP 확인: tailscale ip -4
```

### 2. MacBook Pro (현장용) - 한 번만 설정

```bash
# 프로젝트 클론
git clone <repo-url> ~/rotemguard
cd ~/rotemguard

# Docker Field Kit 빌드
docker compose -f docker-compose.field.yml build

# 또는 Docker 없이 직접 실행
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

### 3. Tailscale VPN 설정

두 기기 모두 같은 Tailscale 계정으로 로그인하면 끝.
Mac mini IP: `100.x.x.x` (tailscale ip -4로 확인)

.env.field 파일 생성:
```
SYNC_TARGET_URL=http://100.x.x.x:8800
OFFLINE_MODE=false
```

## 현장 진단 워크플로우

### 시나리오 A: VPN 연결 가능 (일반 고객사)

```bash
# 1. MacBook Pro에서 Field Agent 시작
cd ~/rotemguard
uvicorn src.field.agent:app --host 0.0.0.0 --port 8801

# 2. 수집 실행
curl -X POST http://localhost:8801/collect \
  -H "Content-Type: application/json" \
  -d '{
    "project_id": 1,
    "hostname": "192.168.1.100",
    "asset_type": "server_unix",
    "username": "root",
    "password": "password123",
    "port": 22
  }'

# 3. 결과 확인
curl http://localhost:8801/results

# 4. 맥미니로 동기화 (자동 또는 수동)
curl -X POST http://localhost:8801/sync

# 5. 맥미니 대시보드에서 판정 결과 확인
# http://100.x.x.x:8800 (Tailscale VPN)
```

### 시나리오 B: 폐쇄망 (VPN 불가)

```bash
# 1~3. 위와 동일 (수집 + 로컬 저장)

# 4. 사무실 복귀 후 내보내기
curl -X POST http://localhost:8801/export

# 5. USB로 field_data/export/ 디렉터리 복사

# 6. 맥미니에서 import
curl -X POST http://localhost:8800/api/v1/sync/upload \
  -H "Content-Type: application/json" \
  -d @exported_results.json
```

### 시나리오 C: 대량 서버 일괄 수집

```bash
# servers.txt (한 줄에 하나씩)
# hostname,ip,type,username,password,port
# web-svr-01,192.168.1.10,server_unix,root,pass123,22
# db-svr-01,192.168.1.20,server_unix,root,pass456,22

# batch_collect.sh
while IFS=',' read -r hostname ip type user pass port; do
  curl -s -X POST http://localhost:8801/collect \
    -H "Content-Type: application/json" \
    -d "{
      \"project_id\": 1,
      \"hostname\": \"$hostname\",
      \"ip_address\": \"$ip\",
      \"asset_type\": \"$type\",
      \"username\": \"$user\",
      \"password\": \"$pass\",
      \"port\": $port
    }"
  echo "✅ $hostname 완료"
done < servers.txt
```

## 포트 정리

| 서비스 | Mac mini | MacBook Pro |
|---|---|---|
| 로뎀가드 서버 | 8800 | - |
| Field Agent | - | 8801 |
| PostgreSQL | 5433 | - |
| Redis | 6380 | - |
| MinIO | 9000/9001 | - |
| ARTEX (기존) | 8787/5432 | 8787/5432 |

모든 포트가 ARTEX와 충돌하지 않습니다.

## 트러블슈팅

### Tailscale 연결 안 될 때
```bash
tailscale status          # 상태 확인
tailscale ping 100.x.x.x # Mac mini 핑
```

### SSH 접속 실패
```bash
# MacBook Pro에서 직접 테스트
ssh -p 22 root@192.168.1.100

# sshpass 필요 시
brew install hudochenkov/sshpass/sshpass
```

### 수집 결과 확인
```bash
# SQLite 직접 조회
sqlite3 field_data/field.db "SELECT hostname, check_item_id, success FROM collection_results ORDER BY collected_at DESC LIMIT 20"
```
