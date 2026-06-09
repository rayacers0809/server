# Turn City API 서버

## 설치 및 실행

```bash
npm install
cp .env.example .env
# .env 값 채우기
# serviceAccountKey.json을 이 폴더에 배치
npm run dev
```

## Railway 배포

1. Railway → New Project → Deploy from GitHub
2. 환경변수 설정:
   - `FIREBASE_SERVICE_ACCOUNT_JSON`: serviceAccountKey.json 내용 전체
   - 나머지 .env.example 참고
3. Start Command: `node index.js`

## API 엔드포인트

| 메서드 | 경로 | 설명 |
|--------|------|------|
| GET | `/auth/discord` | Discord OAuth 시작 |
| GET | `/auth/discord/callback` | OAuth 콜백 |
| GET | `/auth/me` | 현재 유저 정보 |
| POST | `/api/intranet/verify` | 코드 검증 + 팩션 생성 |
| POST | `/api/bot/issue-code` | 봇 → 코드 저장 |
| DELETE | `/api/bot/cancel-code/:targetId` | 봇 → 코드 취소 |
| GET | `/api/bot/active-codes` | 봇 → 활성 코드 목록 |
| GET | `/health` | 헬스 체크 |
