// ╔══════════════════════════════════════════════════════╗
// ║   Turn City API 서버                                  ║
// ║   Firebase Admin SDK + Discord OAuth + 봇 연동        ║
// ╚══════════════════════════════════════════════════════╝

const express = require('express');
const session = require('express-session');
const cors    = require('cors');
const axios   = require('axios');
const admin   = require('firebase-admin');
require('dotenv').config();

// ─── Firebase Admin 초기화 ────────────────────────────
let serviceAccount;
if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
  // Railway 등 환경변수로 JSON 통째로 넣은 경우
  serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
} else {
  // 로컬: serviceAccountKey.json 파일 직접 읽기
  serviceAccount = require(process.env.FIREBASE_SERVICE_ACCOUNT_PATH || './serviceAccountKey.json');
}

admin.initializeApp({
  credential:  admin.credential.cert(serviceAccount),
  databaseURL: process.env.FIREBASE_DATABASE_URL,
  storageBucket: `${process.env.FIREBASE_PROJECT_ID}.firebasestorage.app`,
  projectId: process.env.FIREBASE_PROJECT_ID,
});

const db      = admin.firestore(admin.app(), 'default');
db.settings({ ignoreUndefinedProperties: true });
const rtdb    = admin.database();
const storage = admin.storage();

// Firestore 서울 리전 설정


// ─── Express ─────────────────────────────────────────
const app  = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// CORS - 여러 도메인 허용 (pages.dev + 커스텀 도메인)
const allowedOrigins = [
  process.env.CLIENT_URL,
  process.env.ADMIN_URL,
  'https://turnintranet.com',
  'https://turn-intranet.pages.dev',
  'https://turn-admin.pages.dev',
  'http://localhost:5173',
  'http://localhost:3000',
].filter(Boolean);

app.use(cors({
  origin: function(origin, callback) {
    // origin 없는 요청(서버간/curl)도 허용
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    return callback(null, true); // 일단 모두 허용 (프로덕션에선 false 권장)
  },
  credentials: true,
}));

// 프록시(Railway) 뒤에서 secure 쿠키 작동하게
app.set('trust proxy', 1);

const isProd = process.env.NODE_ENV === 'production' || !!process.env.CLIENT_URL?.startsWith('https');
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-this',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: isProd,                          // HTTPS에서만 secure
    sameSite: isProd ? 'none' : 'lax',       // 크로스 도메인 쿠키
    maxAge: 7 * 24 * 60 * 60 * 1000,
  },
}));

// ─── 유틸 ────────────────────────────────────────────
function generateCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  return Array.from({ length: 6 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
}

async function authMiddleware(req, res, next) {
  // 1. 세션 체크
  if (req.session.userId) { next(); return; }

  // 2. Authorization: Bearer <Firebase ID Token>
  const authHeader = req.headers['authorization'] || '';
  if (authHeader.startsWith('Bearer ')) {
    const idToken = authHeader.slice(7);
    try {
      const decoded = await admin.auth().verifyIdToken(idToken);
      req.session.userId   = decoded.uid;
      req.session.username = decoded.name || decoded.uid;
      next(); return;
    } catch(e) {
      return res.status(401).json({ ok: false, reason: '토큰 인증 실패: ' + e.message });
    }
  }

  return res.status(401).json({ ok: false, reason: '로그인이 필요합니다.' });
}

function botMiddleware(req, res, next) {
  if (req.headers['x-bot-secret'] !== process.env.BOT_SECRET)
    return res.status(403).json({ ok: false, reason: '봇 인증 실패' });
  next();
}

// ════════════════════════════════════════════════════════
// DISCORD OAUTH
// ════════════════════════════════════════════════════════

// GET /auth/discord → Discord 로그인 리다이렉트
app.get('/auth/discord', (req, res) => {
  const params = new URLSearchParams({
    client_id:     process.env.DISCORD_CLIENT_ID,
    redirect_uri:  process.env.DISCORD_REDIRECT_URI,
    response_type: 'code',
    scope:         'identify',
  });
  res.redirect(`https://discord.com/oauth2/authorize?${params}`);
});

// GET /auth/discord/callback
app.get('/auth/discord/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.redirect(`${process.env.CLIENT_URL}?error=no_code`);

  try {
    // code → access_token
    const tokenRes = await axios.post(
      'https://discord.com/api/oauth2/token',
      new URLSearchParams({
        client_id:     process.env.DISCORD_CLIENT_ID,
        client_secret: process.env.DISCORD_CLIENT_SECRET,
        grant_type:    'authorization_code',
        code,
        redirect_uri:  process.env.DISCORD_REDIRECT_URI,
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    const { access_token } = tokenRes.data;

    // 유저 정보
    const userRes = await axios.get('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${access_token}` },
    });
    const du = userRes.data;

    const avatarUrl = du.avatar
      ? `https://cdn.discordapp.com/avatars/${du.id}/${du.avatar}.png?size=128`
      : `https://cdn.discordapp.com/embed/avatars/${Number(du.discriminator || 0) % 5}.png`;

    // Firebase Auth custom token 발급 (uid = discord id)
    const customToken = await admin.auth().createCustomToken(du.id, {
      discordId: du.id,
      username:  du.username,
    });

    // Firestore 유저 문서 upsert
    await db.collection('users').doc(du.id).set({
      discordId:   du.id,
      username:    du.username,
      avatar:      avatarUrl,
      lastLogin:   admin.firestore.FieldValue.serverTimestamp(),
    }, { merge: true });

    // 세션 저장
    req.session.userId   = du.id;
    req.session.username = du.username;
    req.session.avatar   = avatarUrl;

    // 프론트로 custom token 전달 (프론트에서 signInWithCustomToken 호출)
    const clientUrl = (process.env.CLIENT_URL || '').replace(/\/$/, '');
    const mode = req.session.oauthMode || '';
    req.session.oauthMode = null;
    const modeParam = mode ? `&mode=${mode}` : '';
    res.redirect(`${clientUrl}/auth/success?token=${customToken}${modeParam}`);

  } catch (err) {
    console.error('[OAuth Error]', err.response?.data || err.message);
    console.error('[OAuth Error Detail]', err.stack || err);
    const clientUrl2 = (process.env.CLIENT_URL || '').replace(/\/$/, '');
    res.redirect(`${clientUrl2}?error=oauth_failed`);
  }
});

// GET /auth/me
app.get('/auth/me', (req, res) => {
  if (!req.session.userId) return res.json({ ok: false, user: null });
  res.json({ ok: true, user: { id: req.session.userId, username: req.session.username, avatar: req.session.avatar } });
});

// POST /auth/logout
app.post('/auth/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

// ════════════════════════════════════════════════════════
// 인트라넷 코드 검증 & 팩션 생성
// ════════════════════════════════════════════════════════
app.post('/api/intranet/verify', authMiddleware, async (req, res) => {
  const { code, founderRankName } = req.body;
  if (!code) return res.status(400).json({ ok: false, reason: '코드를 입력해주세요.' });

  // 코드 조회
  const snap = await db.collection('intranetCodes')
    .where('code', '==', code.toUpperCase())
    .where('used', '==', false)
    .limit(1)
    .get();

  if (snap.empty) return res.status(404).json({ ok: false, reason: '유효하지 않은 코드입니다.' });

  const codeDoc  = snap.docs[0];
  const codeData = codeDoc.data();

  // 만료 체크
  const now       = Date.now();
  const expiresAt = codeData.expiresAt?.toDate?.()?.getTime() || 0;
  if (now > expiresAt) {
    await codeDoc.ref.delete();
    return res.status(400).json({ ok: false, reason: '만료된 코드입니다.' });
  }

  // 대상 유저 체크
  if (codeData.targetId && req.session.userId !== codeData.targetId)
    return res.status(403).json({ ok: false, reason: '이 코드는 다른 유저에게 발급된 코드입니다.' });

  const userId    = req.session.userId;
  const joinCode  = generateCode();
  const allPerms  = ['rp_write','rp_approve','trade_write','trade_approve','notice_write','attendance_edit','member_manage','rank_manage','warn_give','account_view','account_manage','settings','theme'];

  // Firestore 배치 쓰기
  const batch = db.batch();

  // 팩션 문서
  const factionRef = db.collection('factions').doc();
  batch.set(factionRef, {
    factionName:  req.body.factionName || codeData.factionName || '새 팩션',
    factionType:  req.body.factionType  || codeData.factionType  || '기타',
    founderId:    userId,
    joinCode,
    webhooks:     { rp: '', trade: '', warn: '', notice: '', member: '' },
    settings:     { rpEnabled: true, tradeEnabled: true, rpApprovalRequired: true, tradeAudit: true, rankSystem: true, attendanceAuto: true },
    theme:        { primaryColor: '#2563EB' },
    createdAt:    admin.firestore.FieldValue.serverTimestamp(),
    memberCount:  1,
  });

  // 팩션장 직급 생성
  const rankRef = factionRef.collection('ranks').doc();
  const founderRankData = {
    name:      founderRankName || codeData.founderRankName || '팩션장',
    rankClass: '고위직',
    perms:     allPerms,
    isFounder: true,
    order:     1,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
  };
  batch.set(rankRef, founderRankData);

  // 팩션원 문서 (팩션장)
  const memberRef = factionRef.collection('members').doc(userId);
  batch.set(memberRef, {
    userId,
    username:   req.session.username,
    avatar:     req.session.avatar || '',
    rankId:     rankRef.id,
    rankName:   founderRankData.name,
    rankClass:  '고위직',
    isFounder:  true,
    perms:      allPerms,
    status:     'approved',
    joinedAt:   admin.firestore.FieldValue.serverTimestamp(),
    rp_score:   0,
    trade_count:0,
    warn_count: 0,
  });

  // 코드 사용 처리
  batch.update(codeDoc.ref, {
    used:     true,
    usedAt:   admin.firestore.FieldValue.serverTimestamp(),
    usedBy:   userId,
    factionId: factionRef.id,
  });

  // 유저 → 팩션 연결
  const userRef = db.collection('users').doc(userId);
  batch.update(userRef, { factionId: factionRef.id });

  await batch.commit();

  // 활동 로그
  await factionRef.collection('activity_logs').add({
    type:      'faction_created',
    message:   `팩션이 창설되었습니다.`,
    userId,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
  });

  res.json({ ok: true, factionId: factionRef.id, factionName: req.body.factionName || codeData.factionName, joinCode });
});

// ════════════════════════════════════════════════════════
// 봇 ↔ 서버 API (botMiddleware 인증)
// ════════════════════════════════════════════════════════

// POST /api/bot/issue-code
app.post('/api/bot/issue-code', botMiddleware, async (req, res) => {
  const { code, targetId, factionName, factionType, founderRankName, issuedBy } = req.body;
  if (!code || !targetId) return res.status(400).json({ ok: false, reason: '필수 값 누락' });

  await db.collection('intranetCodes').doc(code).set({
    code,
    targetId,
    factionName:      factionName || '미정',
    factionType:      factionType || '기타',
    founderRankName:  founderRankName || '팩션장',
    issuedBy,
    createdAt:  admin.firestore.FieldValue.serverTimestamp(),
    expiresAt:  admin.firestore.Timestamp.fromDate(new Date(Date.now() + 24 * 60 * 60 * 1000)),
    used:       false,
    usedAt:     null,
    usedBy:     null,
  });

  res.json({ ok: true });
});

// DELETE /api/bot/cancel-code/:targetId
app.delete('/api/bot/cancel-code/:targetId', botMiddleware, async (req, res) => {
  const snap = await db.collection('intranetCodes')
    .where('targetId', '==', req.params.targetId)
    .where('used', '==', false)
    .get();

  const batch = db.batch();
  snap.docs.forEach(d => batch.delete(d.ref));
  await batch.commit();

  res.json({ ok: true, deleted: snap.size });
});

// GET /api/bot/active-codes
app.get('/api/bot/active-codes', botMiddleware, async (req, res) => {
  const snap = await db.collection('intranetCodes')
    .where('used', '==', false)
    .orderBy('createdAt', 'desc')
    .limit(20)
    .get();

  const codes = snap.docs.map(d => ({
    ...d.data(),
    expiresAt: d.data().expiresAt?.toDate?.()?.getTime() || 0,
    createdAt: d.data().createdAt?.toDate?.()?.getTime() || 0,
  }));

  res.json({ ok: true, codes });
});

// ════════════════════════════════════════════════════════
// 팩션 API
// ════════════════════════════════════════════════════════

// GET /api/faction/me
app.get('/api/faction/me', authMiddleware, async (req, res) => {
  const userDoc = await db.collection('users').doc(req.session.userId).get();
  if (!userDoc.exists || !userDoc.data().factionId)
    return res.json({ ok: false, reason: '소속 팩션 없음' });

  const factionId  = userDoc.data().factionId;
  const factionDoc = await db.collection('factions').doc(factionId).get();
  if (!factionDoc.exists) return res.json({ ok: false, reason: '팩션 없음' });

  const memberDoc = await db.collection('factions').doc(factionId)
    .collection('members').doc(req.session.userId).get();

  res.json({
    ok: true,
    faction: { id: factionId, ...factionDoc.data() },
    member:  memberDoc.exists ? memberDoc.data() : null,
  });
});


// ════════════════════════════════════════════════════════
// 관리자 패널 API
// ════════════════════════════════════════════════════════
const crypto = require('crypto');

function adminMiddleware(req, res, next) {
  const token  = req.headers['x-admin-token'] || '';
  const pwHash = process.env.ADMIN_PW_HASH ||
    crypto.createHash('sha256').update('turncity2026@').digest('hex');
  if (!token || token !== pwHash)
    return res.status(403).json({ ok: false, reason: '관리자 인증 실패' });
  next();
}

// GET /api/admin/factions
app.get('/api/admin/factions', adminMiddleware, async (req, res) => {
  const snap = await db.collection('factions').orderBy('createdAt', 'desc').get();
  const factions = snap.docs.map(d => ({
    id:          d.id,
    name:        d.data().factionName,
    type:        d.data().factionType,
    color:       d.data().theme?.primaryColor || '#2563EB',
    memberCount: d.data().memberCount || 0,
    active:      d.data().active !== false,
    createdAt:   d.data().createdAt?.toDate?.()?.toLocaleDateString('ko-KR') || '',
    webhooks:    d.data().webhooks || {},
  }));
  res.json({ ok: true, factions });
});

// GET /api/admin/codes
app.get('/api/admin/codes', adminMiddleware, async (req, res) => {
  const snap = await db.collection('intranetCodes')
    .where('used', '==', false)
    .orderBy('createdAt', 'desc')
    .limit(50)
    .get();
  res.json({ ok: true, codes: snap.docs.map(d => ({ id: d.id, ...d.data() })) });
});

// GET /api/admin/logs
app.get('/api/admin/logs', adminMiddleware, async (req, res) => {
  try {
    const snap = await db.collectionGroup('activity_logs')
      .orderBy('createdAt', 'desc')
      .limit(50)
      .get();
    res.json({ ok: true, logs: snap.docs.map(d => ({ id: d.id, ...d.data() })) });
  } catch {
    res.json({ ok: true, logs: [] });
  }
});

// POST /api/admin/issue-code
app.post('/api/admin/issue-code', adminMiddleware, async (req, res) => {
  const { userId, factionName, factionType, founderRankName } = req.body;
  if (!userId || !factionName) return res.status(400).json({ ok: false, reason: '필수 값 누락' });

  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const code  = Array.from({ length: 6 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');

  await db.collection('intranetCodes').doc(code).set({
    code, targetId: userId,
    factionName:     factionName || '미정',
    factionType:     factionType || '기타',
    founderRankName: founderRankName || '팩션장',
    issuedBy:        'admin-panel',
    createdAt:       admin.firestore.FieldValue.serverTimestamp(),
    expiresAt:       admin.firestore.Timestamp.fromDate(new Date(Date.now() + 24*60*60*1000)),
    used: false, usedAt: null, usedBy: null,
  });
  res.json({ ok: true, code });
});

// DELETE /api/admin/cancel-code/:targetId
app.delete('/api/admin/cancel-code/:targetId', adminMiddleware, async (req, res) => {
  const snap = await db.collection('intranetCodes')
    .where('targetId', '==', req.params.targetId)
    .where('used', '==', false).get();
  const batch = db.batch();
  snap.docs.forEach(d => batch.delete(d.ref));
  await batch.commit();
  res.json({ ok: true, deleted: snap.size });
});

// PUT /api/admin/faction/:factionId/webhooks
app.put('/api/admin/faction/:factionId/webhooks', adminMiddleware, async (req, res) => {
  await db.collection('factions').doc(req.params.factionId).update({ webhooks: req.body.webhooks });
  res.json({ ok: true });
});

// PUT /api/admin/faction/:factionId/status
app.put('/api/admin/faction/:factionId/status', adminMiddleware, async (req, res) => {
  await db.collection('factions').doc(req.params.factionId).update({ active: req.body.active });
  res.json({ ok: true });
});

// POST /api/admin/webhook-test - Discord 웹훅 테스트 전송
app.post('/api/admin/webhook-test', adminMiddleware, async (req, res) => {
  const { url, type } = req.body;
  if (!url || !url.includes('discord.com/api/webhooks/')) {
    return res.status(400).json({ ok: false, reason: '올바른 Discord 웹훅 URL이 아닙니다.' });
  }
  const typeNames = { rp:'RP 보고서', trade:'거래 보고서', warn:'내부경고', notice:'공지사항', member:'팩션원' };
  try {
    await axios.post(url, {
      username: 'Turn City 인트라넷',
      embeds: [{
        title: `✅ ${typeNames[type] || '웹훅'} 테스트`,
        description: '웹훅이 정상적으로 연결되었습니다.',
        color: 0x2563EB,
        footer: { text: 'Turn City Intranet' },
        timestamp: new Date().toISOString(),
      }],
    });
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ ok: false, reason: '웹훅 전송 실패 (URL 확인 필요)' });
  }
});

// ─── 헬스 체크 ──────────────────────────────────────────
app.get('/health', async (req, res) => {
  res.json({ ok: true, uptime: process.uptime(), project: process.env.FIREBASE_PROJECT_ID });
});

app.listen(PORT, () => console.log(`[Turn City API] http://localhost:${PORT}`));
module.exports = app;
