// ════════════════════════════════════════════════════════
// 인게임 연동 API
// FiveM 서버에서만 호출 (x-game-secret 인증)
// ════════════════════════════════════════════════════════

// server/.env에 추가:
// GAME_SECRET=FiveM서버와_공유하는_랜덤_시크릿키

function gameMiddleware(req, res, next) {
  if (req.headers['x-game-secret'] !== process.env.GAME_SECRET)
    return res.status(403).json({ ok: false, reason: '게임서버 인증 실패' });
  next();
}

// POST /api/game/transaction
// FiveM에서 금고 입출금 발생 시 호출
app.post('/api/game/transaction', gameMiddleware, async (req, res) => {
  const { factionId, type, amount, description, playerName, source } = req.body;

  if (!factionId || !type || !amount)
    return res.status(400).json({ ok: false, reason: '필수 값 누락' });
  if (!['in', 'out'].includes(type))
    return res.status(400).json({ ok: false, reason: 'type은 in 또는 out' });
  if (amount <= 0)
    return res.status(400).json({ ok: false, reason: '금액은 0보다 커야 함' });

  // 팩션 존재 확인
  const factionRef = db.collection('factions').doc(factionId);
  const factionDoc = await factionRef.get();
  if (!factionDoc.exists)
    return res.status(404).json({ ok: false, reason: '팩션 없음' });

  const currentBalance = factionDoc.data().balance || 0;

  // 잔액 부족 체크
  if (type === 'out' && currentBalance < amount)
    return res.status(400).json({ ok: false, reason: '잔액 부족', balance: currentBalance });

  const newBalance = type === 'in' ? currentBalance + amount : currentBalance - amount;

  // Firestore 배치 쓰기
  const batch = db.batch();

  // 팩션 잔액 업데이트
  batch.update(factionRef, {
    balance:   newBalance,
    updatedAt: admin.firestore.FieldValue.serverTimestamp(),
  });

  // 거래 내역 저장
  const txRef = factionRef.collection('transactions').doc();
  batch.set(txRef, {
    type,
    amount,
    balance:     newBalance,
    description: description || (type === 'in' ? '인게임 입금' : '인게임 출금'),
    playerName:  playerName || '알 수 없음',
    source:      source || 'ingame',   // 'ingame' | 'web' | 'admin'
    createdAt:   admin.firestore.FieldValue.serverTimestamp(),
  });

  // 활동 로그
  const logRef = factionRef.collection('activity_logs').doc();
  batch.set(logRef, {
    type:    'vault_transaction',
    message: `${playerName || '알 수 없음'}이 금고 ${type === 'in' ? '입금' : '출금'} $${amount.toLocaleString()}`,
    amount,
    txType:  type,
    source:  'ingame',
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
  });

  await batch.commit();

  // Realtime Database로 잔액 실시간 브로드캐스트 (웹에서 즉시 반영)
  await rtdb.ref(`factions/${factionId}/vault`).set({
    balance:   newBalance,
    updatedAt: Date.now(),
  });

  // Discord 웹훅 전송 (설정된 경우)
  const webhookUrl = factionDoc.data().webhooks?.vault;
  if (webhookUrl) {
    sendDiscordWebhook(webhookUrl, {
      embeds: [{
        color:  type === 'in' ? 0x22C55E : 0xEF4444,
        title:  type === 'in' ? '💰 금고 입금' : '💸 금고 출금',
        fields: [
          { name: '금액',    value: `$${amount.toLocaleString()}`,     inline: true },
          { name: '잔액',    value: `$${newBalance.toLocaleString()}`,  inline: true },
          { name: '플레이어', value: playerName || '알 수 없음',         inline: true },
          { name: '내용',    value: description || '-',                 inline: false },
        ],
        timestamp: new Date().toISOString(),
        footer: { text: 'Turn City 인트라넷' },
      }],
    }).catch(() => {});
  }

  res.json({ ok: true, balance: newBalance, txId: txRef.id });
});

// GET /api/game/vault/:factionId
// FiveM에서 현재 잔액 조회
app.get('/api/game/vault/:factionId', gameMiddleware, async (req, res) => {
  const factionDoc = await db.collection('factions').doc(req.params.factionId).get();
  if (!factionDoc.exists)
    return res.status(404).json({ ok: false, reason: '팩션 없음' });

  res.json({ ok: true, balance: factionDoc.data().balance || 0 });
});

// ── Discord 웹훅 전송 헬퍼 ──────────────────────────────
async function sendDiscordWebhook(url, payload) {
  await axios.post(url, payload, {
    headers: { 'Content-Type': 'application/json' },
  });
}
