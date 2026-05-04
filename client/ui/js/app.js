// Chrono-shift UI App
const $=s=>document.querySelector(s),$$=s=>document.querySelectorAll(s);
let friends=[],pending=[],messages={},activeChat=null;

// Init
API.on('status',s=>{ $('#status').textContent=s==='online'?'● 在线':'○ 离线'; $('#status').className='status'+(s==='online'?' online':''); });
API.on('message',m=>{ (messages[m.from]||=[]).push(m); if(activeChat===m.from) renderMessages(); renderChatList(); });
API.connect();

// Tabs
$$('.tab').forEach(t=>t.onclick=()=>{ $$('.tab,.panel').forEach(e=>e.classList.remove('active')); t.classList.add('active'); $(`#tab-${t.dataset.tab}`).classList.add('active'); });

// UID
$('#btn-save-uid').onclick=()=>{ const v=$('#set-uid').value.trim(); if(v){API.uid=v;$('#set-uid').placeholder=v;} };

// Transport
$('#btn-connect').onclick=()=>{ const t=$('#set-transport').value; API.cmd(t==='tor'?'tor start':t==='i2p'?'i2p start':''); };

// Friend
$('#friend-form').onsubmit=e=>{ e.preventDefault(); const uid=$('#friend-uid').value.trim(); if(uid){ API.cmd(`friend add ${uid}`).then(()=>refreshFriends()); $('#friend-uid').value=''; }};
function refreshFriends(){ API.cmd('friend list').then(r=>{ if(r) renderFriends(); }); API.cmd('friend pending').then(r=>{ if(r) renderPending(); }); }

// Message
$('#msg-form').onsubmit=e=>{ e.preventDefault(); const t=$('#msg-input').value.trim(); if(t&&activeChat){ API.cmd(`msg send ${activeChat} ${t}`); addMsg('self',t); $('#msg-input').value=''; }};

// Image upload
$('#btn-img').onclick=()=>$('#img-input').click();
$('#img-input').onchange=async()=>{ const f=$('#img-input').files[0]; if(f&&activeChat){ const b64=await API.uploadImage(f); addMsg('self',`<img src="${b64}">`); }};

function addMsg(type,text){ const d=document.createElement('div'); d.className='msg '+type; d.innerHTML=`<div class="meta">${new Date().toLocaleTimeString()}</div>${text}`; $('#messages').appendChild(d); $('#messages').scrollTop=$('#messages').scrollHeight; }

function renderChatList(){ const c=$('#chat-list'); c.innerHTML=Object.keys(messages).map(u=>`<div class="friend-item" data-uid="${u}" onclick="openChat('${u}')">${u}</div>`).join('')||'<div class="empty">暂无聊天</div>'; }
function renderFriends(){ $('#friend-list').innerHTML=friends.map(u=>`<div class="friend-item"><span>${u}</span></div>`).join('')||'<div class="empty">暂无好友</div>'; }
function renderPending(){ $('#pending-list').innerHTML=pending.map(r=>`<div class="pending-item"><span>${r.from_uid}</span><button onclick="API.cmd('friend accept ${r.from_uid}').then(refreshFriends)">接受</button><button onclick="API.cmd('friend reject ${r.from_uid}').then(refreshFriends)">拒绝</button></div>`).join(''); }
function openChat(uid){ activeChat=uid; $('#messages').innerHTML=''; (messages[uid]||[]).forEach(m=>{ addMsg(m.from===API.uid?'self':'other',m.text); }); }

// User CSS toggle
$('#toggle-user-css').onchange=function(){ $('#user-theme').disabled=!this.checked; };
refreshFriends(); setInterval(refreshFriends,5000);
