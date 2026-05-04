// Chrono-shift API bridge (WebSocket → CLI backend)
const API = {
  ws: null, connected: false, uid: '', callbacks: {},
  connect(port=9010) {
    this.ws = new WebSocket(`ws://127.0.0.1:${port}/api`);
    this.ws.onopen = () => { this.connected = true; this.emit('status','online'); };
    this.ws.onclose = () => { this.connected = false; this.emit('status','offline'); };
    this.ws.onmessage = e => {
      try { const m = JSON.parse(e.data); this.emit(m.type, m); } catch(_) {}
    };
  },
  send(type, data={}) {
    if (!this.ws || !this.connected) return;
    this.ws.send(JSON.stringify({type, ...data}));
  },
  on(event, fn) { (this.callbacks[event]||=[]).push(fn); },
  emit(event, data) { (this.callbacks[event]||[]).forEach(f=>f(data)); },
  // CLI commands via HTTP fallback
  async cmd(cmd) {
    try {
      const r = await fetch('http://127.0.0.1:9010/api/cmd', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({cmd})
      });
      return await r.json();
    } catch(_) { return null; }
  },
  // Image upload (base64)
  async uploadImage(file) {
    return new Promise((resolve) => {
      const r = new FileReader();
      r.onload = () => resolve(r.result);
      r.readAsDataURL(file);
    });
  }
};
