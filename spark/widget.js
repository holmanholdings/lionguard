/**
 * Spark Chat Widget — Drop-in embed for awakened-intelligence.com
 * 
 * Add to any page:
 * <script src="https://your-domain.com/spark/widget.js" 
 *   data-spark-url="https://spark-api.up.railway.app"></script>
 */
(function() {
  const SPARK_URL = document.currentScript?.getAttribute('data-spark-url') 
    || 'http://localhost:8100';

  const STYLES = `
    #spark-widget {
      position: fixed;
      bottom: 20px;
      right: 20px;
      z-index: 10000;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    }
    #spark-toggle {
      width: 56px; height: 56px;
      border-radius: 50%;
      background: linear-gradient(135deg, #0a0f1a 0%, #1a2332 100%);
      border: 2px solid #06b6d4;
      cursor: pointer;
      display: flex; align-items: center; justify-content: center;
      font-size: 28px;
      box-shadow: 0 4px 20px rgba(6, 182, 212, 0.3);
      transition: transform 0.2s, box-shadow 0.2s;
    }
    #spark-toggle:hover {
      transform: scale(1.1);
      box-shadow: 0 6px 30px rgba(6, 182, 212, 0.5);
    }
    #spark-panel {
      display: none;
      position: absolute;
      bottom: 70px; right: 0;
      width: 360px; height: 480px;
      background: #0a0f1a;
      border: 1px solid #1e293b;
      border-radius: 16px;
      overflow: hidden;
      box-shadow: 0 8px 40px rgba(0,0,0,0.5);
      flex-direction: column;
    }
    #spark-panel.open { display: flex; }
    #spark-header {
      padding: 14px 16px;
      background: #111827;
      border-bottom: 1px solid #1e293b;
      display: flex; align-items: center; gap: 10px;
    }
    #spark-header-dot {
      width: 8px; height: 8px;
      background: #22c55e;
      border-radius: 50%;
    }
    #spark-header-text {
      color: #f1f5f9;
      font-size: 14px; font-weight: 600;
    }
    #spark-header-sub {
      color: #64748b;
      font-size: 11px;
      margin-left: auto;
    }
    #spark-messages {
      flex: 1;
      overflow-y: auto;
      padding: 12px;
      display: flex; flex-direction: column; gap: 8px;
    }
    .spark-msg {
      max-width: 85%;
      padding: 10px 14px;
      border-radius: 12px;
      font-size: 13px;
      line-height: 1.5;
      word-wrap: break-word;
    }
    .spark-msg.bot {
      background: #111827;
      color: #e2e8f0;
      align-self: flex-start;
      border: 1px solid #1e293b;
    }
    .spark-msg.user {
      background: #06b6d4;
      color: #0a0f1a;
      align-self: flex-end;
      font-weight: 500;
    }
    .spark-msg.blocked {
      background: #1e1b2e;
      border: 1px solid #f59e0b;
      color: #f59e0b;
    }
    #spark-input-area {
      padding: 10px;
      border-top: 1px solid #1e293b;
      display: flex; gap: 8px;
    }
    #spark-input {
      flex: 1;
      background: #111827;
      border: 1px solid #1e293b;
      border-radius: 8px;
      padding: 8px 12px;
      color: #f1f5f9;
      font-size: 13px;
      outline: none;
    }
    #spark-input:focus { border-color: #06b6d4; }
    #spark-send {
      background: #06b6d4;
      color: #0a0f1a;
      border: none;
      border-radius: 8px;
      padding: 8px 14px;
      font-weight: 600;
      cursor: pointer;
      font-size: 13px;
    }
    #spark-send:hover { background: #0891b2; }
    #spark-send:disabled { opacity: 0.5; cursor: not-allowed; }
  `;

  const style = document.createElement('style');
  style.textContent = STYLES;
  document.head.appendChild(style);

  const widget = document.createElement('div');
  widget.id = 'spark-widget';
  widget.innerHTML = `
    <div id="spark-panel">
      <div id="spark-header">
        <div id="spark-header-dot"></div>
        <div id="spark-header-text">Spark</div>
        <div id="spark-header-sub">Lionguard Community Guide</div>
      </div>
      <div id="spark-messages">
        <div class="spark-msg bot">Hey! I'm Spark, your Lionguard community guide. Ask me about AI agent security, cost tracking, or why lobsters make the best developers. ⚡🦞</div>
      </div>
      <div id="spark-input-area">
        <input id="spark-input" placeholder="Ask Spark anything..." autocomplete="off" />
        <button id="spark-send">Send</button>
      </div>
    </div>
    <div id="spark-toggle">🦞</div>
  `;
  document.body.appendChild(widget);

  const toggle = document.getElementById('spark-toggle');
  const panel = document.getElementById('spark-panel');
  const input = document.getElementById('spark-input');
  const sendBtn = document.getElementById('spark-send');
  const messages = document.getElementById('spark-messages');

  toggle.addEventListener('click', () => {
    panel.classList.toggle('open');
    if (panel.classList.contains('open')) input.focus();
  });

  async function sendMessage() {
    const text = input.value.trim();
    if (!text) return;

    const userMsg = document.createElement('div');
    userMsg.className = 'spark-msg user';
    userMsg.textContent = text;
    messages.appendChild(userMsg);
    input.value = '';
    sendBtn.disabled = true;
    messages.scrollTop = messages.scrollHeight;

    try {
      const res = await fetch(SPARK_URL + '/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: text }),
      });
      const data = await res.json();
      const botMsg = document.createElement('div');
      botMsg.className = data.blocked ? 'spark-msg blocked' : 'spark-msg bot';
      botMsg.textContent = data.reply;
      messages.appendChild(botMsg);
    } catch (err) {
      const errMsg = document.createElement('div');
      errMsg.className = 'spark-msg bot';
      errMsg.textContent = "I'm having trouble connecting. Try again in a moment! ⚡";
      messages.appendChild(errMsg);
    }

    sendBtn.disabled = false;
    messages.scrollTop = messages.scrollHeight;
    input.focus();
  }

  sendBtn.addEventListener('click', sendMessage);
  input.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') sendMessage();
  });
})();
