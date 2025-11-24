const CHAT_HISTORY_KEY = 'lakshya_chat_history';

document.addEventListener("DOMContentLoaded", () => {
    injectChatbot();
});

function injectChatbot() {
    // 1. Inject CSS Styles
    const style = document.createElement('style');
    style.innerHTML = `
        /* Toggle Button */
        .bot-toggle {
            position: fixed; bottom: 30px; right: 30px; width: 60px; height: 60px;
            background: linear-gradient(135deg, #00d2ff, #3a7bd5); 
            border-radius: 50%;
            display: flex; align-items: center; justify-content: center;
            cursor: pointer; 
            box-shadow: 0 0 20px rgba(0, 210, 255, 0.6);
            z-index: 5000; transition: transform 0.3s;
            animation: pulseBot 2s infinite;
        }
        .bot-toggle:hover { transform: scale(1.1); }
        .bot-toggle i { font-size: 1.8rem; color: #fff; }

        @keyframes pulseBot {
            0% { box-shadow: 0 0 0 0 rgba(0, 210, 255, 0.7); }
            70% { box-shadow: 0 0 0 15px rgba(0, 210, 255, 0); }
            100% { box-shadow: 0 0 0 0 rgba(0, 210, 255, 0); }
        }

        /* Chat Window */
        .chat-window {
            position: fixed; bottom: 100px; right: 30px; width: 350px; height: 500px;
            background: rgba(15, 15, 30, 0.95); 
            border: 1px solid rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(15px); border-radius: 20px;
            display: none; flex-direction: column; overflow: hidden;
            box-shadow: 0 10px 40px rgba(0,0,0,0.5); z-index: 5000;
            opacity: 0; transform: translateY(20px);
            transition: all 0.3s cubic-bezier(0.165, 0.84, 0.44, 1);
        }
        .chat-window.active { display: flex; opacity: 1; transform: translateY(0); }

        /* Header */
        .chat-header {
            padding: 15px; background: rgba(0, 210, 255, 0.15);
            border-bottom: 1px solid rgba(255,255,255,0.1);
            display: flex; justify-content: space-between; align-items: center;
            color: white; font-family: 'Rajdhani', sans-serif;
            border-top-left-radius: 20px; border-top-right-radius: 20px;
        }
        .bot-avatar {
            width: 30px; height: 30px; border-radius: 50%; background: #fff;
            display: flex; align-items: center; justify-content: center; color: #00d2ff;
            margin-right: 10px; font-weight: bold;
        }
        
        /* Body */
        .chat-body {
            flex-grow: 1; padding: 15px; overflow-y: auto; 
            display: flex; flex-direction: column; gap: 15px;
            scrollbar-width: thin; scrollbar-color: #333 transparent;
        }
        .chat-body::-webkit-scrollbar { width: 5px; }
        .chat-body::-webkit-scrollbar-thumb { background: #333; border-radius: 10px; }

        /* Input Area */
        .chat-input-area {
            padding: 15px; border-top: 1px solid rgba(255,255,255,0.1);
            display: flex; gap: 10px; background: rgba(0,0,0,0.2);
        }
        .chat-input {
            flex-grow: 1; background: rgba(255,255,255,0.05); 
            border: 1px solid rgba(255,255,255,0.1);
            color: white; padding: 10px 15px; border-radius: 50px; outline: none;
            font-family: 'Poppins', sans-serif; font-size: 0.9rem;
        }
        .chat-input:focus { border-color: #00d2ff; }
        .chat-send {
            width: 40px; height: 40px; border-radius: 50%;
            background: #00d2ff; border: none; 
            cursor: pointer; color: black; display: flex; align-items: center; justify-content: center;
            transition: 0.2s;
        }
        .chat-send:hover { background: white; }

        /* Messages */
        .msg { max-width: 80%; padding: 10px 15px; border-radius: 12px; font-size: 0.9rem; line-height: 1.4; animation: fadeIn 0.3s ease; }
        .msg.bot { align-self: flex-start; background: rgba(255,255,255,0.1); color: #ddd; border-bottom-left-radius: 2px; border: 1px solid rgba(255,255,255,0.05); }
        .msg.user { align-self: flex-end; background: linear-gradient(135deg, #00d2ff, #3a7bd5); color: #fff; border-bottom-right-radius: 2px; box-shadow: 0 4px 15px rgba(0, 210, 255, 0.2); }
        
        /* Action Chips */
        .chip-container { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 5px; animation: fadeIn 0.5s ease; }
        .chip {
            font-size: 0.75rem; padding: 6px 12px; border-radius: 50px;
            border: 1px solid #00d2ff; color: #00d2ff;
            cursor: pointer; background: rgba(0, 210, 255, 0.05); transition: 0.2s;
        }
        .chip:hover { background: #00d2ff; color: black; box-shadow: 0 0 10px rgba(0, 210, 255, 0.3); }

        @keyframes fadeIn { from { opacity: 0; transform: translateY(5px); } to { opacity: 1; transform: translateY(0); } }
        
        /* Mobile Responsive */
        @media (max-width: 480px) {
            .chat-window { width: 100%; height: 100%; bottom: 0; right: 0; border-radius: 0; }
            .chat-header { border-radius: 0; padding: 20px; }
            .bot-toggle { bottom: 20px; right: 20px; }
        }
    `;
    document.head.appendChild(style);

    // 2. Inject HTML (Initial Empty Body)
    const html = `
        <div class="bot-toggle" onclick="toggleChat()">
            <i class="fa-solid fa-robot"></i>
        </div>
        <div class="chat-window" id="chatWindow">
            <div class="chat-header">
                <div style="display:flex; align-items:center;">
                    <div class="bot-avatar"><i class="fa-solid fa-bolt"></i></div>
                    <span style="font-weight:700; font-size:1.1rem; letter-spacing:1px;">LAKSHYA AI</span>
                </div>
                <i class="fa-solid fa-xmark" style="cursor:pointer; font-size:1.2rem;" onclick="toggleChat()"></i>
            </div>
            <div class="chat-body" id="chatBody">
                <!-- Content will be loaded by initChat() -->
            </div>
            <div class="chat-input-area">
                <input type="text" id="chatInput" class="chat-input" placeholder="Type your question..." onkeypress="handleEnter(event)">
                <button class="chat-send" onclick="sendMessage()"><i class="fa-solid fa-paper-plane"></i></button>
            </div>
        </div>
    `;
    const div = document.createElement('div');
    div.innerHTML = html;
    document.body.appendChild(div);

    // 3. Initialize History
    initChat();
}

// --- INITIALIZATION ---
function initChat() {
    const chatBody = document.getElementById('chatBody');
    const storedHistory = localStorage.getItem(CHAT_HISTORY_KEY);

    if (storedHistory) {
        // Load existing history
        const history = JSON.parse(storedHistory);
        history.forEach(msg => {
            appendMessageToDOM(msg.text, msg.sender, msg.actions);
        });
    } else {
        // No history (Fresh Login or First Visit) -> Show Welcome
        const welcomeText = "Hello! I'm your Lakshya 2k26 guide. Ask me about:";
        const welcomeActions = [
            { text: "Events", val: "event list" },
            { text: "My Status", val: "my registration status" },
            { text: "Accommodation", val: "accommodation details" }
        ];
        
        // Save initial state so it persists
        saveMessageToHistory(welcomeText, 'bot', welcomeActions);
        appendMessageToDOM(welcomeText, 'bot', welcomeActions);
    }
}

// --- UTILS ---
function saveMessageToHistory(text, sender, actions = null) {
    const history = JSON.parse(localStorage.getItem(CHAT_HISTORY_KEY) || '[]');
    history.push({ text, sender, actions });
    localStorage.setItem(CHAT_HISTORY_KEY, JSON.stringify(history));
}

function appendMessageToDOM(text, sender, actions = null, isTyping = false) {
    const chatBody = document.getElementById('chatBody');
    const div = document.createElement('div');
    div.className = `msg ${sender}`;
    div.innerText = text;
    
    if (isTyping) {
        div.id = 'typing-' + Date.now();
        div.style.opacity = '0.7';
        div.style.fontStyle = 'italic';
    }

    chatBody.appendChild(div);

    if (actions && actions.length > 0) {
        const chipsDiv = document.createElement('div');
        chipsDiv.className = 'chip-container';
        actions.forEach(act => {
            const chip = document.createElement('button');
            chip.className = 'chip';
            chip.innerText = act.text;
            if(act.link) {
                chip.onclick = () => window.location.href = act.link;
            } else {
                chip.onclick = () => sendMessage(act.val);
            }
            chipsDiv.appendChild(chip);
        });
        chatBody.appendChild(chipsDiv);
    }

    chatBody.scrollTop = chatBody.scrollHeight;
    return div.id;
}

// --- INTERACTION LOGIC ---
function toggleChat() {
    const win = document.getElementById('chatWindow');
    win.classList.toggle('active');
    if(win.classList.contains('active')) document.getElementById('chatInput').focus();
}

function handleEnter(e) {
    if (e.key === 'Enter') sendMessage();
}

async function sendMessage(text = null) {
    const input = document.getElementById('chatInput');
    const msg = text || input.value.trim();
    if (!msg) return;

    if(!text) input.value = ''; // Clear input if user typed

    // 1. Add User Message to DOM & History
    saveMessageToHistory(msg, 'user');
    appendMessageToDOM(msg, 'user');

    // 2. Show Typing Indicator (Do NOT save to history)
    const typingId = appendMessageToDOM('Thinking...', 'bot', null, true);

    try {
        const res = await fetch('/api/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message: msg })
        });
        const data = await res.json();
        
        // Remove typing
        const typingEl = document.getElementById(typingId);
        if(typingEl) typingEl.remove();
        
        // 3. Add Bot Reply to DOM & History
        saveMessageToHistory(data.reply, 'bot', data.actions);
        appendMessageToDOM(data.reply, 'bot', data.actions);

    } catch (e) {
        const typingEl = document.getElementById(typingId);
        if(typingEl) typingEl.remove();
        appendMessageToDOM("⚠️ My server is unreachable right now.", 'bot');
    }
}