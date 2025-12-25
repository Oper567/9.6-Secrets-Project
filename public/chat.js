/* -------------------------------------------------------------------------- */
/* CHAT.JS                                  */
/* -------------------------------------------------------------------------- */

let currentFriendId = null;
let lastMessageCount = 0;
let chatRefreshInterval = null;

/**
 * Selects a friend from the sidebar and initializes the chat window
 * @param {string} id - The database ID of the friend
 * @param {string} name - The display name/email of the friend
 */
async function selectFriend(id, name) {
    if (currentFriendId === id) return; // Don't reload if already chatting

    currentFriendId = id;
    lastMessageCount = 0; // Force a full re-render for the new conversation

    // 1. UI Feedback: Highlight active friend in sidebar
    document.querySelectorAll('.friend-item').forEach(el => {
        el.classList.remove('bg-slate-900', 'border-l-4', 'border-blue-600');
    });
    const activeEl = document.getElementById(`friend-${id}`);
    if (activeEl) {
        activeEl.classList.add('bg-slate-900', 'border-l-4', 'border-blue-600');
    }

    // 2. UI Feedback: Show input dock and update header status
    document.getElementById('inputDock').classList.remove('hidden');
    const statusText = document.getElementById('chatStatus');
    if (statusText) statusText.innerText = `Chatting with @${name}`;

    // 3. Clear existing interval and start fresh for this contact
    if (chatRefreshInterval) clearInterval(chatRefreshInterval);
    
    // Initial fetch
    await fetchMessages();
    
    // Set polling to check for new messages every 3 seconds
    chatRefreshInterval = setInterval(fetchMessages, 3000);
}

/**
 * Fetches message history from the server and updates the DOM
 */
async function fetchMessages() {
    if (!currentFriendId) return;

    try {
        const res = await fetch(`/api/chat/${currentFriendId}`);
        if (!res.ok) throw new Error("Network response was not ok");
        
        const messages = await res.json();

        // Only update the DOM if the message count has changed
        if (messages.length !== lastMessageCount) {
            renderMessages(messages);
            lastMessageCount = messages.length;
        }
    } catch (err) {
        console.error("Village Chat Error:", err);
    }
}

/**
 * Renders the message array into the chat window
 * @param {Array} messages - List of message objects
 */
function renderMessages(messages) {
    const chatWindow = document.getElementById('chatWindow');
    if (!chatWindow) return;

    // Clear loading state/previous messages
    chatWindow.innerHTML = '';

    messages.forEach(m => {
        // currentUserId is defined globally in the EJS <script> tag
        const isMe = m.sender_id == currentUserId; 
        
        const wrapper = document.createElement('div');
        wrapper.className = `flex w-full ${isMe ? 'justify-end' : 'justify-start'} mb-1`;

        const bubble = document.createElement('div');
        bubble.className = `bubble ${isMe ? 'bubble-me' : 'bubble-them'}`;
        bubble.innerText = m.content;

        wrapper.appendChild(bubble);
        chatWindow.appendChild(wrapper);
    });

    // Smooth scroll to the bottom so the newest message is visible
    chatWindow.scrollTo({
        top: chatWindow.scrollHeight,
        behavior: 'smooth'
    });
}

/**
 * Handles the submission of the chat form
 */
async function handleChatSubmit(e) {
    e.preventDefault();
    
    const input = document.getElementById('msgInput');
    const content = input.value.trim();
    
    if (!content || !currentFriendId) return;

    // Clear input immediately for snappy UI feel
    input.value = '';

    try {
        const res = await fetch('/api/chat/send', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                receiverId: currentFriendId, 
                content: content 
            })
        });

        if (res.ok) {
            // Fetch immediately so our message appears without waiting 3s
            await fetchMessages();
        } else {
            console.error("Message failed to fly.");
        }
    } catch (err) {
        console.error("Send Error:", err);
    }
}

// Attach event listener to the form
document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('chatForm');
    if (form) {
        form.addEventListener('submit', handleChatSubmit);
    }
});