// ========== CHAT FUNCTIONALITY ==========

let currentAnalysisData = null;
let questionCount = 0;
const MAX_QUESTIONS = 10;

function initializeChat(data) {
    currentAnalysisData = data;
    questionCount = 0;

    // Mostrar sección de chat
    const chatSection = document.getElementById('chatSection');
    chatSection.style.display = 'block';

    // Limpiar mensajes previos
    const chatMessages = document.getElementById('chatMessages');
    chatMessages.innerHTML = '';

    // Actualizar contador
    const questionsLeftEl = document.getElementById('questionsLeft');
    if (questionsLeftEl) questionsLeftEl.textContent = MAX_QUESTIONS;

    // Mostrar mensaje de bienvenida dinámico
    showWelcomeMessage();
}

function showWelcomeMessage() {
    const chatMessages = document.getElementById('chatMessages');
    if (!chatMessages) return;

    let welcomeText = "¡Hola! Soy CyberGuard, tu experto en seguridad.";

    if (currentAnalysisData) {
        if (currentAnalysisData.identity && currentAnalysisData.identity.status === 'verified') {
            welcomeText = `¡Hola! He verificado que **${currentAnalysisData.identity.name}** es un sitio legítimo. ¿Quieres saber por qué es seguro?`;
        } else if (currentAnalysisData.status === 'phishing') {
            welcomeText = "⚠️ **¡Atención!** He detectado amenazas serias en esta URL. No ingreses datos. Pregúntame qué riesgos encontré.";
        }
    }

    const messageDiv = document.createElement('div');
    messageDiv.className = 'chat-message ai-message';
    messageDiv.innerHTML = `
        <div class="message-avatar"></div>
        <div class="message-content">
            <p>${formatAIMessage(welcomeText)}</p>
            <p><small>Tienes ${MAX_QUESTIONS} preguntas disponibles para este análisis.</small></p>
        </div>
    `;
    chatMessages.appendChild(messageDiv);
}

function sendChatMessage() {
    const chatInput = document.getElementById('chatInput');
    const question = chatInput.value.trim();

    if (!question) {
        return;
    }

    if (questionCount >= MAX_QUESTIONS) {
        alert('Has alcanzado el límite de preguntas para este análisis. Analiza otra URL para continuar.');
        return;
    }

    if (!currentAnalysisData) {
        // Chat general sin contexto
        const analysisContext = {};

        // Agregar mensaje del usuario
        addUserMessage(question);

        // Limpiar input
        chatInput.value = '';
        chatInput.disabled = true;
        document.getElementById('chatSendBtn').disabled = true;
        showTypingIndicator();

        // Enviar pregunta al backend
        fetch('/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                url: "",
                question: question,
                analysis_context: analysisContext
            })
        })
            .then(response => response.json())
            .then(data => {
                removeTypingIndicator();
                if (data.status === 'success') {
                    addAIMessage(data.answer);
                } else {
                    addAIMessage(data.answer || 'Hubo un error.');
                }
                chatInput.disabled = false;
                document.getElementById('chatSendBtn').disabled = false;
                chatInput.focus();
            })
            .catch(error => {
                console.error('Error:', error);
                removeTypingIndicator();
                addAIMessage('Error de conexión.');
                chatInput.disabled = false;
                document.getElementById('chatSendBtn').disabled = false;
            });
        return;
    }

    // Chat con contexto de análisis existente
    // Agregar mensaje del usuario
    addUserMessage(question);

    // Limpiar input
    chatInput.value = '';

    // Deshabilitar input mientras se procesa
    chatInput.disabled = true;
    document.getElementById('chatSendBtn').disabled = true;

    // Mostrar typing indicator
    showTypingIndicator();

    // Preparar contexto
    const analysisContext = {
        ai_analysis: currentAnalysisData.ai_analysis,
        ai_risk_level: currentAnalysisData.ai_risk_level,
        heuristic: currentAnalysisData.heuristic,
        virustotal: currentAnalysisData.virustotal,
        identity: currentAnalysisData.identity
    };

    // Enviar pregunta al backend
    fetch('/chat', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            url: currentAnalysisData.url,
            question: question,
            analysis_context: analysisContext
        })
    })
        .then(response => response.json())
        .then(data => {
            // Remover typing indicator
            removeTypingIndicator();

            if (data.status === 'success') {
                // Agregar respuesta de la IA
                addAIMessage(data.answer);

                // Incrementar contador
                questionCount++;
                updateQuestionCounter();

                // Mostrar preguntas sugeridas
                if (data.suggested_questions && data.suggested_questions.length > 0) {
                    showSuggestedQuestions(data.suggested_questions);
                }
            } else {
                addAIMessage(data.answer || 'Hubo un error al procesar tu pregunta.');
            }

            // Rehabilitar input
            chatInput.disabled = false;
            document.getElementById('chatSendBtn').disabled = false;
            chatInput.focus();
        })
        .catch(error => {
            console.error('Error:', error);
            removeTypingIndicator();
            addAIMessage('Hubo un error al procesar tu pregunta. Por favor intenta de nuevo.');
            chatInput.disabled = false;
            document.getElementById('chatSendBtn').disabled = false;
        });
}

function addUserMessage(message) {
    const chatMessages = document.getElementById('chatMessages');
    const messageDiv = document.createElement('div');
    messageDiv.className = 'chat-message user-message';
    messageDiv.innerHTML = `
        <div class="message-content">
            <p>${escapeHtml(message)}</p>
        </div>
        <div class="message-avatar"></div>
    `;
    chatMessages.appendChild(messageDiv);
    scrollToBottom();
}

function addAIMessage(message) {
    const chatMessages = document.getElementById('chatMessages');
    const messageDiv = document.createElement('div');
    messageDiv.className = 'chat-message ai-message';
    messageDiv.innerHTML = `
        <div class="message-avatar"></div>
        <div class="message-content">
            <p>${formatAIMessage(message)}</p>
        </div>
    `;
    chatMessages.appendChild(messageDiv);
    scrollToBottom();
}

function showTypingIndicator() {
    const chatMessages = document.getElementById('chatMessages');
    const typingDiv = document.createElement('div');
    typingDiv.className = 'chat-message ai-message typing-indicator';
    typingDiv.id = 'typingIndicator';
    typingDiv.innerHTML = `
        <div class="message-avatar"></div>
        <div class="message-content">
            <div class="typing-dots">
                <span></span><span></span><span></span>
            </div>
        </div>
    `;
    chatMessages.appendChild(typingDiv);
    scrollToBottom();
}

function removeTypingIndicator() {
    const typingIndicator = document.getElementById('typingIndicator');
    if (typingIndicator) {
        typingIndicator.remove();
    }
}

function showSuggestedQuestions(questions) {
    const chatMessages = document.getElementById('chatMessages');
    const suggestionsDiv = document.createElement('div');
    suggestionsDiv.className = 'suggested-questions';

    questions.forEach(q => {
        const btn = document.createElement('button');
        btn.className = 'suggestion-btn';
        btn.textContent = q;
        btn.onclick = () => askSuggestedQuestion(q);
        suggestionsDiv.appendChild(btn);
    });

    chatMessages.appendChild(suggestionsDiv);
    scrollToBottom();
}

function askSuggestedQuestion(question) {
    document.getElementById('chatInput').value = question;
    sendChatMessage();
}

function updateQuestionCounter() {
    const questionsLeft = MAX_QUESTIONS - questionCount;
    const counterEl = document.getElementById('questionsLeft');
    const limitEl = document.getElementById('chatLimit');

    if (counterEl) {
        counterEl.textContent = questionsLeft;
    }

    if (limitEl && questionsLeft <= 3) {
        limitEl.style.color = '#ea580c';
    }
}

function scrollToBottom() {
    const chatMessages = document.getElementById('chatMessages');
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

function handleChatKeyPress(event) {
    if (event.key === 'Enter') {
        sendChatMessage();
    }
}

function formatAIMessage(message) {
    // Convertir negritas **texto** a <strong>texto</strong>
    message = message.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');

    // Convertir código `texto` a <code>texto</code>
    message = message.replace(/`(.*?)`/g, '<code>$1</code>');

    // Convertir listas con guiones
    if (message.includes('\n- ') || message.includes('\n• ')) {
        const lines = message.split('\n');
        let inList = false;
        const formattedLines = lines.map(line => {
            if (line.trim().startsWith('- ') || line.trim().startsWith('• ')) {
                const content = line.trim().substring(2);
                if (!inList) {
                    inList = true;
                    return '<ul><li>' + content + '</li>';
                }
                return '<li>' + content + '</li>';
            } else {
                if (inList) {
                    inList = false;
                    return '</ul>' + line;
                }
                return line;
            }
        });
        if (inList) formattedLines.push('</ul>');
        message = formattedLines.join('<br>');
    } else {
        // Convertir saltos de línea a <br>
        message = message.replace(/\n/g, '<br>');
    }

    return message;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
