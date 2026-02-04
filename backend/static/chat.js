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
    document.getElementById('chatMessages').innerHTML = '';

    // Actualizar contador
    document.getElementById('questionsLeft').textContent = MAX_QUESTIONS;

    // Mostrar mensaje de bienvenida
    showWelcomeMessage();
}

function showWelcomeMessage() {
    const chatMessages = document.getElementById('chatMessages');
    chatMessages.innerHTML = `
        <div class="chat-message ai-message">
            <div class="message-avatar">🤖</div>
            <div class="message-content">
                <p>¡Hola! Soy tu asistente de ciberseguridad. Puedes preguntarme sobre:</p>
                <ul>
                    <li>Por qué esta URL es peligrosa o segura</li>
                    <li>Qué hacer si ya visitaste el sitio</li>
                    <li>Conceptos de phishing y ciberseguridad</li>
                    <li>Cómo protegerte en el futuro</li>
                </ul>
                <p><small>Tienes ${MAX_QUESTIONS} preguntas disponibles para este análisis.</small></p>
            </div>
        </div>
    `;
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
        alert('Primero debes analizar una URL.');
        return;
    }

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
        virustotal: currentAnalysisData.virustotal
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

                // Mostrar preguntas sugeridas si es la primera
                // if (questionCount === 1 && data.suggested_questions) {
                //    showSuggestedQuestions(data.suggested_questions);
                // }
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
        <div class="message-avatar">👤</div>
    `;
    chatMessages.appendChild(messageDiv);
    scrollToBottom();
}

function addAIMessage(message) {
    const chatMessages = document.getElementById('chatMessages');
    const messageDiv = document.createElement('div');
    messageDiv.className = 'chat-message ai-message';
    messageDiv.innerHTML = `
        <div class="message-avatar">🤖</div>
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
        <div class="message-avatar">🤖</div>
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
    // Función deshabilitada por solicitud del usuario
    return;
}

function askSuggestedQuestion(question) {
    document.getElementById('chatInput').value = question;
    sendChatMessage();
}

function updateQuestionCounter() {
    const questionsLeft = MAX_QUESTIONS - questionCount;
    document.getElementById('questionsLeft').textContent = questionsLeft;

    if (questionsLeft <= 3) {
        document.getElementById('chatLimit').style.color = '#ea580c';
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
    // Convertir saltos de línea a <br>
    message = message.replace(/\n/g, '<br>');
    return message;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
