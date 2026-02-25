function checkURL() {
    // Inject Custom Styles for Consensus Badge if not present
    if (!document.getElementById('consensus-styles')) {
        const style = document.createElement('style');
        style.id = 'consensus-styles';
        style.innerHTML = `
            .consensus-section {
                box-shadow: 0 4px 15px rgba(0,0,0,0.05);
                border-left-width: 6px !important;
                transition: transform 0.2s;
            }
            .consensus-section:hover {
                transform: translateY(-2px);
            }
            .consensus-section.phishing {
                background: linear-gradient(135deg, #fed7d7 0%, #fff5f5 100%);
                border-left-color: #e53e3e !important;
                border: 1px solid #fc8181;
            }
            .consensus-section.safe {
                background: linear-gradient(135deg, #c6f6d5 0%, #f0fff4 100%);
                border-left-color: #38a169 !important;
                border: 1px solid #68d391;
            }
            .consensus-section.warning {
                background: linear-gradient(135deg, #feebc8 0%, #fffaf0 100%);
                border-left-color: #dd6b20 !important;
                border: 1px solid #f6ad55;
            }
            .consensus-main-text {
                font-size: 1.25em;
                font-weight: bold;
                color: #1a202c;
                margin-bottom: 8px;
            }
            .consensus-note {
                font-size: 0.9em;
                color: #718096;
                font-style: italic;
            }
            .score-circle {
                border-width: 6px !important;
                box-shadow: 0 4px 10px rgba(0,0,0,0.1);
            }
            /* Override for Critical/High -> Phishing/Danger */
            .score-circle.critical, .score-circle.phishing {
                background: #e53e3e !important;
                border-color: #9b2c2c !important;
                color: #ffffff !important;
            }
            /* Override for High -> Warning/Orange */
            .score-circle.high {
                background: #dd6b20 !important;
                border-color: #9c4221 !important;
                color: #ffffff !important;
            }
            /* Override for Medium -> Yellow/Caution */
            .score-circle.medium {
                background: #d69e2e !important;
                border-color: #975a16 !important;
                color: #ffffff !important;
            }
            /* Override for Low -> Safe/Green */
            .score-circle.low, .score-circle.safe {
                background: #38a169 !important;
                border-color: #276749 !important;
                color: #ffffff !important;
            }
            .score-circle .score-max {
                color: rgba(255,255,255,0.8) !important;
            }
            .identity-badge {
                display: inline-block;
                padding: 6px 12px;
                border-radius: 20px;
                font-weight: bold;
                margin-top: 10px;
                font-size: 0.9em;
            }
            .identity-badge.verified {
                background: #e6fffa;
                color: #2c7a7b;
                border: 1px solid #81e6d9;
            }
            .identity-badge.impersonation {
                background: #fff5f5;
                color: #c53030;
                border: 1px solid #feb2b2;
                animation: pulse 2s infinite;
            }
            @keyframes pulse {
                0% { box-shadow: 0 0 0 0 rgba(229, 62, 62, 0.4); }
                70% { box-shadow: 0 0 0 10px rgba(229, 62, 62, 0); }
                100% { box-shadow: 0 0 0 0 rgba(229, 62, 62, 0); }
            }
        `;
        document.head.appendChild(style);
    }
    const url = document.getElementById("urlInput").value.trim();
    const resultDiv = document.getElementById("result");

    // Reset visual
    resultDiv.className = "alert";
    resultDiv.innerHTML = "";

    if (!url) {
        resultDiv.classList.add("warning");
        resultDiv.innerHTML = "⚠️ Por favor ingresa una URL";
        return;
    }

    resultDiv.classList.add("loading");
    resultDiv.innerHTML = `
        <div class="loading-animation">
            <div class="spinner"></div>
            <p>🔍 Analizando URL con IA y motores de seguridad...</p>
            <small>Esto puede tardar 15-20 segundos</small>
        </div>
    `;

    fetch(`/check?url=${encodeURIComponent(url)}`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            resultDiv.className = "alert";

            // Determinar clase de estilo basada en estado
            let statusClass = "safe";
            let statusIcon = "✅";
            let statusTitle = data.identity && data.identity.status === "verified" ? "URL OFICIAL VERIFICADA" : "URL SEGURA";

            if (data.status === "phishing") {
                statusClass = "phishing";
                statusIcon = "🚨";
                statusTitle = "PHISHING DETECTADO";
            } else if (data.status === "suspicious") {
                statusClass = "warning";
                statusIcon = "⚠️";
                statusTitle = "URL SOSPECHOSA";
            } else if (data.status === "error") {
                statusClass = "error";
                statusIcon = "❌";
                statusTitle = "ERROR DE ANÁLISIS";
            }

            resultDiv.classList.add(statusClass);

            // Construir HTML con toda la información
            let voteCount = 0;
            // Calcular votos desde el frontend también para mostrar detalle
            // Nota: El backend ya hizo la lógica, pero aquí lo recalculamos visualmente si queremos o usamos el reason del backend

            // Extraer el conteo del reason si es posible, o simplemente mostrar el status
            let consensusText = data.reason;

            let html = `
                <div class="result-header">
                    <h2>${statusIcon} ${statusTitle}</h2>
                    <div class="url-analyzed">${data.url || url}</div>
                    ${data.identity && data.identity.status === 'verified' ? `
                        <div class="identity-badge verified">
                            🛡️ Identidad Verificada: ${data.identity.name}
                        </div>
                    ` : ''}
                    ${data.identity && data.identity.status === 'impersonation' ? `
                        <div class="identity-badge impersonation">
                            🚨 Alerta de Suplantación detectada
                        </div>
                    ` : ''}
                </div>
            `;

            // Nueva Card de Consenso
            html += `
                <div class="section consensus-section ${statusClass}">
                    <h3>📊 Resultado del Consenso</h3>
                    <div class="consensus-content">
                        <div class="consensus-main-text">${consensusText}</div>
                        <div class="consensus-note">
                            ℹ️ Decisión basada en la coincidencia de al menos 2 de los 3 motores de análisis (IA, VirusTotal, Heurística).
                        </div>
                    </div>
                </div>
            `;

            // Sección de Análisis con IA
            if (data.ai_analysis) {
                html += `
                    <div class="section ai-section">
                        <h3>Análisis con Inteligencia Artificial</h3>
                        <div class="ai-content">
                            <p class="ai-analysis">${data.ai_analysis}</p>
                            <div class="risk-badge ${getRiskClass(data.ai_risk_level)}">
                                <strong>Nivel de Riesgo:</strong> ${data.ai_risk_level || 'Desconocido'}
                            </div>
                        </div>
                        
                        ${data.ai_recommendations && data.ai_recommendations.length > 0 ? `
                            <div class="recommendations">
                                <h4>💡 Recomendaciones:</h4>
                                <ul>
                                    ${data.ai_recommendations.map(rec => `<li>${rec}</li>`).join('')}
                                </ul>
                            </div>
                        ` : ''}
                        
                        ${data.metadata && data.metadata.ai_source ? `
                            <small class="ai-source">Fuente: ${data.metadata.ai_source === 'claude' ? '🧠 Anthropic Claude' : '📋 Análisis Estático'}</small>
                        ` : ''}
                    </div>
                `;
            }

            // Sección de Análisis Heurístico
            if (data.heuristic) {
                html += `
                    <div class="section heuristic-section">
                        <h3>🔍 Análisis Heurístico</h3>
                        <div class="score-container">
                            <div class="score-circle ${getScoreClass(data.heuristic.score)}">
                                <span class="score-value">${data.heuristic.score}</span>
                                <span class="score-max">/100</span>
                            </div>
                            <div class="score-info">
                                <div class="risk-level">Nivel: <strong>${data.heuristic.risk_level}</strong></div>
                                <div class="indicators-count">${data.heuristic.total_indicators} indicadores detectados</div>
                            </div>
                        </div>
                        
                        ${data.heuristic.indicators && data.heuristic.indicators.length > 0 ? `
                            <div class="indicators-list">
                                <h4>Indicadores detectados:</h4>
                                <ul>
                                    ${data.heuristic.indicators.map(ind => `<li>⚠️ ${ind}</li>`).join('')}
                                </ul>
                            </div>
                        ` : '<p class="no-indicators">✅ No se detectaron indicadores sospechosos</p>'}
                    </div>
                `;
            }

            // Sección de VirusTotal
            if (data.virustotal && data.virustotal.stats) {
                const vt = data.virustotal;
                const total = vt.stats.malicious + vt.stats.suspicious + vt.stats.harmless + vt.stats.undetected;

                html += `
                    <div class="section virustotal-section">
                        <h3>🛡️ Análisis VirusTotal</h3>
                        <div class="vt-stats">
                            <div class="stat-item danger">
                                <div class="stat-number">${vt.stats.malicious}</div>
                                <div class="stat-label">Maliciosos</div>
                            </div>
                            <div class="stat-item warning">
                                <div class="stat-number">${vt.stats.suspicious}</div>
                                <div class="stat-label">Sospechosos</div>
                            </div>
                            <div class="stat-item safe">
                                <div class="stat-number">${vt.stats.harmless}</div>
                                <div class="stat-label">Inofensivos</div>
                            </div>
                            <div class="stat-item neutral">
                                <div class="stat-number">${vt.stats.undetected}</div>
                                <div class="stat-label">No detectado</div>
                            </div>
                        </div>
                        
                        <div class="vt-summary">
                            <strong>Total de motores:</strong> ${total}
                        </div>
                        
                        ${vt.detection_engines && vt.detection_engines.length > 0 ? `
                            <div class="detection-engines">
                                <h4>Motores que detectaron amenazas:</h4>
                                <div class="engines-tags">
                                    ${vt.detection_engines.slice(0, 10).map(engine =>
                    `<span class="engine-tag">${engine}</span>`
                ).join('')}
                                    ${vt.detection_engines.length > 10 ?
                            `<span class="engine-tag more">+${vt.detection_engines.length - 10} más</span>`
                            : ''
                        }
                                </div>
                            </div>
                        ` : ''}
                        
                        ${vt.categories && vt.categories.length > 0 ? `
                            <div class="vt-categories">
                                <strong>Categorías:</strong> ${vt.categories.join(', ')}
                            </div>
                        ` : ''}
                        

                    </div>
                `;
            }

            resultDiv.innerHTML = html;

            // Inicializar chat con los datos del análisis
            if (typeof initializeChat === 'function') {
                initializeChat(data);
            }
        })
        .catch((error) => {
            resultDiv.className = "alert error";
            resultDiv.innerHTML = `
                <div class="error-content">
                    <h2>❌ ERROR DE CONEXIÓN</h2>
                    <p>No se pudo conectar con el servidor</p>
                    <small>Detalles: ${error.message}</small>
                </div>
            `;
            console.error("Error completo:", error);
        });
}

// Funciones auxiliares
function getRiskClass(riskLevel) {
    if (!riskLevel) return 'neutral';
    const level = riskLevel.toLowerCase();
    if (level.includes('crítico') || level.includes('critico')) return 'critical';
    if (level.includes('alto')) return 'high';
    if (level.includes('medio')) return 'medium';
    return 'low';
}

function getScoreClass(score) {
    if (score >= 60) return 'critical';
    if (score >= 40) return 'high';
    if (score >= 20) return 'medium';
    return 'low';
}

// Permitir análisis con Enter
document.addEventListener('DOMContentLoaded', function () {
    const urlInput = document.getElementById('urlInput');
    if (urlInput) {
        urlInput.addEventListener('keypress', function (e) {
            if (e.key === 'Enter') {
                checkURL();
            }
        });
    }
});