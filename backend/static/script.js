function checkURL() {
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
            let statusTitle = "URL APARENTEMENTE SEGURA";

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
            let html = `
                <div class="result-header">
                    <h2>${statusIcon} ${statusTitle}</h2>
                    <div class="url-analyzed">${data.url || url}</div>
                </div>
            `;

            // Sección de Análisis con IA
            if (data.ai_analysis) {
                html += `
                    <div class="section ai-section">
                        <h3>🤖 Análisis con Inteligencia Artificial</h3>
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
                            <small class="ai-source">Fuente: ${data.metadata.ai_source === 'gemini' ? '🌟 Google Gemini' : '📋 Análisis Estático'}</small>
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
                        
                        ${vt.analysis_url ? `
                            <div class="vt-link">
                                <a href="${vt.analysis_url}" target="_blank" rel="noopener noreferrer">
                                    🔗 Ver análisis completo en VirusTotal →
                                </a>
                            </div>
                        ` : ''}
                    </div>
                `;
            }

            resultDiv.innerHTML = html;
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