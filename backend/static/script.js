function checkURL() {
    const url = document.getElementById("urlInput").value.trim();
    const resultDiv = document.getElementById("result");

    // Reset visual
    resultDiv.className = "";
    resultDiv.innerHTML = "";

    if (!url) {
        resultDiv.classList.add("alert", "warning");
        resultDiv.innerHTML = "⚠️ Por favor ingresa una URL";
        return;
    }

    resultDiv.classList.add("alert", "loading");
    resultDiv.innerHTML = "🔍 Analizando URL...";

    fetch(`/check?url=${encodeURIComponent(url)}`)
        .then(response => response.json())
        .then(data => {
            resultDiv.className = "alert";

            if (data.status === "phishing") {
                resultDiv.classList.add("phishing");
                resultDiv.innerHTML = `
                    🚨 <strong>PHISHING DETECTADO</strong><br>
                    <span>Objetivo: ${data.target}</span><br>
                    <a href="${data.phish_detail_url}" target="_blank">
                        Ver detalle en PhishTank
                    </a>
                `;
            } else {
                resultDiv.classList.add("safe");
                resultDiv.innerHTML = "✅ <strong>URL SEGURA</strong>";
            }
        })
        .catch(() => {
            resultDiv.className = "alert error";
            resultDiv.innerHTML = "❌ Error al conectar con el servidor";
        });
}
