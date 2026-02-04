import re
import math
from urllib.parse import urlparse
from collections import Counter

# Listas de palabras sospechosas
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account",
    "update", "bank", "free", "confirm",
    "password", "billing", "verification",
    "suspend", "limited", "unusual", "click"
]

# Servicios conocidos de acortamiento de URLs
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly",
    "t.co", "is.gd", "buff.ly", "adf.ly"
]

# Extensiones comunes de archivos sospechosos
SUSPICIOUS_EXTENSIONS = [
    ".exe", ".zip", ".rar", ".scr", ".bat",
    ".cmd", ".com", ".pif", ".vbs"
]


def calculate_entropy(text):
    """Calcula la entropía de Shannon de un texto (detecta strings aleatorios)"""
    if not text:
        return 0
    
    # Contar frecuencia de cada carácter
    counter = Counter(text)
    length = len(text)
    
    # Calcular entropía
    entropy = 0
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return entropy


def check_url_shortener(url):
    """Detecta si la URL usa un servicio de acortamiento"""
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    
    for shortener in URL_SHORTENERS:
        if shortener in domain:
            return True
    return False


def check_suspicious_extension(url):
    """Detecta extensiones de archivo sospechosas"""
    url_lower = url.lower()
    for ext in SUSPICIOUS_EXTENSIONS:
        if url_lower.endswith(ext):
            return True
    return False


def check_ip_address(url):
    """Detecta si la URL usa una dirección IP en lugar de dominio"""
    parsed = urlparse(url)
    domain = parsed.netloc
    
    # Remover puerto si existe
    if ':' in domain:
        domain = domain.split(':')[0]
    
    # Patrón simple para IPv4
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    return bool(re.match(ip_pattern, domain))


def check_too_many_subdomains(url):
    """Detecta uso excesivo de subdominios"""
    parsed = urlparse(url)
    domain = parsed.netloc
    
    # Remover puerto si existe
    if ':' in domain:
        domain = domain.split(':')[0]
    
    # Contar puntos (cada punto separa subdominios)
    dots_count = domain.count('.')
    
    # Más de 3 puntos es sospechoso (ej: a.b.c.example.com)
    return dots_count > 3


def check_suspicious_patterns(url):
    """Detecta patrones comunes en URLs de phishing"""
    patterns = {
        "@ en URL": '@' in url,  # phishing@real.com
        "Doble slash": '//' in url.split('://')[1] if '://' in url else False,
        "Guión antes de dominio": re.search(r'[a-z]-\.[a-z]', url.lower()) is not None,
        "Mezcla extraña de caracteres": bool(re.search(r'[0-9]+[a-z]+[0-9]+', urlparse(url).netloc)),
    }
    
    detected = [name for name, found in patterns.items() if found]
    return detected


def heuristic_analysis(url):
    """
    Realiza un análisis heurístico avanzado de la URL.
    Retorna un score de 0-100 y una lista de razones.
    """
    score = 0
    reasons = []
    
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    
    # 1. Uso excesivo de guiones (phishing común)
    if domain.count("-") >= 3:
        score += 15
        reasons.append(f"Uso excesivo de guiones en el dominio ({domain.count('-')} guiones)")
    elif domain.count("-") >= 2:
        score += 8
        reasons.append("Múltiples guiones en el dominio")
    
    # 2. Números largos en la URL
    long_numbers = re.findall(r'\d{4,}', url)
    if long_numbers:
        score += 12
        reasons.append(f"Números largos sospechosos: {', '.join(long_numbers[:2])}")
    
    # 3. Palabras clave sospechosas
    url_lower = url.lower()
    found_keywords = [word for word in SUSPICIOUS_KEYWORDS if word in url_lower]
    if found_keywords:
        score += min(20, len(found_keywords) * 5)
        reasons.append(f"Palabras de phishing detectadas: {', '.join(found_keywords[:3])}")
    
    # 4. URL demasiado larga
    if len(url) > 100:
        score += 10
        reasons.append(f"URL excesivamente larga ({len(url)} caracteres)")
    elif len(path) > 50:
        score += 5
        reasons.append("Ruta de URL muy larga")
    
    # 5. Acortador de URLs (oculta destino real)
    if check_url_shortener(url):
        score += 18
        reasons.append("URL acortada (oculta el destino real)")
    
    # 6. Extensión de archivo sospechosa
    if check_suspicious_extension(url):
        score += 25
        reasons.append("Extensión de archivo peligrosa detectada")
    
    # 7. Uso de dirección IP en lugar de dominio
    if check_ip_address(url):
        score += 20
        reasons.append("Usa dirección IP en lugar de nombre de dominio")
    
    # 8. Demasiados subdominios
    if check_too_many_subdomains(url):
        score += 15
        reasons.append("Uso excesivo de subdominios")
    
    # 9. Análisis de entropía del dominio (detecta dominios aleatorios)
    domain_entropy = calculate_entropy(domain)
    if domain_entropy > 4.0:  # Alta aleatoriedad
        score += 12
        reasons.append(f"Dominio con alta aleatoriedad (entropía: {domain_entropy:.2f})")
    
    # 10. Patrones sospechosos adicionales
    suspicious_patterns = check_suspicious_patterns(url)
    if suspicious_patterns:
        score += min(15, len(suspicious_patterns) * 5)
        reasons.append(f"Patrones sospechosos: {', '.join(suspicious_patterns)}")
    
    # 11. Protocolo no seguro
    if url.startswith('http://') and not url.startswith('https://'):
        score += 8
        reasons.append("No usa conexión segura (HTTP en lugar de HTTPS)")
    
    # 12. Exceso de símbolos especiales
    special_chars = len(re.findall(r'[^a-zA-Z0-9.\-/:?=&]', url))
    if special_chars > 5:
        score += 10
        reasons.append(f"Exceso de caracteres especiales ({special_chars})")
    
    # Limitar score a 100
    score = min(100, score)
    
    # Categorizar el riesgo
    if score >= 60:
        risk_level = "CRÍTICO"
    elif score >= 40:
        risk_level = "ALTO"
    elif score >= 20:
        risk_level = "MEDIO"
    else:
        risk_level = "BAJO"
    
    return {
        "score": score,
        "risk_level": risk_level,
        "reasons": reasons,
        "total_indicators": len(reasons)
    }
