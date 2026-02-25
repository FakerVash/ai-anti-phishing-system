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

# Dominios de Alta Confianza (Identidad Verificada)
HIGH_TRUST_DOMAINS = {
    # Globales
    "google.com": "Google",
    "paypal.com": "PayPal",
    "stripe.com": "Stripe",
    
    # Servicios Tech y Correo
    "google.com": "Google",
    "gmail.com": "Gmail",
    "outlook.com": "Outlook",
    "hotmail.com": "Hotmail",
    "live.com": "Microsoft Live",
    "microsoftonline.com": "Microsoft",
    "office.com": "Microsoft Office",
    "amazon.com": "Amazon",
    "apple.com": "Apple",
    "netflix.com": "Netflix",
    "github.com": "GitHub",
    "instagram.com": "Instagram",
    "facebook.com": "Facebook",
    "linkedin.com": "LinkedIn",
    "twitter.com": "Twitter",
    "x.com": "X (Twitter)",

    # Bancos (Ecuador y Regionales)
    "bancopichincha.com": "Banco Pichincha",
    "pichincha.com": "Banco Pichincha",
    "guayaquil.com": "Banco Guayaquil",
    "bancoguayaquil.com": "Banco Guayaquil",
    "produbanco.com": "Produbanco",
    "pacifico.fin.ec": "Banco del Pacífico",
    "bolivariano.com": "Banco Bolivariano",
    "internacional.com.ec": "Banco Internacional",
    "austro.fin.ec": "Banco del Austro",
    "bancodeloja.fin.ec": "Banco de Loja",
    "cooprogreso.fin.ec": "Cooprogreso",
    "jep.coop": "Cooperativa JEP",
    "mutualistapichincha.com": "Mutualista Pichincha",
}

def get_base_domain(domain):
    """Extrae el dominio base (ej: www.google.com -> google.com)"""
    parts = domain.lower().split('.')
    if len(parts) >= 2:
        # Manejo simple de .com.ec, .fin.ec, etc.
        if parts[-2] in ["com", "fin", "org", "net", "gob", "edu", "mil"] and len(parts) >= 3:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return domain

def calculate_levenshtein(s1, s2):
    """Calcula la distancia de Levenshtein entre dos strings"""
    if len(s1) < len(s2):
        return calculate_levenshtein(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]

def check_identity_and_typosquatting(url):
    """
    Analiza si la URL es un dominio de alta confianza o un intento de suplantación.
    """
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    if ':' in domain:
        domain = domain.split(':')[0]
    
    base_domain = get_base_domain(domain)
    full_hostname = domain
    
    # Lista de hostings gratuitos/sospechosos donde se suelen crear subdominios de phishing
    SUSPICIOUS_SUFFIXES = ["webcindario.com", "000webhostapp.com", "vercel.app", "github.io", "web.app", "firebaseapp.com"]
    
    # 1. ¿Es un dominio de confianza exacto?
    if base_domain in HIGH_TRUST_DOMAINS:
        return {
            "status": "verified",
            "name": HIGH_TRUST_DOMAINS[base_domain],
            "reason": f"Identidad confirmada: Sitio oficial de {HIGH_TRUST_DOMAINS[base_domain]}."
        }
    
    # 2. ¿Es un ataque de Typosquatting (suplantación)?
    for trust_domain, trust_name in HIGH_TRUST_DOMAINS.items():
        trust_base = trust_domain.split('.')[0]
        
        # Revisamos tanto el dominio base como el hostname completo (subdominios)
        # Esto captura habilitar-outl3.webcindario.com
        parts_to_check = [base_domain.split('.')[0]]
        if base_domain in SUSPICIOUS_SUFFIXES:
            # Si el dominio base es un hosting, revisamos los subdominios
            parts_to_check.extend(full_hostname.split('.'))
        else:
            # Siempre revisar si la marca está oculta en algún lado
            parts_to_check.extend(full_hostname.split('.'))

        for part in set(parts_to_check):
            if not part or part == "com" or part == "www": continue
            
            # Caso 1: Distancia de Levenshtein (ej: outl3 vs outlook)
            if part != trust_base:
                distance = calculate_levenshtein(part, trust_base)
                if distance <= 2 and len(trust_base) > 3:
                    # Umbral más estricto para partes cortas
                    if distance == 1 or len(part) > 4:
                        return {
                            "status": "impersonation",
                            "target": trust_name,
                            "reason": f"ALERTA DE SUPLANTACIÓN: El término '{part}' parece intentar imitar a {trust_name} ({trust_domain})."
                        }

            # Caso 2: Contiene la marca pero con extras sospechosos (ej: pichincha-login)
            if trust_base in part and len(part) > len(trust_base):
                # Evitar falsos positivos si es una palabra legítima que contiene la otra (difícil en este contexto)
                return {
                    "status": "impersonation",
                    "target": trust_name,
                    "reason": f"ALERTA DE SUPLANTACIÓN: Se detectó el nombre de '{trust_name}' en un dominio no oficial ({part})."
                }

    return {"status": "unknown"}



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
    # Aumentamos umbral: 4 o más es sospechoso, 3 es "múltiples"
    if domain.count("-") >= 4:
        score += 15
        reasons.append(f"Uso excesivo de guiones en el dominio ({domain.count('-')} guiones)")
    elif domain.count("-") >= 3:
        score += 5  # Bajamos puntaje de 8 a 5
        reasons.append("Múltiples guiones en el dominio")
    
    # 2. Números largos en la URL
    long_numbers = re.findall(r'\d{4,}', url)
    if long_numbers:
        score += 12
        reasons.append(f"Números largos sospechosos: {', '.join(long_numbers[:2])}")
    
    # 3. Palabras clave sospechosas
    # Refinamos: solo si están en el host o path, y bajamos peso
    url_lower = url.lower()
    found_keywords = [word for word in SUSPICIOUS_KEYWORDS if word in url_lower]
    if found_keywords:
        # Reducimos peso por palabra de 5 a 3, y tope de 20 a 15
        points = min(15, len(found_keywords) * 3)
        score += points
        reasons.append(f"Palabras clave detectadas: {', '.join(found_keywords[:3])}")
    
    # 4. URL demasiado larga
    # Aumentamos umbral de 100 a 150 caracteres para evitar falsos positivos en deep links
    if len(url) > 150:
        score += 10
        reasons.append(f"URL excesivamente larga ({len(url)} caracteres)")
    elif len(path) > 80:  # Path muy largo (aumentado de 50 a 80)
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
    # Aumentamos umbral de 4.0 a 4.5 para ser menos sensible
    if domain_entropy > 4.5:  # Alta aleatoriedad
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
