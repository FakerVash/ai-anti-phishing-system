
import requests

def test_impersonation(url):
    print(f"\n🔍 Probando URL: {url}")
    try:
        response = requests.post("http://127.0.0.1:5000/check", json={"url": url})
        data = response.json()
        
        identity = data.get("identity", {})
        status = data.get("status")
        reason = data.get("reason")
        
        print(f"  - Estatus Global: {status}")
        print(f"  - Motor Identidad: {identity.get('status')} ({identity.get('reason')})")
        print(f"  - Razón Consenso: {reason}")
        
    except Exception as e:
        print(f"❌ Error al conectar: {e}")

if __name__ == "__main__":
    # URLs de prueba
    test_impersonation("https://habilitar-outl3.webcindario.com/")
    test_impersonation("https://pichincha-seguro.000webhostapp.com/")
    test_impersonation("https://login.outlook.com/") # Debería ser verificado
