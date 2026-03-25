import requests
import time
import sys
from collections import Counter
import os

# ==============================
# CONFIGURACIÓN (desde ENV)
# ==============================
SONAR_URL = os.getenv("SONAR_URL", "https://sonarcloud.io")
PROJECT_KEY = os.getenv("PROJECT_KEY")
TOKEN = os.getenv("SONAR_TOKEN")

if not PROJECT_KEY or not TOKEN:
    print("❌ Faltan variables de entorno: PROJECT_KEY o SONAR_TOKEN")
    sys.exit(1)

auth = (TOKEN, "")

# ==============================
# FUNCIÓN: ESPERAR QUALITY GATE
# ==============================
def get_quality_gate():
    url = f"{SONAR_URL}/api/qualitygates/project_status?projectKey={PROJECT_KEY}"

    for i in range(15):
        response = requests.get(url, auth=auth)
        data = response.json()

        print(f"Intento {i+1} - respuesta:", data)

        if "projectStatus" in data:
            return data["projectStatus"]["status"]

        if "errors" in data:
            print("❌ Error desde API:", data["errors"])
            sys.exit(1)

        print("⏳ Esperando análisis de SonarCloud...")
        time.sleep(10)

    print("❌ Timeout esperando Quality Gate")
    sys.exit(1)

# ==============================
# FUNCIÓN: OBTENER ISSUES
# ==============================
def get_issues():
    url = f"{SONAR_URL}/api/issues/search"
    params = {
        "componentKeys": PROJECT_KEY,
        "types": "VULNERABILITY",
        "ps": 500
    }

    response = requests.get(url, params=params, auth=auth)
    data = response.json()

    if "issues" not in data:
        print("❌ Error obteniendo issues:", data)
        sys.exit(1)

    return data["issues"]

# ==============================
# PROCESO PRINCIPAL
# ==============================
print("🔍 Obteniendo Quality Gate...")
qg_status = get_quality_gate()

print("🔍 Obteniendo vulnerabilidades...")
issues = get_issues()

# Contar severidades
severity_count = Counter(issue["severity"] for issue in issues)

critical = severity_count.get("CRITICAL", 0)
high = severity_count.get("MAJOR", 0)
medium = severity_count.get("MINOR", 0)
low = severity_count.get("LOW", 0)

total = len(issues)

# ==============================
# EVALUACIÓN PERSONALIZADA
# ==============================
fail = False

if critical > 0:
    fail = True
elif high > 2:
    fail = True

# ==============================
# RECOMENDACIÓN FINAL
# ==============================
if qg_status == "OK" and not fail:
    recommendation = "✅ Aprobado para despliegue"
elif not fail:
    recommendation = "⚠️ Aprobado con observaciones"
else:
    recommendation = "❌ No aprobado para despliegue"

# ==============================
# GENERAR REPORTE
# ==============================
report = f"""
# 🛡️ Informe SAST - SonarCloud

## 📌 Proyecto
- Project Key: {PROJECT_KEY}

## 📊 Resumen
- Total vulnerabilidades: {total}

## 🔎 Severidades
- Críticas: {critical}
- Altas: {high}
- Medias: {medium}
- Bajas: {low}

## 🚦 Quality Gate
- Estado: {qg_status}

## 📢 Recomendación
{recommendation}
"""

with open("reporte_sast.md", "w") as f:
    f.write(report)

print("📄 Reporte generado: reporte_sast.md")

# ==============================
# FALLAR PIPELINE SI ES NECESARIO
# ==============================
if fail or qg_status != "OK":
    print("❌ Pipeline fallido por políticas de seguridad")
    sys.exit(1)

print("✅ Pipeline OK")