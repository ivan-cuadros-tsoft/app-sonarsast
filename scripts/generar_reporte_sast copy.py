import requests
from collections import Counter

SONAR_URL = "https://sonarcloud.io"
PROJECT_KEY = "ivan-cuadros-tsoft-key"
TOKEN = "a98db4d1441ccd6ca3a59bfd2a52e27dde6dffa3"

auth = (TOKEN, "")

# Obtener vulnerabilidades
issues_url = f"{SONAR_URL}/api/issues/search"
params = {
    "componentKeys": PROJECT_KEY,
    "types": "VULNERABILITY",
    "ps": 500
}

response = requests.get(issues_url, params=params, auth=auth)
data = response.json()

issues = data.get("issues", [])

# Contar severidades
severity_count = Counter(issue["severity"] for issue in issues)

# Obtener quality gate
qg_url = f"{SONAR_URL}/api/qualitygates/project_status?projectKey={PROJECT_KEY}"
qg_response = requests.get(qg_url, auth=auth)
qg_status = qg_response.json()["projectStatus"]["status"]

# Evaluar recomendación
if qg_status == "OK":
    recommendation = "✅ Aprobado para despliegue"
else:
    recommendation = "❌ No aprobado para despliegue"

# Generar informe
report = f"""
# Informe SAST - SonarQube

## Resumen
- Proyecto: {PROJECT_KEY}
- Total vulnerabilidades: {len(issues)}

## Severidades
- Críticas: {severity_count.get('CRITICAL', 0)}
- Altas: {severity_count.get('MAJOR', 0)}
- Medias: {severity_count.get('MINOR', 0)}

## Quality Gate
Estado: {qg_status}

## Recomendación
{recommendation}
"""

with open("reporte_sast.md", "w") as f:
    f.write(report)

print("Reporte generado: reporte_sast.md")