import os
import requests

SONAR_URL = os.getenv("SONAR_URL", "https://sonarcloud.io")
PROJECT_KEY = os.getenv("PROJECT_KEY")
TOKEN = os.getenv("SONAR_TOKEN")
auth = (TOKEN, "")

def fetch_vulnerabilities():
    url = f"{SONAR_URL}/api/issues/search"
    params = {
        "componentKeys": PROJECT_KEY,
        "types": "VULNERABILITY",
        "resolved": "false",
        "ps": 100,  # página tamaño máximo (100)
        "p": 1      # página 1 (puedes implementar paginado)
    }
    issues = []
    while True:
        resp = requests.get(url, auth=auth, params=params)
        data = resp.json()
        issues.extend(data.get("issues", []))
        if data.get("paging", {}).get("pageIndex") >= data.get("paging", {}).get("total"):
            break
        params["p"] += 1
    return issues

def generate_report(issues):
    with open("reporte_sast.md", "w") as f:
        f.write("# Reporte de Vulnerabilidades SAST\n\n")
        if not issues:
            f.write("No se encontraron vulnerabilidades abiertas.\n")
            return

        for issue in issues:
            severity = issue.get("severity", "UNKNOWN")
            message = issue.get("message", "")
            component = issue.get("component", "")
            line = issue.get("line", "N/A")
            rule = issue.get("rule", "")

            # Aquí podrías mapear reglas a recomendaciones personalizadas
            recomendacion = map_rule_to_recommendation(rule)

            f.write(f"## Vulnerabilidad: {message}\n")
            f.write(f"- Severidad: **{severity}**\n")
            f.write(f"- Archivo: {component}\n")
            f.write(f"- Línea: {line}\n")
            f.write(f"- Regla: {rule}\n")
            f.write(f"- Recomendación: {recomendacion}\n\n")

def map_rule_to_recommendation(rule_key):
    # Mapea reglas comunes a recomendaciones (puedes ampliar esta lista)
    mapping = {
        "python:S2077": "Evitar uso de eval() para prevenir ejecución de código arbitrario.",
        "python:S5063": "Validar correctamente entradas para evitar inyecciones SQL.",
        "python:S4044": "No usar funciones con vulnerabilidades conocidas.",
        # Añade más reglas y recomendaciones aquí
    }
    return mapping.get(rule_key, "Consultar documentación oficial de la regla para remediación.")

if __name__ == "__main__":
    issues = fetch_vulnerabilities()
    generate_report(issues)
    print("📄 Reporte de vulnerabilidades generado: reporte_sast.md")