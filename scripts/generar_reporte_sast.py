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
        "ps": 100,
        "p": 1
    }
    issues = []
    while True:
        resp = requests.get(url, auth=auth, params=params)
        data = resp.json()
        issues.extend(data.get("issues", []))
        paging = data.get("paging", {})
        if paging.get("pageIndex", 1) >= paging.get("total", 1):
            break
        params["p"] += 1
    return issues

def map_rule_to_recommendation(rule_key):
    mapping = {
        "typescript:S7652": (
            "Evita nombrar outputs con prefijos o nombres 'on'.\n\n"
            "Ejemplo no conforme:\n"
            "```typescript\n"
            "class MyComponent {\n"
            "  onClick = output();  // No conforme\n"
            "  change = output({ alias: 'onChange' }); // No conforme\n"
            "}\n"
            "```\n\n"
            "Ejemplo conforme:\n"
            "```typescript\n"
            "class MyComponent {\n"
            "  click = new EventEmitter();\n"
            "  submit = new EventEmitter();\n"
            "}\n"
            "```\n\n"
            "Más detalles: https://angular.dev/guide/components/outputs#choosing-event-names"
        ),
        "python:S2077": (
            "Evitar uso de eval() para prevenir ejecución de código arbitrario.\n"
            "Consulta: https://rules.sonarsource.com/python/RSPEC-2077"
        ),
        "python:S5063": (
            "Validar correctamente entradas para evitar inyecciones SQL.\n"
            "Consulta: https://rules.sonarsource.com/python/RSPEC-5063"
        ),
        # Añade más reglas y recomendaciones aquí
    }
    return mapping.get(rule_key, "Consultar documentación oficial de la regla para remediación.")

def generate_report(issues):
    with open("reporte_sast.md", "w", encoding="utf-8") as f:
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
            recomendacion = map_rule_to_recommendation(rule)

            f.write(f"## Vulnerabilidad: {message}\n")
            f.write(f"- Severidad: **{severity}**\n")
            f.write(f"- Archivo: {component}\n")
            f.write(f"- Línea: {line}\n")
            f.write(f"- Regla: {rule}\n")
            f.write(f"- Recomendación:\n{recomendacion}\n\n")

if __name__ == "__main__":
    issues = fetch_vulnerabilities()
    generate_report(issues)
    print("📄 Reporte de vulnerabilidades generado: reporte_sast.md")