import os
import requests
import html
from bs4 import BeautifulSoup

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

def html_to_markdown_text(html_text):
    # Usa BeautifulSoup para limpiar etiquetas HTML y convertir a texto plano simple
    soup = BeautifulSoup(html_text, "html.parser")
    text = soup.get_text(separator="\n")
    # Desescape entidades HTML
    return html.unescape(text.strip())

def fetch_rule_description(rule_key):
    url = f"{SONAR_URL}/api/rules/show"
    params = {"key": rule_key}
    resp = requests.get(url, params=params)
    if resp.status_code != 200:
        return "Consultar documentación oficial de la regla para remediación."
    data = resp.json()
    rule = data.get("rule", {})
    desc_html = rule.get("htmlDesc", "")
    desc_text = html_to_markdown_text(desc_html)
    lang, code = rule_key.split(":", 1)
    rule_url = f"https://rules.sonarsource.com/{lang}/RSPEC-{code[1:]}" if code.startswith("S") else ""
    recommendation = f"{desc_text}\n\nMás detalles: {rule_url}"
    return recommendation

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
            recomendacion = fetch_rule_description(rule)

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