import os
import requests
import html
from bs4 import BeautifulSoup

SONAR_URL = os.getenv("SONAR_URL", "https://sonarcloud.io")
PROJECT_KEY = os.getenv("PROJECT_KEY")
TOKEN = os.getenv("SONAR_TOKEN")
auth = (TOKEN, "")

# Colores según severidad
SEVERITY_COLORS = {
    "BLOCKER": "#ff4d4d",
    "CRITICAL": "#ff944d",
    "MAJOR": "#ffd11a",
    "MINOR": "#a3d1ff",
    "INFO": "#b3b3b3",
    "UNKNOWN": "#cccccc"
}

def fetch_vulnerabilities():
    url = f"{SONAR_URL}/api/issues/search"
    params = {
        "componentKeys": PROJECT_KEY,
        "types": "VULNERABILITY",
        "resolved": "false",
        "ps": 100,
        "p": 1,
        "sinceLeakPeriod": "true"  # 🔥 CLAVE
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

def html_to_text(html_text):
    soup = BeautifulSoup(html_text, "html.parser")
    return html.unescape(soup.get_text(separator="\n").strip())

def fetch_rule_description(rule_key):
    url = f"{SONAR_URL}/api/rules/show"
    params = {"key": rule_key}
    resp = requests.get(url, params=params)
    if resp.status_code != 200:
        return "Consultar documentación oficial de la regla para remediación."
    rule = resp.json().get("rule", {})
    desc_html = rule.get("htmlDesc", "")
    desc_text = html_to_text(desc_html)
    lang, code = rule_key.split(":", 1)
    rule_url = f"https://rules.sonarsource.com/{lang}/RSPEC-{code[1:]}" if code.startswith("S") else ""
    return f"{desc_text}\n\nMás detalles: <a href='{rule_url}' target='_blank'>{rule_url}</a>"

def generate_html_report(issues):
    with open("reporte_sast_html.html", "w", encoding="utf-8") as f:
        f.write("""
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>Informe Profesional SAST</title>
<style>
body { font-family: Arial, sans-serif; margin: 20px; background: #f9f9f9; }
h1 { color: #2F4F4F; }
h2 { color: #4682B4; }
table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
th { background-color: #4682B4; color: white; }
tr:hover { background-color: #f1f1f1; }
.severity { font-weight: bold; color: white; padding: 3px 8px; border-radius: 4px; }
.issue-details { background: #fff; border-radius: 8px; padding: 15px; margin-bottom: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);}
.recommendation { background: #f0f8ff; padding: 10px; border-left: 4px solid #4682B4; white-space: pre-wrap; }
</style>
</head>
<body>
<h1>Informe Profesional de Vulnerabilidades SAST</h1>
""")

        if not issues:
            f.write("<p>No se encontraron vulnerabilidades abiertas.</p>\n")
            f.write("</body></html>")
            return

        # Tabla resumen
        f.write("<h2>Resumen de Vulnerabilidades</h2>\n")
        f.write("<table>\n<tr><th>Mensaje</th><th>Severidad</th><th>Archivo</th><th>Línea</th><th>Regla</th></tr>\n")
        for issue in issues:
            severity = issue.get("severity", "UNKNOWN")
            message = issue.get("message", "")
            component = issue.get("component", "")
            line = issue.get("line", "N/A")
            rule = issue.get("rule", "")
            color = SEVERITY_COLORS.get(severity.upper(), "#cccccc")
            f.write(f"<tr><td>{message}</td><td style='background:{color}; color:white;'>{severity}</td><td>{component}</td><td>{line}</td><td>{rule}</td></tr>\n")
        f.write("</table>\n")

        # Detalles de cada vulnerabilidad
        f.write("<h2>Detalles de Vulnerabilidades</h2>\n")
        for issue in issues:
            severity = issue.get("severity", "UNKNOWN")
            message = issue.get("message", "")
            component = issue.get("component", "")
            line = issue.get("line", "N/A")
            rule = issue.get("rule", "")
            recomendacion = fetch_rule_description(rule)
            f.write("<div class='issue-details'>\n")
            f.write(f"<h3>{message}</h3>\n")
            f.write(f"<p><strong>Severidad:</strong> {severity}</p>\n")
            f.write(f"<p><strong>Archivo:</strong> {component} | <strong>Línea:</strong> {line}</p>\n")
            f.write(f"<p><strong>Regla:</strong> {rule}</p>\n")
            f.write(f"<div class='recommendation'><strong>Recomendación:</strong>\n{recomendacion}</div>\n")
            f.write("</div>\n")

        summary = count_by_severity(issues)

        f.write("<h2>Resumen por Severidad</h2>\n")
        total = sum(summary.values())
        f.write(f"<p><strong>Total de vulnerabilidades:</strong> {total}</p>")

        f.write("<table>\n<tr><th>Severidad</th><th>Cantidad</th></tr>\n")

        for severity, count in summary.items():
            color = SEVERITY_COLORS.get(severity.upper(), "#cccccc")
            f.write(f"<tr><td style='background:{color}; color:white;'>{severity}</td><td>{count}</td></tr>\n")

        f.write("</table>\n")

        f.write("</body></html>")
    print("📄 Reporte profesional generado: reporte_sast_html.html")

def count_by_severity(issues):
    summary = {}
    for issue in issues:
        severity = issue.get("severity", "UNKNOWN")
        summary[severity] = summary.get(severity, 0) + 1
    return summary

if __name__ == "__main__":
    issues = fetch_vulnerabilities()
    generate_html_report(issues)