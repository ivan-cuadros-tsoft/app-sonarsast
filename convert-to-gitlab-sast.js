const fs = require("fs");

const input = process.argv[2];
const output = process.argv[3];

if (!input || !output) {
  console.error("Uso: node convert-to-gitlab-sast.js input.json output.json");
  process.exit(1);
}

const sonarData = JSON.parse(fs.readFileSync(input, "utf8"));

const mapSeverity = (severity) => {
  switch (severity) {
    case "BLOCKER":
    case "CRITICAL":
      return "High";
    case "MAJOR":
      return "Medium";
    case "MINOR":
      return "Low";
    default:
      return "Info";
  }
};

const vulnerabilities = (sonarData.issues || [])
  .filter(issue => issue.type === "VULNERABILITY")
  .map(issue => ({
    id: issue.key,
    category: "sast",
    name: issue.message,
    message: issue.message,
    description: issue.message,
    severity: mapSeverity(issue.severity),
    confidence: "Medium",
    scanner: {
      id: "sonarqube",
      name: "SonarQube"
    },
    location: {
      file: issue.component.split(":").pop(),
      start_line: issue.line || 1
    },
    identifiers: [
      {
        type: "sonarqube_rule",
        name: issue.rule,
        value: issue.rule
      }
    ]
  }));

const report = {
  version: "15.0.0",
  vulnerabilities
};

fs.writeFileSync(output, JSON.stringify(report, null, 2));
console.log("Reporte generado:", output);