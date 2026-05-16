import json
import time
import subprocess
from datetime import datetime
from collections import defaultdict
from elasticsearch import Elasticsearch

# -----------------------------------
# Elasticsearch Connection
# -----------------------------------

es = Elasticsearch("http://localhost:9200")

# -----------------------------------
# Load Custom Detection Rules
# -----------------------------------

RULES_FILE = "/rules/mitre_rules.json"

with open(RULES_FILE, "r") as f:
    rules = json.load(f)

# -----------------------------------
# Load Official MITRE ATT&CK Dataset
# -----------------------------------

MITRE_FILE = "/mitre/enterprise-attack.json"

with open(MITRE_FILE, "r") as f:
    mitre_data = json.load(f)

mitre_techniques = {}

for obj in mitre_data["objects"]:

    if obj.get("type") == "attack-pattern":

        refs = obj.get("external_references", [])

        technique_id = None

        for ref in refs:

            if ref.get("source_name") == "mitre-attack":

                technique_id = ref.get("external_id")

        if technique_id:

            tactic_names = []

            for phase in obj.get("kill_chain_phases", []):

                tactic_names.append(
                    phase.get("phase_name")
                )

            mitre_techniques[technique_id] = {

                "name":
                    obj.get("name"),

                "description":
                    obj.get("description", ""),

                "tactics":
                    tactic_names
            }

print("=" * 60)
print(f"Loaded {len(mitre_techniques)} MITRE techniques")
print("=" * 60)

# -----------------------------------
# Memory Structures
# -----------------------------------

processed_ids = set()

failed_logins = defaultdict(list)

print("=" * 60)
print("MITRE Analyzer Started...")
print("=" * 60)

# -----------------------------------
# Trigger Trivy Scan
# -----------------------------------

def trigger_trivy_scan():

    print("\n[+] Starting Trivy Scan...")

    try:

        subprocess.run([

            "docker",
            "exec",
            "trivy-scanner",

            "trivy",
            "image",

            "--scanners",
            "vuln",

            "--format",
            "json",

            "--output",
            "/reports/report.json",

            "nginx:latest"

        ], check=True)

        print("[+] Trivy Scan Completed")

    except Exception as e:

        print("[!] Trivy Scan Failed")
        print(str(e))


# -----------------------------------
# Run Vulnerability Parser
# -----------------------------------

def run_parser():

    print("\n[+] Running Vulnerability Parser...")

    try:

        subprocess.run([

            "docker",
            "exec",
            "vulnerability-parser",

            "python",

            "parser.py"

        ], check=True)

        print("[+] Vulnerability Parser Completed")

    except Exception as e:

        print("[!] Vulnerability Parser Failed")
        print(str(e))


# -----------------------------------
# Generate Final Security Report
# -----------------------------------

def generate_final_report(attack_event):

    print("\n[+] Generating Final Security Report...")

    vulnerabilities = es.search(

        index="vulnerabilities",

        size=50,

        sort=[
            {"timestamp": "desc"}
        ]
    )

    vuln_hits = vulnerabilities["hits"]["hits"]

    vuln_list = []

    recommendations = []

    critical_count = 0
    high_count = 0

    for hit in vuln_hits:

        vuln = hit["_source"]

        vuln_list.append({

            "cve":
                vuln.get("cve"),

            "package":
                vuln.get("package"),

            "severity":
                vuln.get("severity"),

            "installed_version":
                vuln.get("installed_version"),

            "fixed_version":
                vuln.get("fixed_version"),

            "title":
                vuln.get("title")
        })

        if vuln.get("severity") == "CRITICAL":
            critical_count += 1

        if vuln.get("severity") == "HIGH":
            high_count += 1

        recommendations.append({

            "package":
                vuln.get("package"),

            "current_version":
                vuln.get("installed_version"),

            "fix_version":
                vuln.get("fixed_version"),

            "recommendation":
                f"Upgrade "
                f"{vuln.get('package')} "
                f"to "
                f"{vuln.get('fixed_version')}"
        })

    risk_level = "LOW"

    if critical_count > 0:
        risk_level = "CRITICAL"

    elif high_count > 5:
        risk_level = "HIGH"

    elif high_count > 0:
        risk_level = "MEDIUM"

    final_report = {

        "timestamp":
            datetime.utcnow().isoformat(),

        "attack_type":
            attack_event.get("attack_type"),

        "mitre_technique_id":
            attack_event.get(
                "mitre_technique_id"
            ),

        "mitre_technique":
            attack_event.get(
                "mitre_technique"
            ),

        "severity":
            attack_event.get("severity"),

        "risk_score":
            attack_event.get("risk_score"),

        "message":
            attack_event.get("message"),

        "email":
            attack_event.get("email"),

        "risk_level":
            risk_level,

        "vulnerability_count":
            len(vuln_list),

        "critical_vulnerabilities":
            critical_count,

        "high_vulnerabilities":
            high_count,

        "vulnerabilities":
            vuln_list,

        "recommendations":
            recommendations
    }

    es.index(
        index="final-security-reports",
        document=final_report
    )

    print("\n" + "=" * 60)
    print("FINAL SECURITY REPORT GENERATED")
    print(json.dumps(
        final_report,
        indent=2
    ))
    print("=" * 60)


# -----------------------------------
# Main Loop
# -----------------------------------

while True:

    try:

        logs = es.search(
            index="bhishi-logs",
            size=100,
            sort=[{"@timestamp": "desc"}]
        )

        hits = logs["hits"]["hits"]

        for hit in hits:

            doc_id = hit["_id"]

            if doc_id in processed_ids:
                continue

            processed_ids.add(doc_id)

            source = hit["_source"]

            print("\nProcessing Log:")
            print(source)

            # ===================================
            # Brute Force Correlation Detection
            # ===================================

            if (
                source.get("event") == "admin_login"
                and source.get("status") == "failed"
            ):

                email = source.get("email", "unknown")

                failed_logins[email].append(time.time())

                failed_logins[email] = [

                    t for t in failed_logins[email]

                    if time.time() - t < 60
                ]

                print(
                    f"Failed login count for {email}: "
                    f"{len(failed_logins[email])}"
                )

                if len(failed_logins[email]) >= 5:

                    technique_id = "T1110"

                    mitre_info = mitre_techniques.get(
                        technique_id,
                        {}
                    )

                    brute_force_event = {

                        "@timestamp":
                            source.get("@timestamp"),

                        "event":
                            "brute_force_detected",

                        "status":
                            "detected",

                        "email":
                            email,

                        "attack_type":
                            "brute_force",

                        "mitre_technique_id":
                            technique_id,

                        "mitre_technique":
                            mitre_info.get("name"),

                        "mitre_tactic":
                            ",".join(
                                mitre_info.get(
                                    "tactics",
                                    []
                                )
                            ),

                        "mitre_description":
                            mitre_info.get(
                                "description"
                            ),

                        "severity":
                            "critical",

                        "risk_score":
                            95,

                        "message":
                            "Multiple failed login attempts detected"
                    }

                    # -----------------------------------
                    # Store Security Event
                    # -----------------------------------

                    es.index(
                        index="security-events",
                        document=brute_force_event
                    )

                    print("\n" + "=" * 60)
                    print("BRUTE FORCE DETECTED")
                    print(json.dumps(
                        brute_force_event,
                        indent=2
                    ))
                    print("=" * 60)

                    # -----------------------------------
                    # Trigger Vulnerability Workflow
                    # -----------------------------------

                    trigger_trivy_scan()

                    time.sleep(5)

                    run_parser()

                    time.sleep(5)

                    generate_final_report(
                        brute_force_event
                    )

            # ===================================
            # Rule Matching
            # ===================================

            for rule in rules:

                matched = False

                if rule.get("event") == source.get("event"):

                    if "status" in rule:

                        if (
                            rule["status"]
                            == source.get("status")
                        ):

                            matched = True

                    else:

                        matched = True

                # -----------------------------------
                # MITRE Dynamic Lookup
                # -----------------------------------

                if matched:

                    technique_id = rule.get(
                        "mitre_technique_id"
                    )

                    mitre_info = mitre_techniques.get(
                        technique_id,
                        {}
                    )

                    enriched = {

                        "@timestamp":
                            source.get("@timestamp"),

                        "event":
                            source.get("event"),

                        "status":
                            source.get("status"),

                        "email":
                            source.get("email"),

                        "attack_type":
                            rule["attack_type"],

                        "mitre_technique_id":
                            technique_id,

                        "mitre_technique":
                            mitre_info.get("name"),

                        "mitre_tactic":
                            ",".join(
                                mitre_info.get(
                                    "tactics",
                                    []
                                )
                            ),

                        "mitre_description":
                            mitre_info.get(
                                "description"
                            ),

                        "severity":
                            rule["severity"],

                        "risk_score":
                            rule["risk_score"],

                        "message":
                            source.get("message")
                    }

                    es.index(
                        index="security-events",
                        document=enriched
                    )

                    print("\nThreat Detected:")
                    print(json.dumps(
                        enriched,
                        indent=2
                    ))

        time.sleep(5)

    except Exception as e:

        print("\nERROR:")
        print(str(e))

        time.sleep(5)
