import json
import time
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

print("=" * 50)
print(f"Loaded {len(mitre_techniques)} MITRE techniques")
print("=" * 50)

# -----------------------------------
# Memory Structures
# -----------------------------------

processed_ids = set()

failed_logins = defaultdict(list)

print("=" * 50)
print("MITRE Analyzer Started...")
print("=" * 50)

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
            # Correlation Detection
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

                    es.index(
                        index="security-events",
                        document=brute_force_event
                    )

                    print("\n" + "=" * 50)
                    print("BRUTE FORCE DETECTED")
                    print(json.dumps(
                        brute_force_event,
                        indent=2
                    ))
                    print("=" * 50)

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
