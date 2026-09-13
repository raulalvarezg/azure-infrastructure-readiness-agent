# Azure Infrastructure Readiness Agent

AI-powered agent that validates Azure infrastructure deployment YAML files, detects
Linux and SAP high-availability (HA) deployment risks, and generates human-readable
deployment readiness assessments with corrective action recommendations — before
you deploy to production.

## Features

- **YAML syntax validation** — catches malformed YAML with precise line/column errors.
- **Azure infrastructure checks** — required metadata, valid region names, VM sizing,
  availability zone/set placement for production, managed disks, virtual network
  configuration, and open network security group (NSG) rules on sensitive ports.
- **Linux HA risk detection** — Pacemaker fencing/STONITH configuration, cluster
  quorum/split-brain risk, cluster type declaration, and supported Linux
  distributions for HA.
- **SAP HA risk detection** — HANA fencing agent, shared storage for `/hana/shared`,
  SAP Central Services (SCS/ASCS) high availability, HANA VM sizing, and backup
  configuration.
- **Readiness assessments** — an overall `READY` / `READY WITH WARNINGS` / `NOT READY`
  status and a 0-100 readiness score.
- **Human-readable explanations** — every finding includes a plain-language
  explanation and a specific recommended corrective action.
- **Modular architecture** — validators, rules, and the explanation engine are
  independent, composable Python modules.
- **Command line interface** — run assessments directly from the terminal with
  text or JSON output.

## Project structure

```
src/
  models.py             # Shared data models (Issue, ReadinessAssessment, etc.)
  validators/
    yaml_validator.py    # YAML syntax & basic structure validation
  rules/
    base.py              # Rule/RuleSet base classes
    azure_rules.py        # Azure infrastructure configuration rules
    linux_ha_rules.py     # Linux HA (Pacemaker) deployment risk rules
    sap_ha_rules.py        # SAP HANA/SCS HA deployment risk rules
  ai/
    explainer.py          # Human-readable explanation & summary generation
    assessment.py          # End-to-end readiness assessment pipeline
  cli/
    main.py                # Command line interface entry point

tests/                    # Unit tests for every module
samples/                  # Example YAML deployment files (valid & risky)
```

## Installation

Requires Python 3.8+.

```bash
pip install -r requirements.txt
```

Optionally, install the package (and the `readiness-agent` console script):

```bash
pip install -e .
```

## Usage

### Command line

```bash
python3 -m src.cli.main samples/valid_sap_ha_deployment.yaml
```

Or, if installed as a package:

```bash
readiness-agent samples/valid_sap_ha_deployment.yaml
```

Example output:

```
============================================================
Azure Infrastructure Readiness Assessment
============================================================
Status: READY
Score:  100/100

No issues were detected. The deployment configuration follows Azure, Linux HA, and SAP HA best practices.
```

#### Options

| Flag | Description |
| --- | --- |
| `--format {text,json}` | Output format. Defaults to `text`. |
| `--strict` | Exit non-zero unless the deployment status is fully `READY` (by default, only `NOT_READY` causes a non-zero exit code). |

JSON output example:

```bash
python3 -m src.cli.main samples/risky_azure_config.yaml --format json
```

```json
{
  "status": "not_ready",
  "score": 0,
  "summary": "Found 7 issues across the deployment (2 critical, 3 high, 2 medium)...",
  "explanations": ["..."],
  "issues": [
    {
      "rule_id": "azure-nsg-008",
      "category": "azure",
      "severity": "critical",
      "message": "NSG 'nsg-open' rule 'allow-ssh-any' allows inbound traffic from the public internet on port 22.",
      "recommendation": "Restrict 'source_address_prefix' to trusted IP ranges...",
      "path": "networking.network_security_groups[0].rules[0]",
      "details": {}
    }
  ]
}
```

### Using the Python API

```python
from src.ai.assessment import assess_deployment_file

assessment = assess_deployment_file("samples/valid_sap_ha_deployment.yaml")
print(assessment.status, assessment.score)
for issue in assessment.issues:
    print(issue.severity, issue.message, "->", issue.recommendation)
```

## Sample YAML files

The `samples/` directory contains example deployment files used both for manual
exploration and by the automated test suite:

| File | Purpose |
| --- | --- |
| `valid_sap_ha_deployment.yaml` | A fully compliant production SAP HANA HA deployment (expected: `READY`). |
| `warnings_only_deployment.yaml` | A deployment with only a medium-severity finding (expected: `READY WITH WARNINGS`). |
| `invalid_syntax.yaml` | Deliberately malformed YAML to exercise syntax validation. |
| `risky_azure_config.yaml` | Missing VM size, open SSH/RDP to the internet, unmanaged disks, invalid region, no vnet. |
| `risky_linux_ha_deployment.yaml` | Pacemaker cluster missing fencing, even node count without a quorum device, unsupported distro. |
| `risky_sap_ha_deployment.yaml` | SAP HANA HA missing fencing, shared storage, SCS HA, and undersized VM. |

## Deployment YAML schema (informal)

```yaml
metadata:
  name: string            # required
  environment: string     # required (e.g. production, staging, dev)
  region: string           # required (Azure region name, e.g. eastus)

networking:
  vnet: string
  subnets: [...]
  network_security_groups:
    - name: string
      rules:
        - name: string
          direction: Inbound|Outbound
          access: Allow|Deny
          protocol: string
          destination_port_range: string
          source_address_prefix: string

resources:
  - type: Microsoft.Compute/virtualMachines
    name: string
    sap_role: hana            # optional, used by SAP rules
    properties:
      size: string             # Azure VM SKU
      os_type: Linux
      os_distro: string        # e.g. sles_sap, rhel_ha
      availability_zone: int
      availability_set: string
      managed_disk_type: string

high_availability:
  enabled: bool
  cluster_type: string        # e.g. pacemaker
  fencing_agent: string        # e.g. sbd, azure_fence_agent
  number_of_nodes: int
  quorum_device: string

sap:
  enabled: bool
  hana_ha_enabled: bool
  scs_ha_enabled: bool
  fencing_agent: string
  shared_storage_type: string  # e.g. ANF, azure_files
  backup_enabled: bool
```

## Running the tests

```bash
python3 -m unittest discover -s tests -v
```

## Extending the rule engine

Each rule is a small, independent class implementing `Rule.evaluate(deployment) -> List[Issue]`
(see `src/rules/base.py`). To add a new rule:

1. Create a `Rule` subclass in the relevant module (`azure_rules.py`, `linux_ha_rules.py`,
   `sap_ha_rules.py`, or a new module).
2. Register it in that module's `default_*_rules()` function.
3. Add unit tests covering both the "issue detected" and "no issue" cases.

Because rules are pure functions over a parsed dictionary, they are simple to unit
test in isolation without needing real YAML files.
