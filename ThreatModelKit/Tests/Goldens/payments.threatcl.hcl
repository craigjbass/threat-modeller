spec_version = "0.8.1"

threatmodel "Payments" {
  author = "Craig"
  description = "Takes card payments."
  link = "https://example.com/design"
  repository = ["https://github.com/example/payments"]

  information_asset "Card numbers" {
    description = "The primary account numbers."
    information_classification = "Restricted"
  }

  usecase {
    description = "take-a-payment: A customer pays for a basket."
  }

  exclusion {
    description = "the card network: This model does not cover the card network. Another team owns it."
  }

  exclusion {
    description = "Assumed: network-segmented: The VPC has no route to the internet."
  }

  third_party_dependency "Stripe" {
    description = "Stripe provides EC2"
    saas = "true"
    open_source = "false"
    infrastructure = "false"
    paying_customer = "true"
    uptime_dependency = "hard"
    uptime_notes = "No payment is taken while Stripe is down."
  }

  threat "Credential Theft on EC2" {
    description = "Attacker steals credentials to impersonate a principal"
    impacts = ["Confidentiality"]
    stride = ["Spoofing"]
    information_asset_refs = ["Card numbers"]

    risk {
      likelihood = "high"
      impact = "very_high"
      severity = "critical"
      rationale = "Residual 13 of 13 before controls, on EC2."
    }

    control "Enforce IMDSv2 to block SSRF-based credential theft" {
      description = "Enforce IMDSv2 to block SSRF-based credential theft"
      implemented = false
      risk_reduction = 0
    }

    control "Use IAM roles with minimal permissions" {
      description = "Use IAM roles with minimal permissions"
      implemented = false
      risk_reduction = 0
    }
  }

  threat "Man-in-the-Middle Attack on actor-attacker → EC2" {
    description = "Attacker intercepts traffic between two components"
    impacts = ["Confidentiality", "Integrity"]
    stride = ["Tampering", "Info Disclosure"]

    risk {
      likelihood = "high"
      impact = "medium"
      severity = "high"
      rationale = "Residual 8 of 8 before controls, on actor-attacker → EC2."
    }

    control "Enforce TLS on every hop" {
      description = "Enforce TLS on every hop"
      implemented = false
      risk_reduction = 0
    }
  }

  threat "Man-in-the-Middle Attack on EC2 → RDS" {
    description = "Attacker intercepts traffic between two components"
    impacts = ["Confidentiality", "Integrity"]
    stride = ["Tampering", "Info Disclosure"]

    risk {
      likelihood = "high"
      impact = "medium"
      severity = "medium"
      rationale = "Residual 6 of 6 before controls, on EC2 → RDS."
    }

    control "Enforce TLS on every hop" {
      description = "Enforce TLS on every hop"
      implemented = false
      risk_reduction = 0
    }
  }

  threat "Misconfiguration on EC2" {
    description = "Insecure defaults or drift leave the service exposed"
    impacts = ["Integrity"]
    stride = ["Tampering"]
    information_asset_refs = ["Card numbers"]

    risk {
      likelihood = "high"
      impact = "medium"
      severity = "medium"
      rationale = "Residual 6 of 6 before controls, on EC2."
    }

    control "Scan configuration continuously" {
      description = "Scan configuration continuously"
      implemented = false
      risk_reduction = 0
    }
  }

  threat "Misconfiguration on RDS" {
    description = "Insecure defaults or drift leave the service exposed"
    impacts = ["Integrity"]
    stride = ["Tampering"]

    risk {
      likelihood = "high"
      impact = "medium"
      severity = "medium"
      rationale = "Residual 6 of 6 before controls, on RDS."
    }

    control "Scan configuration continuously" {
      description = "Scan configuration continuously"
      implemented = false
      risk_reduction = 0
    }
  }

  threat "Lateral Movement on Private Zone" {
    description = "Attacker pivots between resources inside the network zone"
    impacts = ["Confidentiality", "Integrity", "Availability"]
    stride = ["Elevation Of Privilege"]

    risk {
      likelihood = "high"
      impact = "high"
      severity = "medium"
      rationale = "Residual 5 of 5 before controls, on Private Zone."
    }

    control "Segment the network and restrict east-west traffic" {
      description = "Segment the network and restrict east-west traffic"
      implemented = false
      risk_reduction = 0
    }
  }

  threat "Connection Flooding on actor-attacker → EC2" {
    description = "Attacker exhausts the link between two components"
    impacts = ["Availability"]
    stride = ["Denial Of Service"]

    risk {
      likelihood = "high"
      impact = "low"
      severity = "medium"
      rationale = "Residual 4 of 4 before controls, on actor-attacker → EC2."
    }

    control "Apply connection rate limits" {
      description = "Apply connection rate limits"
      implemented = false
      risk_reduction = 0
    }
  }

  threat "Connection Flooding on EC2 → RDS" {
    description = "Attacker exhausts the link between two components"
    impacts = ["Availability"]
    stride = ["Denial Of Service"]

    risk {
      likelihood = "high"
      impact = "low"
      severity = "low"
      rationale = "Residual 3 of 3 before controls, on EC2 → RDS."
    }

    control "Apply connection rate limits" {
      description = "Apply connection rate limits"
      implemented = false
      risk_reduction = 0
    }
  }

  threat "Denial of Service on EC2" {
    description = "Attacker exhausts capacity to deny availability"
    impacts = ["Availability"]
    stride = ["Denial Of Service"]
    information_asset_refs = ["Card numbers"]

    risk {
      likelihood = "high"
      impact = "low"
      severity = "low"
      rationale = "Residual 3 of 3 before controls, on EC2."
    }

    control "Apply rate limits" {
      description = "Apply rate limits"
      implemented = false
      risk_reduction = 0
    }
  }

  threat "Misconfiguration on Private Zone" {
    description = "Insecure defaults or drift leave the service exposed"
    impacts = ["Integrity"]
    stride = ["Tampering"]

    risk {
      likelihood = "high"
      impact = "medium"
      severity = "low"
      rationale = "Residual 3 of 3 before controls, on Private Zone."
    }

    control "Scan configuration continuously" {
      description = "Scan configuration continuously"
      implemented = false
      risk_reduction = 0
    }
  }

  data_flow_diagram_v2 "Payments DFD" {

    trust_zone "Private Zone" {
      process "EC2" {
      }
      data_store "RDS" {
      }
    }

    process "actor-attacker" {
    }

    flow "Network" {
      from = "actor-attacker"
      to = "EC2"
      protocol = "Network"
    }

    flow "Network" {
      from = "EC2"
      to = "RDS"
      protocol = "Network"
    }
  }
}
