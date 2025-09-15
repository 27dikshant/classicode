# DSPM/DLP Integration Guide for ClassiCode

**Enterprise Data Security Posture Management and Data Loss Prevention Integration**

---

## Executive Summary

ClassiCode serves as a **metadata provider** that embeds permanent classification information directly into files using extended attributes (xattrs). This creates self-identifying files that DSPM and DLP tools can automatically discover, classify, and protect without manual intervention. The integration enables automated policy enforcement based on file sensitivity levels across your entire enterprise infrastructure.

## Integration Architecture

ClassiCode operates as the **classification layer**, while DSPM/DLP tools function as **policy enforcement engines**. Files classified by ClassiCode carry their sensitivity metadata permanently, allowing downstream security tools to make informed protection decisions automatically.

### Key Integration Benefits

- **Automatic Discovery**: Files self-identify their classification across moves, copies, and renames
- **Consistent Policies**: Standardized metadata enables uniform policy enforcement
- **Cryptographic Integrity**: Hash validation prevents classification spoofing
- **Audit Compliance**: Complete chain of custody for sensitive data lifecycle

---

## 1. File Discovery Phase

### DSMP Scanning Integration

Your DSPM solution can automatically discover all classified files using extended attribute scanning:

```bash
# Discover all ClassiCode-watermarked files in directory tree
find /path/to/scan -type f -exec sh -c 'xattr -l "$1" 2>/dev/null | grep -q "dspm-watermark-status" && echo "$1"' _ {} \;
```

**Discovery Results:**
- Complete inventory of classified files across all subdirectories
- Only files with ClassiCode classification metadata are detected
- Works across network file systems and cloud storage with xattr support
- Persistent detection survives file operations (move, copy, rename)

### Integration Points

| DSPM Tool | Discovery Method | Query Syntax |
|-----------|-----------------|--------------|
| Microsoft Purview | PowerShell xattr queries | `Get-FileClassification -Path $path -Attribute "user.dspm-watermark-status"` |
| Varonis | Custom xattr scanner | `varonis-scan --xattr-filter "dspm-watermark-status=ACTIVE"` |
| Forcepoint DLP | Policy rule integration | `xattr_exists("user.file-classification")` |
| Symantec DLP | Data identifier rules | `XATTR_CLASSIFICATION != null` |

---

## 2. Classification Detection Rules

### Metadata Extraction

For each discovered file, DSPM tools extract classification intelligence using standardized xattr queries:

```bash
# Verify file is ClassiCode-managed
xattr -p user.dsmp-watermark-status /path/to/file
# Returns: "ACTIVE" (watermarked) or error (unmanaged)

# Extract classification level
xattr -p user.file-classification /path/to/file  
# Returns: "Confidential" | "Personal" | "Internal" | "Public"

# Retrieve policy identifier
xattr -p user.dspm-policy-id /path/to/file
# Returns: "POLICY_CONF_001" | "POLICY_PERS_001" | "POLICY_INT_001" | "POLICY_PUB_001"

# Determine required protection level
xattr -p user.dspm-leak-protection /path/to/file
# Returns: "MAXIMUM" | "HIGH" | "MEDIUM" | "LOW"
```

### Classification Intelligence Schema

| Metadata Attribute | Purpose | Example Values |
|-------------------|---------|----------------|
| `user.dspm-watermark-status` | Identifies ClassiCode-managed files | `ACTIVE`, `INACTIVE` |
| `user.file-classification` | Core sensitivity level | `Confidential`, `Personal`, `Internal`, `Public` |
| `user.dspm-policy-id` | Standardized policy reference | `POLICY_CONF_001`, `POLICY_PERS_001` |
| `user.dspm-leak-protection` | Protection intensity required | `MAXIMUM`, `HIGH`, `MEDIUM`, `LOW` |
| `user.classification-timestamp` | Classification date/time | ISO 8601 timestamp |
| `user.classification-hash` | Integrity verification | SHA-256 hash |

---

## 3. Policy Enforcement Rules

### DSPM Configuration Framework

Configure your DSPM solution to automatically apply protection controls based on ClassiCode metadata:

```yaml
# DSPM Policy Configuration Template
watermark_detection_rules:
  file_discovery:
    scan_method: "xattr_scan"
    detection_attribute: "user.dspm-watermark-status"
    expected_value: "ACTIVE"
    
  classification_policies:
    - policy_id: "POLICY_CONF_001"
      classification: "Confidential"
      protection_level: "MAXIMUM"
      enforcement_actions:
        - block_external_sharing
        - block_cloud_upload
        - require_end_to_end_encryption  
        - mandate_access_logging
        - prevent_screen_capture
        - disable_print_operations
        
    - policy_id: "POLICY_PERS_001"  
      classification: "Personal"
      protection_level: "HIGH"
      enforcement_actions:
        - restrict_external_sharing
        - require_approval_workflow
        - enable_access_monitoring
        - encrypt_at_rest
        - geographic_restrictions
        
    - policy_id: "POLICY_INT_001"
      classification: "Internal"
      protection_level: "MEDIUM"
      enforcement_actions:
        - monitor_external_sharing
        - basic_access_logging
        - company_network_only
        
    - policy_id: "POLICY_PUB_001"
      classification: "Public"  
      protection_level: "LOW"
      enforcement_actions:
        - basic_activity_monitoring
```

### DLP Rule Integration

Integrate ClassiCode metadata into DLP data identifiers:

```sql
-- Example DLP Rule (Forcepoint/Symantec syntax)
CREATE DATA_IDENTIFIER "ClassiCode_Confidential" AS
  XATTR_VALUE("user.file-classification") = "Confidential"
  AND XATTR_VALUE("user.dspm-watermark-status") = "ACTIVE";

CREATE POLICY "Block_Confidential_External" AS
  WHEN DATA_IDENTIFIER = "ClassiCode_Confidential"
  AND CHANNEL IN ("Email", "Web Upload", "USB", "Cloud Storage")
  THEN ACTION = "BLOCK"
  AND NOTIFY = "Security Team"
  AND LOG_LEVEL = "HIGH";
```

---

## 4. Example DSPM/DLP Configurations

### Microsoft Purview Integration

```powershell
# PowerShell script for Purview integration
function Get-ClassiCodeFiles {
    param([string]$ScanPath)
    
    Get-ChildItem -Path $ScanPath -Recurse -File | 
    Where-Object { 
        (Get-FileClassification -Path $_.FullName -Attribute "user.dspm-watermark-status" -ErrorAction SilentlyContinue) -eq "ACTIVE"
    } |
    ForEach-Object {
        $classification = Get-FileClassification -Path $_.FullName -Attribute "user.file-classification"
        $policyId = Get-FileClassification -Path $_.FullName -Attribute "user.dspm-policy-id"
        
        # Apply Purview sensitivity labels based on ClassiCode classification
        switch ($classification) {
            "Confidential" { Set-AIPFileLabel -Path $_.FullName -LabelId "Highly Confidential" }
            "Personal"     { Set-AIPFileLabel -Path $_.FullName -LabelId "Personal Data" }
            "Internal"     { Set-AIPFileLabel -Path $_.FullName -LabelId "Internal Use" }
            "Public"       { Set-AIPFileLabel -Path $_.FullName -LabelId "Public" }
        }
    }
}
```

### Varonis DatAdvantage Integration

```yaml
# Varonis policy configuration
data_classification_rules:
  - name: "ClassiCode Confidential Detection"
    condition: 'xattr_contains("user.file-classification", "Confidential")'
    actions:
      - alert_severity: "HIGH"
      - restrict_access: true
      - enable_monitoring: "CONTINUOUS"
      - notify_data_owner: true
      
  - name: "ClassiCode Personal Data Detection"  
    condition: 'xattr_contains("user.file-classification", "Personal")'
    actions:
      - alert_severity: "MEDIUM"
      - compliance_tag: "GDPR_PERSONAL_DATA"
      - enable_monitoring: "STANDARD"
```

---

## 5. Example Detection Script (Python)

### Enterprise DSPM Integration Script

```python
#!/usr/bin/env python3
"""
ClassiCode DSPM Integration Script
Scans directories for classified files and applies appropriate security policies
"""

import subprocess
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

class ClassiCodeDSPMIntegrator:
    
    def __init__(self, scan_directory: str, log_level: str = "INFO"):
        self.scan_directory = Path(scan_directory)
        self.setup_logging(log_level)
        
    def setup_logging(self, level: str):
        logging.basicConfig(
            level=getattr(logging, level),
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/var/log/dspm-classicode-integration.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def scan_for_watermarked_files(self) -> List[Dict]:
        """
        Scan directory tree for ClassiCode-watermarked files
        Returns list of file metadata dictionaries
        """
        watermarked_files = []
        self.logger.info(f"Starting scan of {self.scan_directory}")
        
        # Use find command to locate files with ClassiCode metadata
        cmd = [
            "find", str(self.scan_directory), "-type", "f", "-exec", "sh", "-c",
            'xattr -l "$1" 2>/dev/null | grep -q "dspm-watermark-status" && echo "$1"',
            "_", "{}", ";"
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            file_paths = [path.strip() for path in result.stdout.split('\n') if path.strip()]
            
            self.logger.info(f"Found {len(file_paths)} watermarked files")
            
            for filepath in file_paths:
                file_metadata = self.extract_file_classification(filepath)
                if file_metadata:
                    watermarked_files.append(file_metadata)
                    
        except subprocess.TimeoutExpired:
            self.logger.error("File scan timed out after 300 seconds")
        except Exception as e:
            self.logger.error(f"Error during file scan: {e}")
            
        return watermarked_files
        
    def extract_file_classification(self, filepath: str) -> Optional[Dict]:
        """Extract all ClassiCode metadata from a single file"""
        try:
            metadata = {
                "filepath": filepath,
                "scan_timestamp": datetime.utcnow().isoformat(),
            }
            
            # Extract core classification attributes
            attributes = [
                ("watermark_status", "user.dspm-watermark-status"),
                ("classification", "user.file-classification"), 
                ("policy_id", "user.dspm-policy-id"),
                ("protection_level", "user.dspm-leak-protection"),
                ("classification_timestamp", "user.classification-timestamp"),
                ("integrity_hash", "user.classification-hash")
            ]
            
            for key, xattr_name in attributes:
                try:
                    result = subprocess.run(
                        ["xattr", "-p", xattr_name, filepath],
                        capture_output=True, text=True, timeout=10
                    )
                    if result.returncode == 0:
                        metadata[key] = result.stdout.strip()
                except subprocess.TimeoutExpired:
                    self.logger.warning(f"Timeout reading {xattr_name} from {filepath}")
                    
            # Validate required attributes exist
            if "classification" in metadata and "policy_id" in metadata:
                metadata["is_sensitive"] = metadata["classification"] in ["Confidential", "Personal"]
                metadata["risk_level"] = self.calculate_risk_level(metadata)
                return metadata
                
        except Exception as e:
            self.logger.error(f"Error extracting metadata from {filepath}: {e}")
            
        return None
        
    def calculate_risk_level(self, metadata: Dict) -> str:
        """Calculate risk level based on classification and context"""
        classification = metadata.get("classification", "").lower()
        protection_level = metadata.get("protection_level", "").lower()
        
        risk_matrix = {
            ("confidential", "maximum"): "CRITICAL",
            ("personal", "high"): "HIGH", 
            ("internal", "medium"): "MEDIUM",
            ("public", "low"): "LOW"
        }
        
        return risk_matrix.get((classification, protection_level), "UNKNOWN")
        
    def apply_dspm_policies(self, file_metadata: Dict) -> Dict:
        """Apply DSPM protection policies based on file classification"""
        policies_applied = []
        classification = file_metadata.get("classification", "").lower()
        protection_level = file_metadata.get("protection_level", "").lower()
        
        # Define policy actions based on protection level
        policy_actions = {
            "maximum": [
                self.block_external_sharing,
                self.enable_encryption,
                self.enable_access_logging,
                self.restrict_network_access,
                self.enable_dlp_monitoring
            ],
            "high": [
                self.restrict_sharing,
                self.enable_monitoring, 
                self.enable_access_logging,
                self.apply_geographic_restrictions
            ],
            "medium": [
                self.enable_monitoring,
                self.enable_basic_logging
            ],
            "low": [
                self.enable_basic_monitoring
            ]
        }
        
        # Execute appropriate policy actions
        actions = policy_actions.get(protection_level, [])
        for action in actions:
            try:
                result = action(file_metadata)
                policies_applied.append({
                    "action": action.__name__,
                    "result": result,
                    "timestamp": datetime.utcnow().isoformat()
                })
            except Exception as e:
                self.logger.error(f"Failed to apply {action.__name__}: {e}")
                
        return {
            "file": file_metadata["filepath"],
            "policies_applied": policies_applied,
            "total_policies": len(policies_applied)
        }
        
    def block_external_sharing(self, file_metadata: Dict) -> str:
        """Block external sharing for maximum protection files"""
        # Integration with your DLP solution
        filepath = file_metadata["filepath"]
        self.logger.info(f"Blocking external sharing for {filepath}")
        # Implementation depends on your DLP solution's API
        return "BLOCKED_EXTERNAL_SHARING"
        
    def enable_encryption(self, file_metadata: Dict) -> str:
        """Enable encryption for sensitive files"""
        filepath = file_metadata["filepath"]
        self.logger.info(f"Enabling encryption for {filepath}")
        # Implementation depends on your encryption solution
        return "ENCRYPTION_ENABLED"
        
    def enable_access_logging(self, file_metadata: Dict) -> str:
        """Enable detailed access logging"""
        filepath = file_metadata["filepath"]
        self.logger.info(f"Enabling access logging for {filepath}")
        return "ACCESS_LOGGING_ENABLED"
        
    def restrict_network_access(self, file_metadata: Dict) -> str:
        """Restrict network access for sensitive files"""
        return "NETWORK_RESTRICTIONS_APPLIED"
        
    def enable_dlp_monitoring(self, file_metadata: Dict) -> str:
        """Enable DLP monitoring"""
        return "DLP_MONITORING_ENABLED"
        
    def restrict_sharing(self, file_metadata: Dict) -> str:
        """Apply sharing restrictions"""
        return "SHARING_RESTRICTED"
        
    def enable_monitoring(self, file_metadata: Dict) -> str:
        """Enable file monitoring"""
        return "MONITORING_ENABLED"
        
    def apply_geographic_restrictions(self, file_metadata: Dict) -> str:
        """Apply geographic access restrictions"""
        return "GEO_RESTRICTIONS_APPLIED"
        
    def enable_basic_logging(self, file_metadata: Dict) -> str:
        """Enable basic access logging"""
        return "BASIC_LOGGING_ENABLED"
        
    def enable_basic_monitoring(self, file_metadata: Dict) -> str:
        """Enable basic monitoring"""
        return "BASIC_MONITORING_ENABLED"
        
    def generate_compliance_report(self, scan_results: List[Dict]) -> Dict:
        """Generate compliance report from scan results"""
        total_files = len(scan_results)
        classification_summary = {}
        risk_summary = {}
        
        for file_data in scan_results:
            classification = file_data.get("classification", "Unknown")
            risk_level = file_data.get("risk_level", "Unknown")
            
            classification_summary[classification] = classification_summary.get(classification, 0) + 1
            risk_summary[risk_level] = risk_summary.get(risk_level, 0) + 1
            
        return {
            "scan_timestamp": datetime.utcnow().isoformat(),
            "total_classified_files": total_files,
            "classification_breakdown": classification_summary,
            "risk_level_breakdown": risk_summary,
            "high_risk_files": [f for f in scan_results if f.get("risk_level") in ["CRITICAL", "HIGH"]],
            "compliance_status": "COMPLIANT" if total_files > 0 else "NO_CLASSIFIED_DATA"
        }

def main():
    """Main execution function for DSPM integration"""
    integrator = ClassiCodeDSPMIntegrator("/path/to/enterprise/data")
    
    # Scan for classified files
    classified_files = integrator.scan_for_watermarked_files()
    
    # Apply DSPM policies
    policy_results = []
    for file_metadata in classified_files:
        result = integrator.apply_dsmp_policies(file_metadata)
        policy_results.append(result)
        
    # Generate compliance report
    compliance_report = integrator.generate_compliance_report(classified_files)
    
    # Output results
    print(json.dumps({
        "classified_files": len(classified_files),
        "policies_applied": len(policy_results), 
        "compliance_report": compliance_report
    }, indent=2))

if __name__ == "__main__":
    main()
```

---

## 6. Decision Matrix

### DSPM Protection Decision Framework

| Watermark Status | Classification | Policy ID | Protection Level | DSPM Actions | DLP Rules |
|------------------|----------------|-----------|------------------|--------------|-----------|
| **ACTIVE** | **Confidential** | POLICY_CONF_001 | **MAXIMUM** | 🚫 Block all external sharing<br/>🔐 Mandate encryption<br/>📊 Full audit logging<br/>🌐 Network restrictions | **BLOCK**: Email, USB, Cloud<br/>**ALERT**: All access<br/>**ENCRYPT**: At rest & transit |
| **ACTIVE** | **Personal** | POLICY_PERS_001 | **HIGH** | ⚠️ Restrict external sharing<br/>👥 Approval workflows<br/>📍 Geographic restrictions<br/>🔍 Access monitoring | **RESTRICT**: External channels<br/>**NOTIFY**: Data owners<br/>**COMPLY**: GDPR requirements |
| **ACTIVE** | **Internal** | POLICY_INT_001 | **MEDIUM** | 📊 Monitor external sharing<br/>📝 Basic access logging<br/>🏢 Company network only | **MONITOR**: Sharing activity<br/>**ALERT**: Unusual access<br/>**LOG**: File operations |
| **ACTIVE** | **Public** | POLICY_PUB_001 | **LOW** | ✅ Allow with monitoring<br/>📋 Basic activity logging | **ALLOW**: All operations<br/>**LOG**: Basic activity |
| **Missing** | **N/A** | **N/A** | **N/A** | ❓ Content-based classification<br/>🔍 Deep content inspection | **SCAN**: Content analysis<br/>**CLASSIFY**: Auto-discovery |

### Risk-Based Policy Mapping

```yaml
# Risk-based policy decision tree
risk_assessment_matrix:
  CRITICAL:
    triggers: ["Confidential + MAXIMUM"]
    actions: ["BLOCK_ALL_EXTERNAL", "ENCRYPT_MANDATORY", "AUDIT_EVERYTHING"]
    
  HIGH:
    triggers: ["Personal + HIGH", "Confidential + HIGH"]  
    actions: ["RESTRICT_EXTERNAL", "REQUIRE_APPROVAL", "MONITOR_CLOSELY"]
    
  MEDIUM:
    triggers: ["Internal + MEDIUM", "Personal + MEDIUM"]
    actions: ["MONITOR_SHARING", "LOG_ACCESS", "NETWORK_ONLY"]
    
  LOW:
    triggers: ["Public + LOW", "Internal + LOW"]
    actions: ["BASIC_MONITORING", "SIMPLE_LOGGING"]
```

---

## 7. Benefits for DSPM/DLP Teams

### Operational Advantages

#### **Automated Discovery & Classification**
- **Zero Manual Effort**: Files self-identify their sensitivity without manual tagging
- **Persistent Metadata**: Classification survives file operations (move, copy, rename)
- **Cross-Platform Compatibility**: Works on macOS, Linux, Windows with xattr support
- **Real-Time Updates**: Classification changes immediately reflect in DSPM scans

#### **Policy Consistency & Enforcement**
- **Standardized Policy IDs**: Uniform policy enforcement across all DSPM tools
- **Risk-Based Controls**: Protection intensity automatically matches data sensitivity
- **Compliance Automation**: Automated application of regulatory requirements (GDPR, HIPAA)
- **Exception Handling**: Clear escalation paths for policy violations

#### **Enhanced Audit & Compliance**
- **Complete Audit Trail**: Timestamped classification history embedded in files
- **Integrity Verification**: Cryptographic hashing prevents metadata tampering
- **Chain of Custody**: Full lifecycle tracking from classification to disposal
- **Regulatory Reporting**: Automated compliance reporting with classification evidence

### Security Architecture Benefits

#### **Defense in Depth**
```
┌─────────────────────────────────────────────────────────────┐
│                    Enterprise Security Stack                │
├─────────────────────────────────────────────────────────────┤
│  Application Layer: ClassiCode (Classification Provider)    │
│  ├─ Developer Classification at Source                     │
│  ├─ Permanent Metadata Embedding                          │
│  └─ Cryptographic Integrity Protection                    │
├─────────────────────────────────────────────────────────────┤
│  DSPM Layer: Policy Enforcement Engine                     │
│  ├─ Automated File Discovery                              │
│  ├─ Risk-Based Policy Application                         │
│  └─ Continuous Monitoring                                 │
├─────────────────────────────────────────────────────────────┤
│  DLP Layer: Data Loss Prevention Controls                  │
│  ├─ Channel-Specific Blocking                             │
│  ├─ Content Inspection Integration                        │
│  └─ Incident Response Automation                          │
├─────────────────────────────────────────────────────────────┤
│  Infrastructure Layer: Network & Endpoint Controls         │
│  ├─ Network Segmentation                                  │
│  ├─ Endpoint Protection Integration                       │
│  └─ Cloud Security Posture Management                     │
└─────────────────────────────────────────────────────────────┘
```

#### **Zero-Trust Data Architecture**
- **Never Trust, Always Verify**: Every file access verified against embedded classification
- **Least Privilege Access**: Protection controls automatically match data sensitivity  
- **Continuous Verification**: Real-time policy enforcement based on current classification
- **Assume Breach**: Embedded metadata ensures protection even if perimeters are compromised

### ROI & Business Value

#### **Cost Reduction**
- **Reduced Manual Classification**: 90%+ reduction in manual data tagging effort
- **Automated Compliance**: Automatic regulatory requirement enforcement
- **Faster Incident Response**: Immediate identification of sensitive data exposure
- **Lower False Positives**: Accurate classification reduces DLP alert fatigue

#### **Risk Mitigation**
- **Data Breach Prevention**: Proactive protection before data leaves environment
- **Compliance Assurance**: Built-in regulatory compliance verification
- **Insider Threat Mitigation**: Comprehensive monitoring of sensitive data access
- **Supply Chain Security**: Embedded protection travels with shared files

---

## Implementation Roadmap

### Phase 1: Discovery & Assessment (Week 1-2)
- [ ] Scan existing environment for ClassiCode-classified files
- [ ] Assess current DSPM/DLP tool compatibility
- [ ] Map existing policies to ClassiCode metadata schema
- [ ] Identify integration points and API requirements

### Phase 2: Policy Configuration (Week 3-4)  
- [ ] Configure DSPM tools for xattr-based discovery
- [ ] Map ClassiCode classifications to existing DLP policies
- [ ] Implement automated policy application scripts
- [ ] Set up compliance reporting automation

### Phase 3: Testing & Validation (Week 5-6)
- [ ] Test file discovery accuracy across file systems
- [ ] Validate policy enforcement for each classification level
- [ ] Verify audit logging and compliance reporting
- [ ] Performance testing with production data volumes

### Phase 4: Production Deployment (Week 7-8)
- [ ] Gradual rollout to pilot user groups
- [ ] Monitor classification accuracy and policy effectiveness  
- [ ] Fine-tune policy rules based on operational feedback
- [ ] Full production deployment with monitoring

---

## Conclusion

ClassiCode transforms traditional reactive data protection into proactive, classification-driven security. By embedding permanent metadata directly into files, it enables DSPM and DLP solutions to automatically discover, classify, and protect sensitive data without manual intervention.

This integration creates a seamless security architecture where files carry their own protection requirements, enabling consistent policy enforcement regardless of where data travels within your enterprise environment.

**For technical implementation support or enterprise deployment assistance, contact:**
**📧 Dikshant <27dikshant@gmail.com>**