# AWS Compromise Assessment Plan
> **Classification:** Internal Security Documentation  
> **Last Updated:** March 2026  
> **Scope:** EC2, ECS, S3, Databases (RDS/Aurora), Networking (VPC/Route53/ELB), Storage (EBS/EFS/FSx)  
> **Goal:** Identify active or past threat actor activity using AWS-native and open-source tooling

---

## Table of Contents
1. [Assessment Overview](#1-assessment-overview)
2. [Phase 1 — Visibility & Log Collection](#2-phase-1--visibility--log-collection)
3. [Phase 2 — AWS-Native Threat Detection](#3-phase-2--aws-native-threat-detection)
4. [Phase 3 — Open-Source Tooling](#4-phase-3--open-source-tooling)
5. [Phase 4 — Service-Specific Threat Hunting](#5-phase-4--service-specific-threat-hunting)
6. [Phase 5 — IOC & Lateral Movement Analysis](#6-phase-5--ioc--lateral-movement-analysis)
7. [Phase 6 — Containment & Remediation](#7-phase-6--containment--remediation)
8. [Tooling Reference Matrix](#8-tooling-reference-matrix)
9. [MITRE ATT&CK Mapping](#9-mitre-attck-mapping)
10. [Reporting Template](#10-reporting-template)

---

## 1. Assessment Overview

### Objectives
- Determine if threat actors have **current or historical access** to the AWS environment
- Identify **compromised credentials, instances, containers, or data stores**
- Establish a **timeline of suspicious activity**
- Provide **remediation and hardening recommendations**

### Assessment Phases

| Phase | Focus Area | Duration |
|-------|-----------|----------|
| Phase 1 | Log visibility & telemetry gaps | Day 1 |
| Phase 2 | AWS-native detection activation | Day 1–2 |
| Phase 3 | Open-source tooling deployment | Day 2–3 |
| Phase 4 | Service-specific threat hunting | Day 3–5 |
| Phase 5 | IOC analysis & lateral movement | Day 5–7 |
| Phase 6 | Containment & remediation | Day 7+ |

---

## 2. Phase 1 — Visibility & Log Collection

> Ensure all telemetry sources are enabled before hunting. Gaps = blind spots.

### 2.1 Enable & Validate Log Sources

#### AWS CloudTrail
```bash
# Verify CloudTrail is enabled in all regions
aws cloudtrail describe-trails --include-shadow-trails

# Check if multi-region trail exists and logging is active
aws cloudtrail get-trail-status --name <trail-name>

# Enable S3 data events (critical for S3 compromise detection)
aws cloudtrail put-event-selectors --trail-name <trail-name> \
  --event-selectors '[{"ReadWriteType":"All","IncludeManagementEvents":true,"DataResources":[{"Type":"AWS::S3::Object","Values":["arn:aws:s3:::*/"]}]}]'
```

#### VPC Flow Logs
```bash
# List VPCs and check flow log status
aws ec2 describe-vpcs --query 'Vpcs[*].VpcId' --output text | \
  xargs -I{} aws ec2 describe-flow-logs --filter Name=resource-id,Values={}

# Enable VPC Flow Logs (if missing)
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids <vpc-id> \
  --traffic-type ALL \
  --log-destination-type cloud-watch-logs \
  --log-group-name /aws/vpc/flowlogs \
  --deliver-logs-permission-arn <iam-role-arn>
```

#### DNS Query Logs (Route 53 Resolver)
```bash
# Enable DNS query logging (critical for C2 detection)
aws route53resolver create-resolver-query-log-config \
  --name "dns-query-logs" \
  --destination-arn arn:aws:logs:<region>:<account>:log-group:/aws/dns/queries
```

#### ECS & EC2 Logging
```bash
# Ensure ECS task definitions have CloudWatch logging
aws ecs describe-task-definition --task-definition <task-def> \
  --query 'taskDefinition.containerDefinitions[*].logConfiguration'

# Check EC2 SSM Session Manager logging
aws ssm get-document --name "SSM-SessionManagerRunShell" --document-version '$LATEST'
```

#### RDS & Database Logs
```bash
# Enable RDS enhanced monitoring and audit logs
aws rds modify-db-instance \
  --db-instance-identifier <db-id> \
  --enable-cloudwatch-logs-exports '["audit","error","general","slowquery"]' \
  --apply-immediately
```

### 2.2 Log Retention Check
```bash
# Check CloudWatch Log Group retention policies
aws logs describe-log-groups --query 'logGroups[?retentionInDays==`null`].[logGroupName]'

# Set minimum 90-day retention for all security-relevant groups
aws logs put-retention-policy --log-group-name /aws/vpc/flowlogs --retention-in-days 90
```

---

## 3. Phase 2 — AWS-Native Threat Detection

### 3.1 Amazon GuardDuty

GuardDuty uses ML and threat intelligence to analyze CloudTrail, VPC Flow Logs, and DNS logs for malicious activity.

```bash
# Enable GuardDuty in ALL regions
aws guardduty list-detectors
aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES

# Enable ECS Runtime Monitoring (NEW - re:Invent 2025)
aws guardduty update-detector --detector-id <detector-id> \
  --features '[{"Name":"ECS_FARGATE_AGENT_MANAGEMENT","Status":"ENABLED"},{"Name":"RUNTIME_MONITORING","Status":"ENABLED"}]'

# Enable S3 Protection
aws guardduty update-detector --detector-id <detector-id> \
  --features '[{"Name":"S3_DATA_EVENTS","Status":"ENABLED"}]'

# Enable Malware Protection for EC2/EBS
aws guardduty update-detector --detector-id <detector-id> \
  --features '[{"Name":"EBS_MALWARE_PROTECTION","Status":"ENABLED"}]'

# Retrieve ALL current findings (paginated)
aws guardduty list-findings --detector-id <detector-id> \
  --finding-criteria '{"Criterion":{"severity":{"Gte":4}}}' --max-results 50

# Export findings for analysis
aws guardduty get-findings --detector-id <detector-id> \
  --finding-ids $(aws guardduty list-findings --detector-id <detector-id> --query 'FindingIds' --output text)
```

#### Key GuardDuty Finding Categories to Prioritize

| Finding Type | Indicates |
|---|---|
| `UnauthorizedAccess:EC2/SSHBruteForce` | Brute force against EC2 |
| `Backdoor:EC2/C&CActivity.B` | EC2 communicating with known C2 |
| `CryptoCurrency:EC2/BitcoinTool.B` | Cryptomining on EC2 |
| `Trojan:EC2/BlackholeTraffic` | Traffic to known sinkholed domains |
| `UnauthorizedAccess:IAMUser/TorIPCaller` | API calls from Tor exit nodes |
| `Recon:IAMUser/UserPermissions` | Enumeration of IAM permissions |
| `Exfiltration:S3/ObjectRead.Unusual` | Unusual S3 data read patterns |
| `PrivilegeEscalation:IAMUser/AdministrativePermissions` | Privilege escalation via IAM |
| `Impact:ECS/MaliciousFile` | Malware in ECS container (2025 feature) |

### 3.2 AWS Security Hub

```bash
# Enable Security Hub with all standards
aws securityhub enable-security-hub \
  --enable-default-standards \
  --control-finding-generator SECURITY_CONTROL

# Enable AWS Foundational Security Best Practices
aws securityhub batch-enable-standards \
  --standards-subscription-requests \
  '[{"StandardsArn":"arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-best-practices/v/1.0.0"}]'

# Get critical findings
aws securityhub get-findings \
  --filters '{"SeverityLabel":[{"Value":"CRITICAL","Comparison":"EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' \
  --query 'Findings[*].[Title,Description,Resources[0].Id]' --output table
```

### 3.3 AWS Config — Configuration Drift Detection
```bash
# Run conformance pack for security baseline
aws configservice put-conformance-pack \
  --conformance-pack-name "security-baseline" \
  --template-s3-uri s3://aws-configservice-us-east-1/aws-config-conformance-packs/Operational-Best-Practices-for-CIS-AWS-v1-4-Level2.yaml

# Check for non-compliant resources
aws configservice describe-compliance-by-config-rule \
  --compliance-types NON_COMPLIANT
```

### 3.4 AWS CloudTrail — Manual Threat Hunting Queries

Use AWS Athena to query CloudTrail logs stored in S3.

```sql
-- High-privilege API calls from unknown IPs
SELECT eventtime, useridentity.arn, eventname, sourceipaddress, useragent
FROM cloudtrail_logs
WHERE eventname IN ('CreateUser','AttachUserPolicy','CreateAccessKey','AssumeRole',
                    'PutBucketPolicy','DeleteBucketPolicy','StopLogging','DeleteTrail')
  AND from_iso8601_timestamp(eventtime) > current_timestamp - interval '30' day
ORDER BY eventtime DESC;

-- Root account usage (immediate escalation)
SELECT eventtime, eventname, sourceipaddress, useragent
FROM cloudtrail_logs
WHERE useridentity.type = 'Root'
  AND from_iso8601_timestamp(eventtime) > current_timestamp - interval '90' day;

-- Failed authentication attempts (brute force indicators)
SELECT sourceipaddress, count(*) as attempts, array_agg(DISTINCT useridentity.arn) as targets
FROM cloudtrail_logs
WHERE errorcode IN ('AccessDenied','UnauthorizedOperation','InvalidClientTokenId')
  AND from_iso8601_timestamp(eventtime) > current_timestamp - interval '7' day
GROUP BY sourceipaddress
HAVING count(*) > 20
ORDER BY attempts DESC;

-- Unusual IAM key creation or console logins
SELECT eventtime, useridentity.arn, sourceipaddress, useragent, awsregion
FROM cloudtrail_logs
WHERE eventname IN ('CreateAccessKey','ConsoleLogin','GetSessionToken')
  AND from_iso8601_timestamp(eventtime) > current_timestamp - interval '30' day
ORDER BY eventtime DESC;

-- S3 public bucket exposure changes
SELECT eventtime, useridentity.arn, requestparameters
FROM cloudtrail_logs
WHERE eventname IN ('PutBucketAcl','PutBucketPolicy','DeleteBucketPublicAccessBlock')
  AND from_iso8601_timestamp(eventtime) > current_timestamp - interval '30' day;
```

### 3.5 Amazon Detective
```bash
# Enable Amazon Detective for visual investigation
aws detective create-graph

# Detective automatically pulls GuardDuty + CloudTrail + VPC Flow Logs
# Use the console to pivot on: IP addresses, IAM principals, EC2 instances
```

### 3.6 AWS IAM Access Analyzer
```bash
# Enable IAM Access Analyzer in all regions
aws accessanalyzer create-analyzer --analyzer-name "compromise-assessment" --type ACCOUNT

# List findings (externally shared resources)
aws accessanalyzer list-findings --analyzer-name "compromise-assessment" \
  --filter '{"status":{"eq":["ACTIVE"]}}' \
  --query 'findings[*].[resource,condition,action]' --output table

# Check for unused access (service last access)
aws iam generate-service-last-accessed-details --arn <user-or-role-arn>
```

### 3.7 AWS Macie (S3 Data Exposure)
```bash
# Enable Macie and start a sensitive data discovery job
aws macie2 enable-macie

aws macie2 create-classification-job \
  --name "compromise-s3-scan" \
  --job-type ONE_TIME \
  --s3-job-definition '{"bucketDefinitions":[{"accountId":"<account-id>","buckets":["*"]}]}' \
  --sampling-percentage 100
```

---

## 4. Phase 3 — Open-Source Tooling

### 4.1 Prowler — AWS Security Posture Audit
```bash
# Install Prowler
pip install prowler

# Run full assessment against your AWS account
prowler aws --profile default --output-formats json html csv

# Run specific threat-detection checks
prowler aws --checks guardduty_is_enabled cloudtrail_multi_region_enabled \
  vpc_flow_logs_enabled s3_bucket_public_access_block_enabled \
  iam_root_access_key_exists iam_no_root_access_key

# Output to S3 for centralized storage
prowler aws -B <your-bucket-name> -D prowler-results/
```

### 4.2 Trivy — Container & EC2 Vulnerability Scanning
```bash
# Install Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

# Scan ECS container images from ECR
trivy image <account-id>.dkr.ecr.<region>.amazonaws.com/<repo>:<tag>

# Scan EC2 AMI (via filesystem mount)
trivy fs / --severity HIGH,CRITICAL --output trivy-ec2-report.json

# Scan Infrastructure as Code (CloudFormation/Terraform)
trivy config ./infrastructure/ --severity HIGH,CRITICAL

# Scan for secrets in code/configs
trivy fs . --security-checks secret --output secrets-report.json
```

### 4.3 Wazuh — SIEM & Endpoint Detection
```bash
# Deploy Wazuh agent on EC2 instances
curl -so wazuh-agent.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.7.0-1.x86_64.rpm
rpm -ihv wazuh-agent.rpm
WAZUH_MANAGER="<wazuh-server>" systemctl start wazuh-agent

# Wazuh detects:
# - Rootkit presence
# - File integrity violations
# - AWS API anomalies via CloudTrail integration
# - Known malware signatures
```

### 4.4 Falco — Runtime Container Threat Detection (ECS/K8s)
```bash
# Deploy Falco as ECS sidecar or EC2 daemon
docker run -d --name falco \
  --privileged \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v /dev:/host/dev \
  -v /proc:/host/proc:ro \
  falcosecurity/falco:latest

# Key Falco rules to enable:
# - Terminal shell in container
# - Unexpected outbound connection from container
# - Privilege escalation in container
# - Read sensitive files in container (e.g., /etc/shadow)
# - Cryptominer process detected
```

### 4.5 CloudMapper — Network Attack Surface Visualization
```bash
# Install CloudMapper
git clone https://github.com/duo-labs/cloudmapper.git
cd cloudmapper && pip install -r requirements.txt

# Collect AWS network data
python cloudmapper.py collect --account <account-name>

# Analyze for public-facing resources and network exposure
python cloudmapper.py report --account <account-name>
python cloudmapper.py webserver --account <account-name>
```

### 4.6 ScoutSuite — Multi-Service Security Auditor
```bash
# Install ScoutSuite
pip install scoutsuite

# Run full AWS audit
scout aws --profile default --report-dir scoutsuite-report/

# Generates HTML report with findings across:
# EC2, S3, IAM, RDS, ECS, Lambda, VPC, ELB, CloudTrail, Config
```

### 4.7 Steampipe — SQL-Based Cloud Query Engine
```bash
# Install Steampipe and AWS plugin
steampipe plugin install aws

# Query for public S3 buckets
steampipe query "select name, region from aws_s3_bucket where bucket_policy_is_public = true"

# Query for EC2 instances with public IPs
steampipe query "select instance_id, public_ip_address, state_name from aws_ec2_instance where public_ip_address is not null"

# Query for overly permissive security groups
steampipe query "
  select group_id, group_name, from_port, to_port, cidr_ipv4
  from aws_vpc_security_group_rule
  where cidr_ipv4 = '0.0.0.0/0' and type = 'ingress' and from_port != 443"
```

---

## 5. Phase 4 — Service-Specific Threat Hunting

### 5.1 EC2 Threat Hunting

```bash
# List all EC2 instances and check for unexpected public IPs
aws ec2 describe-instances \
  --query 'Reservations[*].Instances[*].[InstanceId,PublicIpAddress,State.Name,LaunchTime,Tags]' \
  --output table

# Check for instances NOT in your standard AMIs
aws ec2 describe-instances \
  --query 'Reservations[*].Instances[*].[InstanceId,ImageId,LaunchTime]' \
  --output table

# Check Security Groups with 0.0.0.0/0 inbound on dangerous ports
aws ec2 describe-security-groups \
  --filters Name=ip-permission.cidr,Values='0.0.0.0/0' \
  --query 'SecurityGroups[*].[GroupId,GroupName,IpPermissions]'

# Check for unusual scheduled tasks or cron jobs via SSM
aws ssm send-command \
  --document-name "AWS-RunShellScript" \
  --instance-ids <instance-id> \
  --parameters 'commands=["crontab -l; ls /etc/cron.*; systemctl list-units --type=service --state=running"]'

# Check for crypto miners or reverse shells
aws ssm send-command \
  --document-name "AWS-RunShellScript" \
  --instance-ids <instance-id> \
  --parameters 'commands=["netstat -tulpn; ps aux | grep -E "xmrig|minerd|kworker" ; ss -tp | grep ESTABLISHED"]'
```

### 5.2 ECS Threat Hunting

```bash
# List all running ECS tasks and check for unexpected containers
aws ecs list-clusters | xargs -I{} aws ecs list-tasks --cluster {}
aws ecs describe-tasks --cluster <cluster-name> --tasks <task-arns> \
  --query 'tasks[*].[taskArn,lastStatus,containers[*].name,startedAt]'

# Check ECS task definitions for dangerous environment variables (secrets in plaintext)
aws ecs describe-task-definition --task-definition <task-def> \
  --query 'taskDefinition.containerDefinitions[*].environment'

# Check for privileged containers
aws ecs describe-task-definition --task-definition <task-def> \
  --query 'taskDefinition.containerDefinitions[*].privileged'

# Check ECS task role permissions
aws ecs describe-task-definition --task-definition <task-def> \
  --query 'taskDefinition.taskRoleArn'
```

### 5.3 S3 Threat Hunting

```bash
# Find buckets with public access enabled
aws s3api list-buckets --query 'Buckets[*].Name' --output text | \
  xargs -I{} aws s3api get-public-access-block --bucket {}

# Check bucket policies for public access
aws s3api get-bucket-policy --bucket <bucket-name>

# Look for recent large data transfers (CloudTrail Athena query)
# Use the Athena query from Phase 2 targeting GetObject/PutObject events

# Check S3 replication rules (potential exfiltration path)
aws s3api get-bucket-replication --bucket <bucket-name>

# Find buckets with server-side encryption DISABLED
for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
  enc=$(aws s3api get-bucket-encryption --bucket $bucket 2>&1)
  if echo "$enc" | grep -q "ServerSideEncryptionConfigurationNotFoundError"; then
    echo "UNENCRYPTED: $bucket"
  fi
done
```

### 5.4 Database (RDS/Aurora) Threat Hunting

```bash
# Check for publicly accessible RDS instances
aws rds describe-db-instances \
  --query 'DBInstances[?PubliclyAccessible==`true`].[DBInstanceIdentifier,Engine,Endpoint.Address]'

# Check for RDS instances without encryption
aws rds describe-db-instances \
  --query 'DBInstances[?StorageEncrypted==`false`].[DBInstanceIdentifier,Engine]'

# Review RDS parameter groups for audit logging
aws rds describe-db-parameters --db-parameter-group-name <group-name> \
  --query 'Parameters[?ParameterName==`audit_log` || ParameterName==`general_log` || ParameterName==`log_output`]'

# Check for recent RDS snapshots (could indicate staging for exfiltration)
aws rds describe-db-snapshots \
  --query 'DBSnapshots[?SnapshotCreateTime>=`2026-01-01`].[DBSnapshotIdentifier,DBInstanceIdentifier,SnapshotCreateTime,SnapshotType]'

# Check RDS security groups
aws rds describe-db-instances \
  --query 'DBInstances[*].[DBInstanceIdentifier,VpcSecurityGroups[*].VpcSecurityGroupId]'
```

### 5.5 Network / VPC Threat Hunting

```bash
# Analyze VPC Flow Logs for unusual outbound traffic (Athena)
# Run in Athena after setting up VPC Flow Log table

# Query 1: Top talkers (potential exfiltration)
SELECT srcaddr, dstaddr, dstport, sum(bytes) as total_bytes
FROM vpc_flow_logs
WHERE action = 'ACCEPT' AND flow_direction = 'egress'
  AND from_unixtime(start) > current_timestamp - interval '7' day
GROUP BY srcaddr, dstaddr, dstport
ORDER BY total_bytes DESC LIMIT 50;

# Query 2: Connections to known threat intelligence IPs
SELECT srcaddr, dstaddr, dstport, packets, bytes, action
FROM vpc_flow_logs
WHERE dstaddr IN (<paste-threat-intel-IPs-here>)
  AND from_unixtime(start) > current_timestamp - interval '30' day;

# Query 3: Port scanning patterns (many ports, same source)
SELECT srcaddr, count(DISTINCT dstport) as ports_scanned
FROM vpc_flow_logs
WHERE action = 'REJECT'
  AND from_unixtime(start) > current_timestamp - interval '1' day
GROUP BY srcaddr
HAVING count(DISTINCT dstport) > 100;

# Check Internet Gateways and NAT Gateways for unexpected entries
aws ec2 describe-internet-gateways
aws ec2 describe-nat-gateways

# Check VPC peering for unauthorized connections
aws ec2 describe-vpc-peering-connections
```

### 5.6 Storage (EBS/EFS) Threat Hunting

```bash
# Check for unencrypted EBS volumes
aws ec2 describe-volumes \
  --query 'Volumes[?Encrypted==`false`].[VolumeId,Size,State,Attachments[0].InstanceId]'

# Check for EBS snapshots shared publicly
aws ec2 describe-snapshots --owner-ids self \
  --query 'Snapshots[*].[SnapshotId,Description,StartTime]' | \
  xargs -I{} aws ec2 describe-snapshot-attribute --snapshot-id {} --attribute createVolumePermission

# Check EFS mount targets and access points
aws efs describe-file-systems
aws efs describe-access-points
aws efs describe-mount-targets --file-system-id <fs-id>
```

---

## 6. Phase 5 — IOC & Lateral Movement Analysis

### 6.1 Credential Compromise Indicators

```bash
# Check for access keys created recently and used from unusual IPs
aws iam list-users --query 'Users[*].UserName' --output text | \
  xargs -I{} aws iam list-access-keys --user-name {}

# Check last used date and IP for each access key
aws iam get-access-key-last-used --access-key-id <key-id>

# Look for STS AssumeRole chains (lateral movement)
# Run Athena query:
SELECT eventtime, useridentity.sessioncontext.sessionissuer.arn as assumed_from,
       resources[1].arn as assumed_role, sourceipaddress
FROM cloudtrail_logs
WHERE eventname = 'AssumeRole'
  AND from_iso8601_timestamp(eventtime) > current_timestamp - interval '30' day
ORDER BY eventtime DESC;
```

### 6.2 Exfiltration Detection

```bash
# CloudTrail: Large S3 GetObject batches from unknown principals
SELECT useridentity.arn, sourceipaddress, count(*) as object_reads, 
       sum(cast(responseelements['contentLength'] as bigint)) as total_bytes
FROM cloudtrail_logs
WHERE eventname = 'GetObject'
  AND from_iso8601_timestamp(eventtime) > current_timestamp - interval '30' day
GROUP BY useridentity.arn, sourceipaddress
HAVING count(*) > 100
ORDER BY total_bytes DESC;

# Check for data transfer to unexpected AWS accounts via S3
SELECT requestparameters, useridentity.arn, sourceipaddress
FROM cloudtrail_logs
WHERE eventname IN ('PutBucketReplication','PutObject') 
  AND requestparameters LIKE '%arn:aws:iam::<external-account-id>%';
```

### 6.3 Persistence Mechanism Hunting

```bash
# Check for new IAM users, roles, policies created recently
aws iam list-users --query 'Users[?CreateDate>=`2026-01-01`]'
aws iam list-roles --query 'Roles[?CreateDate>=`2026-01-01`]'

# Look for Lambda backdoors
aws lambda list-functions --query 'Functions[*].[FunctionName,Runtime,LastModified,Role]'

# Check for unusual CloudWatch Events/EventBridge rules (persistence)
aws events list-rules --query 'Rules[*].[Name,ScheduleExpression,EventPattern,State]'

# Check for SSM Parameter Store secrets recently accessed
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=GetParameter \
  --max-results 50 --query 'Events[*].[EventTime,Username,CloudTrailEvent]'
```

---

## 7. Phase 6 — Containment & Remediation

### 7.1 Immediate Containment Actions

```bash
# ISOLATE compromised EC2 instance (move to quarantine security group)
aws ec2 create-security-group --group-name "QUARANTINE" --description "Isolated instance - incident response"
aws ec2 modify-instance-attribute --instance-id <instance-id> --groups <quarantine-sg-id>

# DISABLE compromised IAM access key
aws iam update-access-key --access-key-id <key-id> --status Inactive --user-name <user>

# REVOKE active sessions for compromised role
aws iam delete-role-policy --role-name <role-name> --policy-name <policy>
# Attach explicit deny policy to terminate all active sessions:
aws iam put-role-policy --role-name <role-name> --policy-name "INCIDENT-DENY-ALL" \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'

# BLOCK malicious IP at WAF level
aws wafv2 update-ip-set --name "blocked-ips" --scope REGIONAL \
  --id <ip-set-id> --addresses '["<malicious-ip>/32"]' --lock-token <token>

# SNAPSHOT compromised instance for forensics (before termination)
aws ec2 create-snapshot --volume-id <volume-id> --description "INCIDENT-FORENSICS-$(date +%Y%m%d)"
```

### 7.2 Credential Rotation

```bash
# Rotate all IAM access keys for affected users
aws iam create-access-key --user-name <user>
aws iam delete-access-key --access-key-id <old-key-id> --user-name <user>

# Update RDS master password
aws rds modify-db-instance --db-instance-identifier <db-id> \
  --master-user-password <new-password> --apply-immediately

# Rotate secrets in Secrets Manager
aws secretsmanager rotate-secret --secret-id <secret-id>
```

### 7.3 Post-Incident Hardening

- [ ] Enable AWS Organizations SCPs to restrict dangerous API calls organization-wide
- [ ] Enable MFA on all IAM users and root account
- [ ] Implement least-privilege IAM using Access Analyzer
- [ ] Enable S3 Block Public Access at account level
- [ ] Enable EBS default encryption
- [ ] Enable RDS encryption and automated backups
- [ ] Deploy AWS Config conformance packs (CIS Level 2)
- [ ] Set up GuardDuty threat intel feeds with custom IOC lists
- [ ] Integrate Security Hub findings into PagerDuty/Slack/JIRA
- [ ] Enable AWS Shield Advanced for public-facing resources
- [ ] Implement network segmentation via VPC security groups and NACLs

---

## 8. Tooling Reference Matrix

| Tool | Type | Coverage | Cost | Purpose |
|------|------|----------|------|---------|
| GuardDuty | AWS Native | EC2, ECS, S3, IAM, DNS | Paid (usage-based) | ML-based threat detection |
| Security Hub | AWS Native | All services | Paid | Findings aggregation & compliance |
| CloudTrail | AWS Native | All API calls | Paid (storage) | API audit trail |
| VPC Flow Logs | AWS Native | Network | Paid (storage) | Network traffic analysis |
| Config | AWS Native | Resource config | Paid | Drift & compliance detection |
| Detective | AWS Native | EC2, IAM, S3 | Paid | Visual investigation |
| Macie | AWS Native | S3 | Paid | Sensitive data discovery |
| IAM Access Analyzer | AWS Native | IAM, S3, KMS | Free | External access detection |
| Prowler | Open Source | All services | Free | Security posture audit |
| Trivy | Open Source | EC2, ECS, IaC | Free | Vulnerability & secret scanning |
| Wazuh | Open Source | EC2 endpoints | Free (self-hosted) | SIEM + EDR |
| Falco | Open Source | ECS/containers | Free | Runtime container detection |
| ScoutSuite | Open Source | All services | Free | Multi-service security audit |
| CloudMapper | Open Source | VPC/Network | Free | Network attack surface mapping |
| Steampipe | Open Source | All services | Free | SQL-based security queries |

---

## 9. MITRE ATT&CK Mapping

| Tactic | Technique | Detection Source |
|--------|-----------|-----------------|
| Initial Access | Valid Accounts (T1078) | CloudTrail, GuardDuty |
| Execution | Command and Scripting (T1059) | Falco, Wazuh, SSM logs |
| Persistence | Create Account (T1136) | CloudTrail, IAM Access Analyzer |
| Persistence | Scheduled Task/Cron (T1053) | Wazuh FIM, SSM |
| Privilege Escalation | Abuse Elevation Control (T1548) | GuardDuty, CloudTrail |
| Defense Evasion | Disable Cloud Logs (T1562) | CloudTrail (StopLogging event) |
| Credential Access | Unsecured Credentials (T1552) | Trivy secrets, Macie |
| Discovery | Cloud Infrastructure Discovery (T1580) | GuardDuty Recon findings |
| Lateral Movement | Use Alternate Auth Material (T1550) | CloudTrail AssumeRole chains |
| Collection | Data from Cloud Storage (T1530) | Macie, CloudTrail S3 events |
| Exfiltration | Transfer to Cloud Account (T1537) | VPC Flow Logs, CloudTrail |
| Impact | Data Encrypted for Impact (T1486) | GuardDuty, Wazuh |
| Impact | Resource Hijacking (T1496) | GuardDuty cryptocurrency findings |

---

## 10. Reporting Template

```markdown
## AWS Compromise Assessment Report
**Date:** YYYY-MM-DD  
**Assessed By:**  
**AWS Account ID(s):**  
**Scope:** EC2, ECS, S3, RDS, VPC, EBS/EFS

### Executive Summary
[2-3 sentence summary of findings and risk level: LOW / MEDIUM / HIGH / CRITICAL]

### Findings

#### Critical Findings
| # | Finding | Service | Evidence | Status |
|---|---------|---------|----------|--------|
| 1 | | | | Open/Remediated |

#### High Findings
| # | Finding | Service | Evidence | Status |
|---|---------|---------|----------|--------|

#### Medium/Low Findings
[Summary table]

### Timeline of Suspicious Activity
| Timestamp (UTC) | Event | Actor (IAM/IP) | Resource | Action Taken |
|----------------|-------|---------------|----------|-------------|

### Indicators of Compromise (IOCs)
- **IPs:** 
- **IAM ARNs:** 
- **Access Key IDs:** 
- **S3 Buckets Accessed:** 
- **Domains (C2/exfil):** 

### Remediation Status
- [ ] Credentials rotated
- [ ] Compromised instances isolated/terminated
- [ ] Malicious IPs blocked
- [ ] Logging gaps closed
- [ ] GuardDuty enabled all regions
- [ ] Security Hub conformance packs applied

### Recommendations
1. 
2. 
3. 
```

---

*This document is part of the Security Incident Response runbooks. Update after each assessment cycle.*
