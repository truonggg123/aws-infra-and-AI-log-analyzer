# 🏗️ AWS Infrastructure & AI Log Analyzer

> **Hệ thống hạ tầng AWS 3-tier với AI-powered Security Log Analysis**

[![Terraform](https://img.shields.io/badge/Terraform-v1.0+-623CE4?logo=terraform&logoColor=white)](https://www.terraform.io/)
[![Ansible](https://img.shields.io/badge/Ansible-v2.9+-EE0000?logo=ansible&logoColor=white)](https://www.ansible.com/)
[![AWS](https://img.shields.io/badge/AWS-ap--southeast--1-FF9900?logo=amazonaws&logoColor=white)](https://aws.amazon.com/)
[![Bedrock](https://img.shields.io/badge/AWS_Bedrock-Claude_AI-4B0082)](https://aws.amazon.com/bedrock/)
[![Streamlit](https://img.shields.io/badge/Streamlit-v1.x-FF4B4B?logo=streamlit&logoColor=white)](https://streamlit.io/)

---

## 📋 Mục lục

- [Tổng quan](#-tổng-quan)
- [Kiến trúc hệ thống](#-kiến-trúc-hệ-thống)
- [Công nghệ sử dụng](#-công-nghệ-sử-dụng)
- [Cấu trúc project](#-cấu-trúc-project)
- [Ứng dụng](#-ứng-dụng)
- [Log Collection & Observability](#-log-collection--observability)
- [AI Log Analysis Pipeline](#-ai-log-analysis-pipeline)
- [Hướng dẫn Deploy](#-hướng-dẫn-deploy)
- [Truy cập ứng dụng](#-truy-cập-ứng-dụng)
- [Chi phí ước tính](#-chi-phí-ước-tính)
- [Bảo mật](#-bảo-mật)
- [Troubleshooting](#-troubleshooting)
- [Tài liệu tham khảo](#-tài-liệu-tham-khảo)

---

## 🎯 Tổng quan

Dự án triển khai một hệ thống hạ tầng **AWS 3-tier** hoàn chỉnh sử dụng **Infrastructure as Code (IaC)** với Terraform và Ansible, bao gồm:

1. **Web Tier (Public)** — Ứng dụng Quản Lý Sinh Viên (QLSV) bằng PHP + MySQL, truy cập qua Application Load Balancer
2. **App Tier (Private)** — AI Log Analyzer bằng Python + Streamlit + AWS Bedrock, truy cập nội bộ qua SSM Port Forwarding
3. **Database Tier** — RDS MySQL Multi-AZ với automated backups

Hệ thống tích hợp **AI-powered security log analysis** tự động phân tích 9 CloudWatch Log Groups mỗi 5 phút, phát hiện tấn công, phân tích nguyên nhân gốc rễ (Root Cause Analysis) và gửi cảnh báo qua Telegram.

---

## 🏗️ Kiến trúc hệ thống

```
                          Internet Users
                               │
                               ▼
                    ┌─────────────────────┐
                    │   Internet Gateway  │
                    └──────────┬──────────┘
                               │
                    ┌──────────┴──────────┐
                    │         ALB         │
                    │   (Internet-facing) │
                    └──────────┬──────────┘
                               │
        ┌──────────────────────┼──────────────────────┐
        │   AZ: ap-southeast-1a│   AZ: ap-southeast-1b│
        │                      │                       │
   ┌────┴─────────────────┐  ┌─┴───────────────────┐  │
   │  WEB TIER (Public)   │  │  WEB TIER (Public)  │  │
   │  EC2 - PHP + MySQL   │  │  EC2 - PHP + MySQL  │  │
   │  Auto Scaling Group  │  │  Auto Scaling Group  │  │
   └──────────────────────┘  └─────────────────────┘  │
                                                       │
   ┌──────────────────────┐  ┌─────────────────────┐  │
   │  APP TIER (Private)  │  │  APP TIER (Private) │  │
   │  EC2 - Streamlit     │  │  EC2 - Streamlit    │  │
   │  Auto Scaling Group  │  │  Auto Scaling Group  │  │
   └──────────────────────┘  └─────────────────────┘  │
                                                       │
   ┌──────────────────────┐  ┌─────────────────────┐  │
   │  DB TIER (Private)   │  │  DB TIER (Standby)  │  │
   │  RDS MySQL Primary   │◄─┤  RDS Read Replica   │  │
   └──────────────────────┘  └─────────────────────┘  │
        └──────────────────────────────────────────────┘

   ┌─────────────────────────────────────────────────────┐
   │              LOG COLLECTION & AI ANALYSIS            │
   │                                                      │
   │  VPC Flow Logs ──┐                                   │
   │  CloudTrail ─────┤                                   │
   │  Web Tier Logs ──┤──► CloudWatch ──► AI Analyzer     │
   │  App Tier Logs ──┤       Logs         (Bedrock)      │
   │  RDS Logs ───────┘                      │             │
   │                                         ▼             │
   │                                   Telegram Alerts     │
   └─────────────────────────────────────────────────────┘
```

### Đặc điểm kiến trúc

| Tiêu chí | Chi tiết |
|-----------|----------|
| **High Availability** | Deploy trên 2 Availability Zones, Auto Scaling Groups, RDS Multi-AZ |
| **Security** | Private subnets cho App & DB, không public IP, IAM roles, Security Groups & NACLs |
| **Access** | Web tier qua ALB, Streamlit UI qua SSM Port Forwarding (không public exposure) |
| **Observability** | 9 CloudWatch Log Groups, VPC Flow Logs, CloudTrail, AI-powered analysis |

---

## 🛠️ Công nghệ sử dụng

| Layer | Công nghệ |
|-------|-----------|
| **Infrastructure as Code** | Terraform v1.0+ |
| **Configuration Management** | Ansible v2.9+ |
| **Cloud Provider** | AWS (ap-southeast-1) |
| **Compute** | EC2 (t3.micro), Auto Scaling Groups |
| **Database** | RDS MySQL 8.0 |
| **Load Balancing** | Application Load Balancer |
| **Web Application** | PHP + Apache (Docker) |
| **AI Application** | Python + Streamlit (Docker) |
| **AI/ML** | AWS Bedrock (Claude 3 Haiku / Sonnet) |
| **Monitoring** | CloudWatch Logs, VPC Flow Logs, CloudTrail |
| **Alerting** | Telegram Bot API |
| **Container** | Docker + supervisord |
| **Access Management** | AWS SSM Session Manager |

---

## 📁 Cấu trúc project

```
terraform-for-project1/
│
├── 📂 environments/
│   └── dev/                      # Terraform cho môi trường dev
│       ├── main.tf               # VPC, Subnets, Gateways
│       ├── compute.tf            # EC2, Auto Scaling Groups
│       ├── database.tf           # RDS MySQL
│       ├── alb.tf                # Application Load Balancer
│       ├── security_groups.tf    # Security Groups
│       ├── iam.tf                # IAM Roles & Policies
│       ├── cloudwatch.tf         # CloudWatch Log Groups
│       ├── cloudtrail.tf         # CloudTrail
│       ├── variables.tf          # Input variables
│       ├── outputs.tf            # Output values
│       └── backend.tf            # S3 remote state
│
├── 📂 bootstrap/
│   └── main.tf                   # S3 bucket & DynamoDB for Terraform state
│
├── 📂 ansible/
│   ├── ansible.cfg               # Ansible configuration
│   ├── inventory/                # Dynamic inventory (aws_ec2)
│   ├── playbooks/                # Deployment playbooks
│   │   ├── site.yml              # Master playbook
│   │   ├── install_docker.yml
│   │   ├── install_cloudwatch_agent.yml
│   │   ├── deploy_web_app.yml
│   │   └── deploy_log_analyzer.yml
│   ├── roles/                    # Ansible roles
│   └── templates/                # Jinja2 templates
│
├── 📂 Web-Project-1/             # QLSV - Student Management System
│   ├── index.php                 # Entry point
│   ├── admin/                    # Admin panel
│   ├── lecturer/                 # Lecturer module
│   ├── student/                  # Student module
│   ├── api/                      # REST API
│   ├── database/                 # SQL schemas
│   └── Dockerfile
│
├── 📂 AI_Log_Analysis-Project-1/
│   └── bedrock-log-analyzer-ui/  # AI Log Analyzer Application
│       ├── streamlit_app.py      # Main Streamlit UI
│       ├── auto_analyzer.py      # Automated cron-based analyzer
│       ├── cloudwatch_client.py  # CloudWatch Logs client
│       ├── incident_store.py     # Persistent incident storage
│       ├── src/
│       │   ├── log_parser.py     # Log parsing engine
│       │   ├── pattern_analyzer.py
│       │   ├── rule_detector.py
│       │   ├── advanced_correlator.py  # Cross-source correlation
│       │   ├── bedrock_enhancer.py     # AWS Bedrock AI integration
│       │   └── telegram_notifier.py    # Telegram alerts
│       ├── correlation_rules.json
│       ├── Dockerfile
│       ├── supervisord.conf
│       └── crontab               # Automated analysis schedule
│
├── 📂 scripts/
│   ├── deploy_all.sh             # Full deployment script
│   ├── check_logs.sh             # Verify CloudWatch log groups
│   ├── fix_log_groups.sh         # Fix log group issues
│   ├── access_app.sh             # Access applications
│   └── database/
│       └── deploy_db.sh          # Database deployment
│
├── 📂 docs/
│   └── DEPLOYMENT_GUIDE.md       # Detailed deployment guide
│
├── AI_SYSTEM_EXPLAINED.md        # AI system architecture deep-dive
├── DEPLOYMENT_COMPLETE_GUIDE.md  # Complete deployment instructions
├── PROJECT_SUMMARY.md            # Project summary & status
├── review_report.md              # Architecture review report
└── README.md                     # ← Bạn đang đây
```

---

## 📦 Ứng dụng

### 1. 🎓 QLSV — Student Management System (Web Tier)

Hệ thống quản lý sinh viên với 3 roles: Admin, Giảng viên, Sinh viên.

| Feature | Mô tả |
|---------|--------|
| Quản lý sinh viên | CRUD sinh viên, lớp học |
| Quản lý giảng viên | Phân công môn học |
| Đăng ký môn học | Sinh viên đăng ký online |
| Quản lý điểm số | Nhập/xem điểm theo môn |
| Phân quyền | 3 roles với permissions khác nhau |

**Công nghệ:** PHP + Apache + MySQL (Docker container)
**Database:** 6 tables — roles, users, classes, students, enrollments, grades
**Tài khoản mặc định:** `admin` / `123@`

### 2. 🤖 AI Log Analyzer (App Tier)

Hệ thống phân tích log bảo mật thông minh sử dụng AWS Bedrock (Claude AI).

| Feature | Mô tả |
|---------|--------|
| Multi-source Analysis | Phân tích 9 CloudWatch Log Groups đồng thời |
| AI-powered RCA | Root Cause Analysis với phương pháp 5 Why |
| Cross-source Correlation | Tương quan events giữa VPC Flow, CloudTrail, Application logs |
| Attack Detection | Phát hiện DoS, SQL Injection, Brute Force, Port Scanning |
| MITRE ATT&CK Mapping | Phân loại theo framework MITRE ATT&CK |
| Telegram Alerts | Cảnh báo real-time khi phát hiện tấn công |
| Automated Analysis | Tự động phân tích mỗi 5 phút (cron + supervisord) |
| Interactive Dashboard | Streamlit UI với search, filter, drill-down |

**Công nghệ:** Python + Streamlit + AWS Bedrock + Docker + supervisord

---

## 📊 Log Collection & Observability

Hệ thống thu thập logs từ **9 CloudWatch Log Groups**:

| # | Log Group | Nguồn | Loại dữ liệu |
|---|-----------|-------|---------------|
| 1 | `/aws/vpc/flowlogs` | VPC | Network traffic (ACCEPT/REJECT) |
| 2 | `/aws/cloudtrail/logs` | CloudTrail | API activity |
| 3 | `/aws/ec2/web-tier/system` | Web EC2 | System logs (messages, secure) |
| 4 | `/aws/ec2/web-tier/httpd` | Web EC2 | Apache access & error logs |
| 5 | `/aws/ec2/web-tier/application` | Web EC2 | PHP application logs |
| 6 | `/aws/ec2/app-tier/system` | App EC2 | System logs |
| 7 | `/aws/ec2/app-tier/streamlit` | App EC2 | Streamlit application logs |
| 8 | `/aws/rds/mysql/error` | RDS | MySQL error logs |
| 9 | `/aws/rds/mysql/slowquery` | RDS | Slow query logs |

---

## 🧠 AI Log Analysis Pipeline

```
Raw Logs (9 sources)
     │
     ▼
┌─────────────────────┐
│  Layer 1: Parsing   │  Log Parser → Pattern Analyzer → Noise Reduction (99.5%)
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Layer 2: Correlate │  Cross-source Correlation → Timeline Builder → Rule Engine
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Layer 3: AI (RCA)  │  Context Builder → AWS Bedrock (Claude) → Global RCA
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│     Outputs         │  Incident Story │ Root Cause │ MITRE ATT&CK │ Telegram Alert
└─────────────────────┘
```

### AI Capabilities

- **Incident Story / Timeline** — Câu chuyện tấn công theo trình tự thời gian
- **Root Cause Analysis (5 Why)** — Phân tích nguyên nhân gốc rễ
- **Control Gap Identification** — Xác định lỗ hổng bảo mật
- **MITRE ATT&CK Mapping** — Phân loại tactics & techniques
- **Immediate Action Recommendations** — Đề xuất xử lý kèm AWS CLI commands
- **Severity & Confidence Scoring** — Đánh giá mức độ nghiêm trọng

> 📖 Xem chi tiết tại [AI_SYSTEM_EXPLAINED.md](AI_SYSTEM_EXPLAINED.md)

---

## 🚀 Hướng dẫn Deploy

### Yêu cầu

- AWS CLI v2.0+ (configured)
- Terraform v1.0+
- Ansible v2.9+
- Python 3.8+
- Session Manager Plugin (cho SSM)

### Quy trình deploy (~30-40 phút)

#### Bước 1: Bootstrap S3 Backend (~1 phút)
```bash
cd bootstrap/
terraform init
terraform apply -auto-approve
```

#### Bước 2: Deploy Infrastructure (~10-15 phút)
```bash
cd ../environments/dev/
terraform init
terraform plan -out=tfplan
terraform apply tfplan
```

#### Bước 3: Deploy Database (~2-3 phút)
```bash
cd ../../scripts/database/
chmod +x deploy_db.sh
./deploy_db.sh
```

#### Bước 4: Deploy Applications (~10-15 phút)
```bash
cd ../../ansible/
ansible-playbook -i inventory/aws_ec2.yml playbooks/site.yml
```

#### Bước 5: Verify (~2-3 phút)
```bash
cd ../scripts/
./check_logs.sh
./access_app.sh
```

> 📖 Hướng dẫn chi tiết: [DEPLOYMENT_COMPLETE_GUIDE.md](DEPLOYMENT_COMPLETE_GUIDE.md)

---

## 🌐 Truy cập ứng dụng

### Web QLSV (Public)

```bash
# Lấy ALB DNS
cd environments/dev/
terraform output alb_dns_name

# Truy cập
http://<ALB-DNS>/qlsv
```

| Role | Username | Password |
|------|----------|----------|
| Admin | `admin` | `123@` |
| Giảng viên | `gv01`, `gv02`, `gv03` | `123@` |
| Sinh viên | `sv01` → `sv10` | `123@` |

### AI Log Analyzer (Private — SSM Port Forwarding)

```bash
# Port forwarding qua SSM
aws ssm start-session \
    --target <instance-id> \
    --document-name AWS-StartPortForwardingSession \
    --parameters '{"portNumber":["8501"],"localPortNumber":["8501"]}'

# Truy cập
http://localhost:8501
```

---

## 💰 Chi phí ước tính (Monthly)

| Dịch vụ | Chi phí |
|---------|---------|
| EC2 (4 × t3.micro) | ~$30 |
| ALB | ~$20 |
| RDS (db.t3.micro) | ~$15 |
| EBS Storage (80GB) | ~$8 |
| NAT Gateway (optional) | ~$32 |
| CloudWatch Logs | ~$5 |
| VPC Flow Logs | ~$3 |
| Bedrock (Claude Haiku) | ~$5-10 |
| **Tổng (có NAT)** | **~$125/tháng** |
| **Tổng (không NAT)** | **~$93/tháng** |

---

## 🔐 Bảo mật

### Network Security
- ✅ Private subnets cho App & Database tier
- ✅ Security Groups với least privilege
- ✅ Không public IP trên app/db instances
- ✅ VPC Endpoints cho SSM, S3 (private access)

### Access Control
- ✅ IAM Roles cho EC2 (không access keys)
- ✅ SSM Session Manager (không SSH keys)
- ✅ RDS trong private subnet
- ✅ Secrets qua SSM Parameter Store

### Application Security
- ✅ Password hashing (SHA256)
- ✅ Prepared statements (chống SQL Injection)
- ✅ Session security
- ✅ Input validation

### Monitoring & Detection
- ✅ 9 CloudWatch Log Groups
- ✅ VPC Flow Logs
- ✅ CloudTrail (API audit)
- ✅ AI-powered threat detection (tự động mỗi 5 phút)
- ✅ Telegram alerts real-time

---

## 🔧 Troubleshooting

### Kiểm tra log groups
```bash
./scripts/check_logs.sh
```

### Kiểm tra infrastructure
```bash
cd environments/dev/
terraform show
terraform state list
```

### Kiểm tra ứng dụng
```bash
# Ansible inventory
cd ansible/
ansible-inventory -i inventory/aws_ec2.yml --list

# SSH vào instance qua SSM
aws ssm start-session --target <instance-id>

# Kiểm tra Docker containers
sudo docker ps
sudo docker logs <container-id>
```

### Kiểm tra CloudWatch Agent
```bash
sudo systemctl status amazon-cloudwatch-agent
sudo tail -f /opt/aws/amazon-cloudwatch-agent/logs/amazon-cloudwatch-agent.log
```

> 📖 Xem thêm tại phần Troubleshooting trong [DEPLOYMENT_COMPLETE_GUIDE.md](DEPLOYMENT_COMPLETE_GUIDE.md#-troubleshooting)

---

## 📚 Tài liệu tham khảo

| Tài liệu | Mô tả |
|-----------|--------|
| [DEPLOYMENT_COMPLETE_GUIDE.md](DEPLOYMENT_COMPLETE_GUIDE.md) | Hướng dẫn deploy chi tiết từng bước |
| [AI_SYSTEM_EXPLAINED.md](AI_SYSTEM_EXPLAINED.md) | Giải thích chi tiết hệ thống AI analysis |
| [PROJECT_SUMMARY.md](PROJECT_SUMMARY.md) | Tổng quan project & status |
| [review_report.md](review_report.md) | Báo cáo review kiến trúc DevSecOps |
| [docs/DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md) | Deployment guide bổ sung |
| [Web-Project-1/README.md](Web-Project-1/README.md) | Tài liệu ứng dụng QLSV |
| [AI_Log_Analysis-Project-1/bedrock-log-analyzer-ui/README.md](AI_Log_Analysis-Project-1/bedrock-log-analyzer-ui/README.md) | Tài liệu AI Log Analyzer |

---

## 🏆 Highlights

| Metric | Value |
|--------|-------|
| **Setup Time** | ~30-40 phút |
| **AWS Resources** | 50+ resources |
| **Lines of Code** | 5000+ (Terraform + Ansible + Apps) |
| **Log Sources** | 9 CloudWatch Log Groups |
| **AI Analysis Speed** | ~15-30 giây |
| **Availability** | 99.9% (Multi-AZ) |
| **Automated Analysis** | Mỗi 5 phút (cron) |

---

<p align="center">
  <b>Made with ❤️ using Terraform + Ansible + AWS Bedrock</b>
</p>
