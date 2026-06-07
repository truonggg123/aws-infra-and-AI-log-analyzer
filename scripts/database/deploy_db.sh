#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

export AWS_REGION="${AWS_REGION:-ap-southeast-1}"

echo "Database Deployment Script"
echo "=========================="
echo "Deploying schema from an EC2 web node inside the VPC..."
echo ""

cd "$REPO_ROOT/ansible"

ansible-inventory -i inventory/aws_ec2.yml --list > /dev/null
ansible role_web -i inventory/aws_ec2.yml -m ping
ansible-playbook -i inventory/aws_ec2.yml playbooks/deploy_database.yml

echo ""
echo "Database deployment complete."
