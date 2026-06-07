#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TERRAFORM_DIR="$REPO_ROOT/environments/dev"
SCHEMA_FILE="$REPO_ROOT/Web-Project-1/database/complete_setup.sql"

echo "🗄️ Database Deployment Script"
echo "================================"

if ! command -v mysql &> /dev/null; then
    echo "mysql client not found. Install it first, e.g. sudo apt-get install -y mysql-client"
    exit 1
fi
# Load DB credentials from Terraform outputs
DB_HOST=$(cd "$TERRAFORM_DIR" && terraform output -raw db_endpoint)
DB_USER="admin"
DB_PASS=$(cd "$TERRAFORM_DIR" && terraform output -raw db_password)
DB_NAME="qlsv_system"

echo "📍 DB Host: $DB_HOST"
echo "👤 DB User: $DB_USER"
echo "🗄️ DB Name: $DB_NAME"

# Kiểm tra kết nối
echo ""
echo "🔍 Testing database connection..."
mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASS" -e "SELECT VERSION();" || {
    echo "❌ Cannot connect to database"
    exit 1
}

echo "✅ Connection successful!"

# Deploy schema
echo ""
echo "📦 Deploying database schema..."
mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASS" < "$SCHEMA_FILE"

echo ""
echo "✅ Database deployment complete!"
echo ""
echo "📊 Database Summary:"
mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASS" -e "
USE qlsv_system;
SELECT 'Users' as Table_Name, COUNT(*) as Count FROM users
UNION ALL
SELECT 'Students', COUNT(*) FROM students
UNION ALL
SELECT 'Classes', COUNT(*) FROM classes
UNION ALL
SELECT 'Enrollments', COUNT(*) FROM enrollments
UNION ALL
SELECT 'Grades', COUNT(*) FROM grades;
"

echo ""
echo "🔐 Default Accounts:"
echo "  Admin: admin / 123@"
echo "  Lecturers: gv01, gv02, gv03 / 123@"
echo "  Students: sv01-sv10 / 123@"
