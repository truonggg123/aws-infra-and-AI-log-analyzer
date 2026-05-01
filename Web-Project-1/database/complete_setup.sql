-- =============================================
-- COMPLETE DATABASE SETUP FOR QLSV SYSTEM
-- =============================================
-- DROP existing database and create fresh
DROP DATABASE IF EXISTS qlsv_system;
CREATE DATABASE qlsv_system CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE qlsv_system;

-- =============================================
-- TABLE: roles
-- =============================================
CREATE TABLE roles (
  role_id INT(11) NOT NULL AUTO_INCREMENT,
  role_code VARCHAR(50) NOT NULL UNIQUE,
  role_name VARCHAR(100) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (role_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO roles (role_id, role_code, role_name) VALUES
(1, 'ADMIN', 'Quản trị viên'),
(2, 'LECTURER', 'Giảng viên'),
(3, 'STUDENT', 'Sinh viên');

-- =============================================
-- TABLE: users
-- =============================================
CREATE TABLE users (
  user_id INT(11) NOT NULL AUTO_INCREMENT,
  username VARCHAR(50) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  full_name VARCHAR(200) DEFAULT NULL,
  email VARCHAR(100) DEFAULT NULL,
  phone VARCHAR(20) DEFAULT NULL,
  role_id INT(11) DEFAULT 3,
  is_active TINYINT(1) DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id),
  KEY idx_username (username),
  KEY idx_role (role_id),
  CONSTRAINT fk_users_role FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Default password for all accounts: 123@
-- Hash: SHA2(CONCAT('123@', username, '_salt'), 256)
INSERT INTO users (user_id, username, password, full_name, email, role_id, is_active) VALUES
-- Admin account (admin / 123@)
(1, 'admin', SHA2(CONCAT('123@', 'admin', '_salt'), 256), 'Quản trị viên', 'admin@qlsv.com', 1, 1),

-- Lecturer accounts (gv01, gv02, gv03 / 123@)
(2, 'gv01', SHA2(CONCAT('123@', 'gv01', '_salt'), 256), 'Nguyễn Văn An', 'nvana@qlsv.com', 2, 1),
(3, 'gv02', SHA2(CONCAT('123@', 'gv02', '_salt'), 256), 'Trần Thị Bình', 'ttbinh@qlsv.com', 2, 1),
(4, 'gv03', SHA2(CONCAT('123@', 'gv03', '_salt'), 256), 'Lê Văn Cường', 'lvcuong@qlsv.com', 2, 1),

-- Student accounts (sv01-sv10 / 123@)
(5, 'sv01', SHA2(CONCAT('123@', 'sv01', '_salt'), 256), 'Phạm Minh Đức', 'pmduc@qlsv.com', 3, 1),
(6, 'sv02', SHA2(CONCAT('123@', 'sv02', '_salt'), 256), 'Hoàng Thị Em', 'htem@qlsv.com', 3, 1),
(7, 'sv03', SHA2(CONCAT('123@', 'sv03', '_salt'), 256), 'Vũ Văn Phong', 'vvphong@qlsv.com', 3, 1),
(8, 'sv04', SHA2(CONCAT('123@', 'sv04', '_salt'), 256), 'Đỗ Thị Giang', 'dtgiang@qlsv.com', 3, 1),
(9, 'sv05', SHA2(CONCAT('123@', 'sv05', '_salt'), 256), 'Bùi Văn Hải', 'bvhai@qlsv.com', 3, 1),
(10, 'sv06', SHA2(CONCAT('123@', 'sv06', '_salt'), 256), 'Ngô Thị Lan', 'ntlan@qlsv.com', 3, 1),
(11, 'sv07', SHA2(CONCAT('123@', 'sv07', '_salt'), 256), 'Trịnh Văn Khoa', 'tvkhoa@qlsv.com', 3, 1),
(12, 'sv08', SHA2(CONCAT('123@', 'sv08', '_salt'), 256), 'Lý Thị Mai', 'ltmai@qlsv.com', 3, 1),
(13, 'sv09', SHA2(CONCAT('123@', 'sv09', '_salt'), 256), 'Đinh Văn Nam', 'dvnam@qlsv.com', 3, 1),
(14, 'sv10', SHA2(CONCAT('123@', 'sv10', '_salt'), 256), 'Phan Thị Oanh', 'ptoanh@qlsv.com', 3, 1);

-- =============================================
-- TABLE: classes
-- =============================================
CREATE TABLE classes (
  class_id INT(11) NOT NULL AUTO_INCREMENT,
  class_code VARCHAR(50) NOT NULL UNIQUE,
  class_name VARCHAR(200) NOT NULL,
  subject VARCHAR(200) DEFAULT NULL,
  lecturer_id INT(11) DEFAULT NULL,
  schedule VARCHAR(200) DEFAULT NULL,
  room VARCHAR(100) DEFAULT NULL,
  semester VARCHAR(100) DEFAULT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (class_id),
  KEY idx_lecturer (lecturer_id),
  KEY idx_class_code (class_code),
  CONSTRAINT fk_classes_lecturer FOREIGN KEY (lecturer_id) REFERENCES users(user_id) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO classes (class_id, class_code, class_name, subject, lecturer_id, schedule, room, semester) VALUES
(1, 'IT001', 'Lập trình căn bản', 'Lập trình C/C++', 2, 'Thứ 2, 7:00-9:30', 'A101', 'HK1 2024-2025'),
(2, 'IT002', 'Cấu trúc dữ liệu', 'Cấu trúc dữ liệu và giải thuật', 2, 'Thứ 4, 13:00-15:30', 'A102', 'HK1 2024-2025'),
(3, 'IT003', 'Cơ sở dữ liệu', 'MySQL & Database Design', 3, 'Thứ 3, 9:00-11:30', 'B201', 'HK1 2024-2025'),
(4, 'IT004', 'Lập trình Web', 'HTML, CSS, JavaScript, PHP', 3, 'Thứ 5, 13:00-15:30', 'B202', 'HK1 2024-2025'),
(5, 'IT005', 'Mạng máy tính', 'Networking Fundamentals', 4, 'Thứ 6, 7:00-9:30', 'C301', 'HK1 2024-2025');

-- =============================================
-- TABLE: lecturers (Mapping user_id → lecturer_id)
-- =============================================
CREATE TABLE lecturers (
  lecturer_id INT(11) NOT NULL AUTO_INCREMENT,
  lecturer_code VARCHAR(50) NOT NULL UNIQUE,
  user_id INT(11) NOT NULL,
  department VARCHAR(200) DEFAULT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (lecturer_id),
  UNIQUE KEY idx_user (user_id),
  CONSTRAINT fk_lecturers_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO lecturers (lecturer_id, lecturer_code, user_id, department) VALUES
(1, 'GV001', 2, 'Khoa CNTT'),
(2, 'GV002', 3, 'Khoa CNTT'),
(3, 'GV003', 4, 'Khoa CNTT');

-- =============================================
-- TABLE: students
-- =============================================
CREATE TABLE students (
  student_id INT(11) NOT NULL AUTO_INCREMENT,
  student_code VARCHAR(50) NOT NULL UNIQUE,
  user_id INT(11) NOT NULL,
  class_id INT(11) DEFAULT NULL,
  phone VARCHAR(20) DEFAULT NULL,
  status VARCHAR(50) DEFAULT 'Đang học',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (student_id),
  UNIQUE KEY idx_user (user_id),
  KEY idx_class (class_id),
  CONSTRAINT fk_students_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_students_class FOREIGN KEY (class_id) REFERENCES classes(class_id) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO students (student_id, student_code, user_id, class_id, phone, status) VALUES
(1, 'SV001', 5, 1, '0912345001', 'Đang học'),
(2, 'SV002', 6, 1, '0912345002', 'Đang học'),
(3, 'SV003', 7, 2, '0912345003', 'Đang học'),
(4, 'SV004', 8, 2, '0912345004', 'Đang học'),
(5, 'SV005', 9, 3, '0912345005', 'Đang học'),
(6, 'SV006', 10, 3, '0912345006', 'Đang học'),
(7, 'SV007', 11, 4, '0912345007', 'Đang học'),
(8, 'SV008', 12, 4, '0912345008', 'Đang học'),
(9, 'SV009', 13, 5, '0912345009', 'Đang học'),
(10, 'SV010', 14, 5, '0912345010', 'Đang học');

-- =============================================
-- TABLE: enrollments (Đăng ký môn học)
-- =============================================
CREATE TABLE enrollments (
  enrollment_id INT(11) NOT NULL AUTO_INCREMENT,
  student_id INT(11) NOT NULL,
  class_id INT(11) NOT NULL,
  enrollment_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  status VARCHAR(50) DEFAULT 'Đang học',
  PRIMARY KEY (enrollment_id),
  UNIQUE KEY idx_student_class (student_id, class_id),
  KEY idx_class_enrollment (class_id),
  CONSTRAINT fk_enrollments_student FOREIGN KEY (student_id) REFERENCES students(student_id) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_enrollments_class FOREIGN KEY (class_id) REFERENCES classes(class_id) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO enrollments (student_id, class_id, status) VALUES
-- Student 1 (SV001) enrolls in IT001 and IT003
(1, 1, 'Đang học'),
(1, 3, 'Đang học'),
-- Student 2 (SV002) enrolls in IT001 and IT004
(2, 1, 'Đang học'),
(2, 4, 'Đang học'),
-- Student 3 (SV003) enrolls in IT002 and IT003
(3, 2, 'Đang học'),
(3, 3, 'Đang học'),
-- Student 4 (SV004) enrolls in IT002 and IT005
(4, 2, 'Đang học'),
(4, 5, 'Đang học'),
-- Student 5 (SV005) enrolls in IT003 and IT004
(5, 3, 'Đang học'),
(5, 4, 'Đang học');

-- =============================================
-- TABLE: grades (Điểm số)
-- =============================================
CREATE TABLE grades (
  grade_id INT(11) NOT NULL AUTO_INCREMENT,
  student_id INT(11) NOT NULL,
  class_id INT(11) NOT NULL,
  score DECIMAL(5,2) DEFAULT NULL,
  notes TEXT DEFAULT NULL,
  graded_by INT(11) DEFAULT NULL COMMENT 'user_id của giảng viên chấm điểm',
  graded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (grade_id),
  UNIQUE KEY idx_student_class (student_id, class_id),
  KEY idx_class (class_id),
  KEY idx_graded_by (graded_by),
  CONSTRAINT fk_grades_student FOREIGN KEY (student_id) REFERENCES students(student_id) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_grades_class FOREIGN KEY (class_id) REFERENCES classes(class_id) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT fk_grades_lecturer FOREIGN KEY (graded_by) REFERENCES users(user_id) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Sample grades data
INSERT INTO grades (student_id, class_id, score, notes, graded_by) VALUES
-- Student 1 (SV001) in IT001 - lecturer gv01
(1, 1, 8.5, 'Làm bài tốt', 2),
-- Student 2 (SV002) in IT001 - lecturer gv01
(2, 1, 9.0, 'Xuất sắc', 2),
-- Student 3 (SV003) in IT002 - lecturer gv01
(3, 2, 7.5, NULL, 2),
-- Student 5 (SV005) in IT003 - lecturer gv02
(5, 3, 8.0, 'Khá tốt', 3);

-- =============================================
-- SUMMARY
-- =============================================
-- Tables created: roles, users, classes, lecturers, students, enrollments, grades
-- Default accounts:
--   Admin: admin / 123@
--   Lecturers: gv01, gv02, gv03 / 123@
--   Students: sv01-sv10 / 123@
-- Sample data:
--   3 lecturers
--   10 students
--   5 classes
--   5 enrollments
--   4 grade records
-- =============================================
