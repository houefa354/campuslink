-- ============================================================
-- CampusLink - schéma complet (nouvelle installation)
-- Pour mettre à jour une base EXISTANTE sans perdre de données,
-- utilisez migration.sql à la place.
-- ============================================================
CREATE DATABASE IF NOT EXISTS campuslink CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE campuslink;

-- Utilisateurs (étudiants, entreprises, modérateurs, admin)
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,                       -- nom affiché (prénom + nom, ou nom de l'entreprise)
    email VARCHAR(150) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,                   -- hachage password_hash()
    role ENUM('student', 'company', 'moderator', 'admin') NOT NULL DEFAULT 'student',
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    email_verified_at DATETIME NULL,                  -- renseigné uniquement après clic réel sur le lien reçu
    session_version INT NOT NULL DEFAULT 1,           -- incrémenté pour invalider toutes les sessions
    avatar_path VARCHAR(255) NULL,                    -- photo de profil / logo
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- Profil étudiant
CREATE TABLE IF NOT EXISTS student_profiles (
    user_id INT PRIMARY KEY,
    first_name VARCHAR(80) NULL,
    last_name VARCHAR(80) NULL,
    phone VARCHAR(20),
    school VARCHAR(150),                              -- université / établissement
    field_of_study VARCHAR(150),                      -- filière
    bio TEXT NULL,
    cv_path VARCHAR(255),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Profil entreprise
-- verification_status n'est modifiable QUE par le serveur (action admin).
CREATE TABLE IF NOT EXISTS company_profiles (
    user_id INT PRIMARY KEY,
    official_name VARCHAR(150) NULL,
    sector VARCHAR(150),
    website_name VARCHAR(150) NULL,
    website VARCHAR(200),
    address VARCHAR(255),
    description TEXT,                                 -- activités
    services TEXT NULL,
    verification_status ENUM('pending', 'verified', 'rejected') NOT NULL DEFAULT 'pending',
    verified_at DATETIME NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_company_verif (verification_status)
) ENGINE=InnoDB;

-- Dossiers de vérification d'entreprise (justificatifs stockés hors dossier public)
CREATE TABLE IF NOT EXISTS company_verifications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    company_id INT NOT NULL,
    legal_name VARCHAR(190) NOT NULL,
    registration_number VARCHAR(80) NOT NULL,         -- immatriculation / identifiant fiscal
    document_path VARCHAR(255) NOT NULL,              -- nom de fichier aléatoire dans storage/documents
    document_original_name VARCHAR(190) NULL,
    document_mime VARCHAR(80) NULL,
    extra_info TEXT NULL,
    status ENUM('pending', 'approved', 'rejected') NOT NULL DEFAULT 'pending',
    rejection_reason TEXT NULL,
    reviewed_by INT NULL,
    reviewed_at DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (company_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (reviewed_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_verif_status (status),
    INDEX idx_verif_company (company_id)
) ENGINE=InnoDB;

-- Jetons de vérification d'adresse e-mail (hachés, usage unique, durée limitée)
CREATE TABLE IF NOT EXISTS email_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token_hash CHAR(64) NOT NULL UNIQUE,              -- sha256 du jeton envoyé par e-mail
    purpose VARCHAR(30) NOT NULL DEFAULT 'verify_email',
    expires_at DATETIME NOT NULL,
    used_at DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_tokens_user (user_id)
) ENGINE=InnoDB;

-- Limitation de débit (tentatives de connexion, renvois d'e-mail, ...)
CREATE TABLE IF NOT EXISTS rate_limits (
    id INT AUTO_INCREMENT PRIMARY KEY,
    action VARCHAR(40) NOT NULL,
    rate_key VARCHAR(190) NOT NULL,                   -- ex. "email|ip"
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_rate (action, rate_key, created_at)
) ENGINE=InnoDB;

-- Fil d'actualité
CREATE TABLE IF NOT EXISTS posts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    content TEXT NOT NULL,
    image_path VARCHAR(255) NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_posts_created (created_at)
) ENGINE=InnoDB;

-- J'aime (un seul par utilisateur et par publication)
CREATE TABLE IF NOT EXISTS post_likes (
    post_id INT NOT NULL,
    user_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (post_id, user_id),
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Commentaires
CREATE TABLE IF NOT EXISTS post_comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    post_id INT NOT NULL,
    user_id INT NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_comments_post (post_id, created_at)
) ENGINE=InnoDB;

-- Invitations / relations.
-- Une seule ligne par paire d'utilisateurs (user_low < user_high) => pas de doublon.
-- Une relation confirmée = ligne au statut 'accepted'.
CREATE TABLE IF NOT EXISTS connections (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sender_id INT NOT NULL,
    receiver_id INT NOT NULL,
    user_low INT NOT NULL,
    user_high INT NOT NULL,
    status ENUM('pending', 'accepted', 'declined') NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    responded_at DATETIME NULL,
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY uq_pair (user_low, user_high),
    INDEX idx_conn_receiver (receiver_id, status),
    INDEX idx_conn_sender (sender_id, status),
    CONSTRAINT chk_not_self CHECK (sender_id <> receiver_id)
) ENGINE=InnoDB;

-- Notifications
CREATE TABLE IF NOT EXISTS notifications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,                             -- destinataire
    actor_id INT NULL,                                -- personne à l'origine
    type ENUM('invitation_received', 'invitation_accepted', 'post_liked', 'post_commented', 'verification_update') NOT NULL,
    ref_id INT NULL,                                  -- publication / invitation concernée
    message VARCHAR(255) NOT NULL,
    is_read TINYINT(1) NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_notif_user (user_id, is_read, created_at)
) ENGINE=InnoDB;

-- Offres de stages et d'emplois
CREATE TABLE IF NOT EXISTS job_offers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    company_id INT NOT NULL,
    title VARCHAR(150) NOT NULL,
    type ENUM('Stage', 'Emploi', 'Alternance') NOT NULL DEFAULT 'Stage',
    description TEXT NOT NULL,
    location VARCHAR(150),
    deadline DATE NULL,
    status ENUM('open', 'closed') NOT NULL DEFAULT 'open',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (company_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_offers_type_status (type, status),
    INDEX idx_offers_company (company_id)
) ENGINE=InnoDB;

-- Candidatures
CREATE TABLE IF NOT EXISTS applications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    job_id INT NOT NULL,
    student_id INT NOT NULL,
    cover_letter TEXT,
    cv_path VARCHAR(255),
    status ENUM('pending', 'accepted', 'rejected') NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (job_id) REFERENCES job_offers(id) ON DELETE CASCADE,
    FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY uq_application (job_id, student_id),
    INDEX idx_app_student (student_id)
) ENGINE=InnoDB;

-- Marketplace (création réservée à l'admin)
CREATE TABLE IF NOT EXISTS products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(150) NOT NULL,
    description TEXT NOT NULL,
    price DECIMAL(10, 2) NOT NULL,
    created_by INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;
