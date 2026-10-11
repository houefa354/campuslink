-- ============================================================
-- CampusLink - MIGRATION d'une base existante (ancien schema.sql)
-- Ne supprime AUCUNE donnée : uniquement des ajouts de colonnes/tables.
-- À exécuter UNE SEULE FOIS :   mysql -u root -p campuslink < migration.sql
-- (Faites une sauvegarde avant : mysqldump -u root -p campuslink > backup.sql)
-- ============================================================
USE campuslink;

ALTER TABLE users
    ADD COLUMN email_verified_at DATETIME NULL AFTER is_active,
    ADD COLUMN session_version INT NOT NULL DEFAULT 1 AFTER email_verified_at,
    ADD COLUMN avatar_path VARCHAR(255) NULL AFTER session_version;

ALTER TABLE student_profiles
    ADD COLUMN first_name VARCHAR(80) NULL AFTER user_id,
    ADD COLUMN last_name VARCHAR(80) NULL AFTER first_name,
    ADD COLUMN bio TEXT NULL;

ALTER TABLE company_profiles
    ADD COLUMN official_name VARCHAR(150) NULL AFTER user_id,
    ADD COLUMN website_name VARCHAR(150) NULL,
    ADD COLUMN services TEXT NULL,
    ADD COLUMN verification_status ENUM('pending', 'verified', 'rejected') NOT NULL DEFAULT 'pending',
    ADD COLUMN verified_at DATETIME NULL,
    ADD INDEX idx_company_verif (verification_status);

ALTER TABLE posts
    ADD COLUMN image_path VARCHAR(255) NULL,
    ADD COLUMN updated_at DATETIME NULL;

-- Les comptes déjà existants n'ont jamais confirmé leur e-mail : ils restent NON vérifiés.
-- Ils pourront demander un nouveau lien depuis la page de connexion.
-- Pour un administrateur existant : php tools/create_admin.php --promote email@exemple.com

-- Profils manquants pour les anciens comptes
INSERT IGNORE INTO student_profiles (user_id) SELECT id FROM users WHERE role = 'student';
INSERT IGNORE INTO company_profiles (user_id, official_name) SELECT id, name FROM users WHERE role = 'company';

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
