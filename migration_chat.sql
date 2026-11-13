-- ============================================================
-- CampusLink - Migration Messagerie et Interactions Commentaires
-- Idempotent, additif et sans perte de données.
-- ============================================================
USE campuslink;

-- 1. Conversations privées 1-à-1 (une seule ligne par paire user_low < user_high)
CREATE TABLE IF NOT EXISTS conversations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_low INT NOT NULL,
    user_high INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_low) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (user_high) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY uq_conv_pair (user_low, user_high),
    INDEX idx_conv_user_low (user_low),
    INDEX idx_conv_user_high (user_high),
    INDEX idx_conv_updated (updated_at)
) ENGINE=InnoDB;

-- 2. Messages des conversations
CREATE TABLE IF NOT EXISTS messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    conversation_id INT NOT NULL,
    sender_id INT NOT NULL,
    content TEXT NOT NULL,
    is_deleted TINYINT(1) NOT NULL DEFAULT 0,
    read_at DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_messages_conv (conversation_id, id),
    INDEX idx_messages_sender (sender_id),
    INDEX idx_messages_read (conversation_id, read_at)
) ENGINE=InnoDB;

-- 3. Réactions aux commentaires (J'aime, J'adore, Bravo, Intéressant)
CREATE TABLE IF NOT EXISTS comment_reactions (
    comment_id INT NOT NULL,
    user_id INT NOT NULL,
    type ENUM('like', 'love', 'bravo', 'insightful') NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (comment_id, user_id),
    FOREIGN KEY (comment_id) REFERENCES post_comments(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_reactions_type (comment_id, type)
) ENGINE=InnoDB;

-- 4. Réponses aux commentaires : parent_id sur post_comments
ALTER TABLE post_comments
    ADD COLUMN IF NOT EXISTS parent_id INT NULL DEFAULT NULL AFTER user_id;

-- Clé étrangère fk_comment_parent si non existante
SET @fk_exists = (
    SELECT COUNT(*) FROM information_schema.table_constraints
    WHERE table_schema = DATABASE()
      AND table_name = 'post_comments'
      AND constraint_name = 'fk_comment_parent'
);
SET @sql_fk = IF(@fk_exists = 0,
    'ALTER TABLE post_comments ADD CONSTRAINT fk_comment_parent FOREIGN KEY (parent_id) REFERENCES post_comments(id) ON DELETE CASCADE',
    'SELECT 1'
);
PREPARE stmt_fk FROM @sql_fk;
EXECUTE stmt_fk;
DEALLOCATE PREPARE stmt_fk;

-- Index sur parent_id si non existant
SET @idx_exists = (
    SELECT COUNT(*) FROM information_schema.statistics
    WHERE table_schema = DATABASE()
      AND table_name = 'post_comments'
      AND index_name = 'idx_comments_parent'
);
SET @sql_idx = IF(@idx_exists = 0,
    'ALTER TABLE post_comments ADD INDEX idx_comments_parent (parent_id)',
    'SELECT 1'
);
PREPARE stmt_idx FROM @sql_idx;
EXECUTE stmt_idx;
DEALLOCATE PREPARE stmt_idx;

-- 5. Extension de l'ENUM notifications.type avec les 3 nouveaux types
ALTER TABLE notifications
    MODIFY COLUMN type ENUM(
        'invitation_received',
        'invitation_accepted',
        'post_liked',
        'post_commented',
        'verification_update',
        'message_received',
        'comment_replied',
        'comment_reacted'
    ) NOT NULL;
