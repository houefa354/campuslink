<?php
/**
 * CampusLink - initialisation : configuration, PDO, session sécurisée, CSRF, helpers.
 */
declare(strict_types=1);

require_once __DIR__ . '/Mailer.php';

// ---------- Configuration (hors dossier public de préférence) ----------
function load_config(): array
{
    $candidates = array_filter([
        getenv('CAMPUSLINK_CONFIG') ?: null,
        dirname(__DIR__, 2) . '/campuslink_config.php',
        dirname(__DIR__) . '/config.php',
    ]);
    foreach ($candidates as $f) {
        if (is_file($f)) {
            $cfg = require $f;
            if (is_array($cfg)) return $cfg;
        }
    }
    // Valeurs de secours (développement local uniquement) + variables d'environnement
    return [
        'db' => [
            'host' => getenv('DB_HOST') ?: 'localhost',
            'port' => (int)(getenv('DB_PORT') ?: 3306),
            'name' => getenv('DB_NAME') ?: 'campuslink',
            'user' => getenv('DB_USER') ?: 'root',
            'pass' => getenv('DB_PASS') ?: '',
        ],
        'app_url' => getenv('APP_URL') ?: 'http://localhost:8000/',
        'storage_path' => getenv('STORAGE_PATH') ?: null,
        'cookie_secure' => null,
        'mail' => ['mode' => 'log', 'from_email' => 'no-reply@localhost', 'from_name' => 'CampusLink'],
    ];
}

$CONFIG = load_config();

function cfg(string $path, $default = null)
{
    global $CONFIG;
    $v = $CONFIG;
    foreach (explode('.', $path) as $k) {
        if (!is_array($v) || !array_key_exists($k, $v)) return $default;
        $v = $v[$k];
    }
    return $v;
}

function storage_dir(string $sub = ''): string
{
    $base = cfg('storage_path') ?: dirname(__DIR__) . '/../campuslink_storage';
    $root = rtrim($base, '/\\');
    if (!is_dir($root)) {
        @mkdir($root, 0750, true);
        // garde-fou si le dossier se retrouve (malgré nos conseils) dans un dossier public Apache
        @file_put_contents($root . '/.htaccess', "Require all denied\n");
    }
    $dir = $root . ($sub !== '' ? '/' . $sub : '');
    if (!is_dir($dir)) @mkdir($dir, 0750, true);
    return $dir;
}

// ---------- Réponses JSON ----------
function json_out(array $data, int $code = 200): never
{
    http_response_code($code);
    if (!headers_sent()) header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function fail(string $message, int $code = 400, array $extra = []): never
{
    json_out(['success' => false, 'message' => $message] + $extra, $code);
}

set_exception_handler(function (Throwable $e) {
    error_log('[CampusLink] ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine());
    if (!headers_sent()) header('Content-Type: application/json; charset=utf-8');
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Erreur interne du serveur.']);
});

// ---------- Base de données ----------
function db(): PDO
{
    static $pdo = null;
    if ($pdo) return $pdo;
    $d = cfg('db');
    try {
        $pdo = new PDO(
            "mysql:host={$d['host']};port=" . ($d['port'] ?? 3306) . ";dbname={$d['name']};charset=utf8mb4",
            $d['user'], $d['pass'],
            [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
            ]
        );
        // NOW() (MySQL) et date()/time() (PHP) doivent utiliser le même fuseau, sinon les expirations dérivent
        $pdo->exec("SET time_zone = '" . date('P') . "'");
    } catch (PDOException $e) {
        error_log('[CampusLink] DB: ' . $e->getMessage());
        fail('Connexion à la base de données impossible.', 500);
    }
    return $pdo;
}

// ---------- Session sécurisée ----------
function start_secure_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) return;
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
    $secure = cfg('cookie_secure');
    if ($secure === null) $secure = $https;
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    session_name('campuslink_sid');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => (bool)$secure,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_start();
    if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
}

function client_ip(): string
{
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

// ---------- CSRF + contrôle d'origine (appelé pour toute requête POST) ----------
function check_csrf(): void
{
    $origin = $_SERVER['HTTP_ORIGIN'] ?? null;
    if ($origin !== null && $origin !== 'null') {
        $oh = parse_url($origin, PHP_URL_HOST);
        $op = parse_url($origin, PHP_URL_PORT);
        $host = $_SERVER['HTTP_HOST'] ?? '';
        $originHost = $oh . ($op ? ':' . $op : '');
        if (!hash_equals(strtolower($host), strtolower($originHost))) {
            fail('Requête refusée (origine invalide).', 403);
        }
    }
    $sent = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (!is_string($sent) || $sent === '' || !hash_equals($_SESSION['csrf'] ?? '', $sent)) {
        fail('Session expirée ou requête invalide. Rechargez la page.', 403, ['code' => 'csrf']);
    }
}

// ---------- Utilisateur courant ----------
function current_user(): ?array
{
    static $cache = false;
    if ($cache !== false) return $cache;
    $uid = $_SESSION['uid'] ?? null;
    if (!$uid) return $cache = null;
    $st = db()->prepare('SELECT * FROM users WHERE id = ?');
    $st->execute([$uid]);
    $u = $st->fetch();
    if (!$u || !$u['is_active'] || (int)$u['session_version'] !== (int)($_SESSION['sv'] ?? 0) || !$u['email_verified_at']) {
        // Compte supprimé/désactivé, mot de passe changé ailleurs, ou e-mail non vérifié : session invalide
        unset($_SESSION['uid'], $_SESSION['sv']);
        return $cache = null;
    }
    return $cache = $u;
}

function require_login(): array
{
    $u = current_user();
    if (!$u) fail('Veuillez vous connecter.', 401, ['code' => 'auth']);
    return $u;
}

function require_role(array $user, array $roles): void
{
    if (!in_array($user['role'], $roles, true)) fail('Accès refusé.', 403);
}

// ---------- Limitation de débit ----------
function rate_count(string $action, string $key, int $windowSec): int
{
    $st = db()->prepare('SELECT COUNT(*) FROM rate_limits WHERE action = ? AND rate_key = ? AND created_at > (NOW() - INTERVAL ? SECOND)');
    $st->execute([$action, $key, $windowSec]);
    return (int)$st->fetchColumn();
}

function rate_hit(string $action, string $key): void
{
    db()->prepare('INSERT INTO rate_limits (action, rate_key) VALUES (?, ?)')->execute([$action, $key]);
    if (random_int(1, 50) === 1) {
        db()->exec('DELETE FROM rate_limits WHERE created_at < (NOW() - INTERVAL 2 DAY)');
    }
}

function rate_guard(string $action, string $key, int $max, int $windowSec, string $msg = 'Trop de tentatives. Réessayez plus tard.'): void
{
    if (rate_count($action, $key, $windowSec) >= $max) fail($msg, 429, ['code' => 'rate_limit']);
}

// ---------- Validation ----------
function password_policy_error(string $p): ?string
{
    if (strlen($p) < 8) return 'Le mot de passe doit contenir au moins 8 caractères.';
    if (strlen($p) > 200) return 'Mot de passe trop long.';
    if (!preg_match('/[a-z]/', $p) || !preg_match('/[A-Z]/', $p) || !preg_match('/\d/', $p)) {
        return 'Le mot de passe doit contenir une minuscule, une majuscule et un chiffre.';
    }
    return null;
}

function clean_text($v, int $max): string
{
    $v = trim((string)$v);
    $v = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F]/u', '', $v) ?? '';
    return mb_substr($v, 0, $max);
}

function valid_url_or_empty(string $url): bool
{
    if ($url === '') return true;
    if (!filter_var($url, FILTER_VALIDATE_URL)) return false;
    return in_array(strtolower((string)parse_url($url, PHP_URL_SCHEME)), ['http', 'https'], true);
}

// ---------- Fichiers téléversés ----------
/**
 * Vérifie le type RÉEL (finfo), la taille, et déplace le fichier sous un nom aléatoire dans storage/<sub>.
 * @return array [nomStocké, mime, nomOriginal]
 */
function store_upload(array $file, array $allowedMimes, int $maxBytes, string $sub): array
{
    if (($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
        $msg = in_array($file['error'] ?? 0, [UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE], true) ? 'Fichier trop volumineux.' : 'Échec du téléversement.';
        fail($msg, 422);
    }
    if (!is_uploaded_file($file['tmp_name'])) fail('Téléversement invalide.', 422);
    if ($file['size'] > $maxBytes) fail('Fichier trop volumineux (max ' . round($maxBytes / 1048576) . ' Mo).', 422);
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mime = $finfo->file($file['tmp_name']);
    if (!isset($allowedMimes[$mime])) fail('Format de fichier non autorisé.', 422);
    if (str_starts_with($mime, 'image/') && @getimagesize($file['tmp_name']) === false) fail('Image invalide.', 422);
    $name = bin2hex(random_bytes(16)) . '.' . $allowedMimes[$mime];
    $dest = storage_dir($sub) . '/' . $name;
    if (!move_uploaded_file($file['tmp_name'], $dest)) fail('Impossible d\'enregistrer le fichier.', 500);
    @chmod($dest, 0640);
    return [$name, $mime, mb_substr(basename((string)$file['name']), 0, 190)];
}

function delete_stored(string $sub, ?string $name): void
{
    if ($name && preg_match('/^[a-f0-9]{32}\.[a-z]{3,4}$/', $name)) {
        @unlink(storage_dir($sub) . '/' . $name);
    }
}

const IMAGE_MIMES = ['image/jpeg' => 'jpg', 'image/png' => 'png', 'image/webp' => 'webp'];
const DOC_MIMES   = ['application/pdf' => 'pdf', 'image/jpeg' => 'jpg', 'image/png' => 'png'];

// ---------- Notifications & e-mails ----------
function notify(int $userId, string $type, string $message, ?int $actorId = null, ?int $refId = null, bool $dedupe = false): void
{
    if ($dedupe) {
        $st = db()->prepare('SELECT 1 FROM notifications WHERE user_id = ? AND type = ? AND actor_id <=> ? AND ref_id <=> ? AND is_read = 0 LIMIT 1');
        $st->execute([$userId, $type, $actorId, $refId]);
        if ($st->fetch()) return;
    }
    db()->prepare('INSERT INTO notifications (user_id, actor_id, type, ref_id, message) VALUES (?, ?, ?, ?, ?)')
        ->execute([$userId, $actorId, $type, $refId, mb_substr($message, 0, 255)]);
}

function mailer(): Mailer
{
    return new Mailer(cfg('mail', []), storage_dir());
}

/** Crée un jeton à usage unique (24 h) et envoie le lien. Retourne true si l'e-mail a été remis au serveur SMTP / écrit en log. */
function send_verification_email(array $user): bool
{
    $pdo = db();
    $pdo->prepare('UPDATE email_tokens SET used_at = NOW() WHERE user_id = ? AND purpose = ? AND used_at IS NULL')->execute([$user['id'], 'verify_email']);
    $token = bin2hex(random_bytes(32));
    $pdo->prepare('INSERT INTO email_tokens (user_id, token_hash, purpose, expires_at) VALUES (?, ?, ?, NOW() + INTERVAL 24 HOUR)')
        ->execute([$user['id'], hash('sha256', $token), 'verify_email']);

    $link = rtrim((string)cfg('app_url', 'http://localhost:8000/'), '/') . '/index.html#/verify?token=' . $token;
    $name = htmlspecialchars($user['name'], ENT_QUOTES, 'UTF-8');
    $text = "Bonjour {$user['name']},\n\nPour activer votre compte CampusLink, confirmez votre adresse e-mail :\n$link\n\nCe lien est valable 24 heures et ne peut être utilisé qu'une fois.\nSi vous n'êtes pas à l'origine de cette inscription, ignorez ce message.";
    $html = "<div style=\"font-family:Arial,sans-serif;max-width:480px;margin:auto\"><h2 style=\"color:#4f46e5\">CampusLink</h2><p>Bonjour $name,</p><p>Pour activer votre compte, confirmez votre adresse e-mail :</p><p><a href=\"$link\" style=\"background:#4f46e5;color:#fff;padding:12px 20px;border-radius:10px;text-decoration:none;display:inline-block\">Confirmer mon adresse e-mail</a></p><p style=\"color:#666;font-size:13px\">Ce lien est valable 24 heures et ne peut être utilisé qu'une fois. Si vous n'êtes pas à l'origine de cette inscription, ignorez ce message.</p></div>";
    return mailer()->send($user['email'], 'Confirmez votre adresse e-mail - CampusLink', $text, $html);
}

// ---------- Représentation publique d'un utilisateur ----------
function user_public(array $u): array
{
    return [
        'id' => (int)$u['id'],
        'name' => $u['name'],
        'role' => $u['role'],
        'has_avatar' => !empty($u['avatar_path']),
    ];
}
