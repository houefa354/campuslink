<?php
/**
 * CampusLink - API (point d'entrée unique : api.php?action=...)
 * Toutes les autorisations sont vérifiées ICI, côté serveur : l'identité vient de la session PHP,
 * jamais du navigateur (plus de user_id / user_role envoyés par le client).
 */
declare(strict_types=1);

require_once __DIR__ . '/includes/bootstrap.php';

header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');
header('Cache-Control: no-store');

start_secure_session();

$action = (string)($_GET['action'] ?? '');
$method = $_SERVER['REQUEST_METHOD'];

$input = [];
if (stripos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') !== false) {
    $raw = json_decode((string)file_get_contents('php://input'), true);
    $input = is_array($raw) ? $raw : [];
} else {
    $input = $_POST;
}

const DUMMY_HASH = '$2y$10$hV9vufd3mvw1zPmfPX6.C.YxMBw5Vb5FrXjHHoct96SQwhiyOcDkq';

$GET_ACTIONS = [
    'me', 'file', 'posts', 'comments', 'profile', 'people', 'connections', 'notifications',
    'jobs', 'products', 'stats', 'admin_verifications', 'admin_companies',
];
$POST_ACTIONS = [
    'register', 'login', 'logout', 'verify_email', 'verify_code', 'resend_verification',
    'update_profile', 'avatar_set', 'avatar_delete', 'change_password', 'submit_verification',
    'post_create', 'post_update', 'post_delete', 'like_set', 'comment_add', 'comment_delete',
    'invite_send', 'invite_respond', 'invite_cancel', 'connection_remove',
    'notif_read', 'notif_read_all', 'job_create', 'job_apply', 'product_create', 'admin_review',
];

if (in_array($action, $GET_ACTIONS, true)) {
    if ($method !== 'GET') fail('Méthode non autorisée.', 405);
} elseif (in_array($action, $POST_ACTIONS, true)) {
    if ($method !== 'POST') fail('Méthode non autorisée.', 405);
    check_csrf();
} else {
    fail('Action inconnue.', 404);
}

$fn = 'act_' . $action;
$fn($input);
exit;

// =====================================================================
//  Utilitaires propres à l'API
// =====================================================================

function me_payload(?array $u): ?array
{
    if (!$u) return null;
    $verification = null;
    if ($u['role'] === 'company') {
        $st = db()->prepare('SELECT verification_status FROM company_profiles WHERE user_id = ?');
        $st->execute([$u['id']]);
        $verification = $st->fetchColumn() ?: 'pending';
    }
    return [
        'id' => (int)$u['id'], 'name' => $u['name'], 'email' => $u['email'], 'role' => $u['role'],
        'has_avatar' => !empty($u['avatar_path']), 'verification_status' => $verification,
    ];
}

function unread_count(int $uid): int
{
    $st = db()->prepare('SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0');
    $st->execute([$uid]);
    return (int)$st->fetchColumn();
}

function pair(int $a, int $b): array
{
    return [min($a, $b), max($a, $b)];
}

/** État de la relation entre $me et $other : none | sent | received | connected | declined */
function connection_state(int $me, int $other): array
{
    [$lo, $hi] = pair($me, $other);
    $st = db()->prepare('SELECT * FROM connections WHERE user_low = ? AND user_high = ?');
    $st->execute([$lo, $hi]);
    $c = $st->fetch();
    if (!$c) return ['state' => 'none', 'id' => null];
    if ($c['status'] === 'accepted') return ['state' => 'connected', 'id' => (int)$c['id']];
    if ($c['status'] === 'pending') {
        return ['state' => ((int)$c['sender_id'] === $me ? 'sent' : 'received'), 'id' => (int)$c['id']];
    }
    // refusée : celui qui a envoyé voit "declined", celui qui a refusé peut ré-inviter
    return ['state' => ((int)$c['sender_id'] === $me ? 'declined' : 'none'), 'id' => (int)$c['id']];
}

function is_verified_company(int $uid): bool
{
    $st = db()->prepare("SELECT 1 FROM company_profiles WHERE user_id = ? AND verification_status = 'verified'");
    $st->execute([$uid]);
    return (bool)$st->fetchColumn();
}

// =====================================================================
//  Authentification
// =====================================================================

function act_me(array $in): void
{
    $u = current_user();
    json_out([
        'success' => true,
        'csrf' => $_SESSION['csrf'],
        'user' => me_payload($u),
        'unread' => $u ? unread_count((int)$u['id']) : 0,
        'mail_mode' => cfg('mail.mode', 'log'),
    ]);
}

function act_register(array $in): void
{
    $ip = client_ip();
    rate_guard('register_ip', $ip, 10, 3600, 'Trop d\'inscriptions depuis cette adresse. Réessayez plus tard.');

    $role = (string)($in['role'] ?? '');
    if (!in_array($role, ['student', 'company'], true)) fail('Choisissez un type de compte (étudiant ou entreprise).', 422);

    $email = strtolower(trim((string)($in['email'] ?? '')));
    $pass = (string)($in['password'] ?? '');
    $confirm = (string)($in['password_confirm'] ?? '');

    $first = $last = $companyName = '';
    if ($role === 'student') {
        $first = clean_text($in['first_name'] ?? '', 80);
        $last = clean_text($in['last_name'] ?? '', 80);
        if ($first === '' || $last === '') fail('Le prénom et le nom sont obligatoires.', 422);
        $displayName = "$first $last";
    } else {
        $companyName = clean_text($in['company_name'] ?? '', 100);
        if ($companyName === '') fail('Le nom de l\'entreprise est obligatoire.', 422);
        $displayName = $companyName;
    }

    if ($email === '' || strlen($email) > 150 || !filter_var($email, FILTER_VALIDATE_EMAIL)) fail('Adresse e-mail invalide.', 422);
    if ($err = password_policy_error($pass)) fail($err, 422);
    if (!hash_equals($pass, $confirm)) fail('Les deux mots de passe ne sont pas identiques.', 422);

    $pdo = db();
    $st = $pdo->prepare('SELECT id FROM users WHERE email = ?');
    $st->execute([$email]);
    if ($st->fetch()) fail('Cette adresse e-mail est déjà utilisée.', 409);

    rate_hit('register_ip', $ip);
    $pdo->beginTransaction();
    try {
        $pdo->prepare('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)')
            ->execute([$displayName, $email, password_hash($pass, PASSWORD_DEFAULT), $role]);
        $id = (int)$pdo->lastInsertId();
        if ($role === 'student') {
            $pdo->prepare('INSERT INTO student_profiles (user_id, first_name, last_name) VALUES (?, ?, ?)')->execute([$id, $first, $last]);
        } else {
            // statut "En attente de vérification" par défaut (colonne gérée par le serveur uniquement)
            $pdo->prepare("INSERT INTO company_profiles (user_id, official_name, verification_status) VALUES (?, ?, 'pending')")->execute([$id, $companyName]);
        }
        $pdo->commit();
    } catch (PDOException $e) {
        $pdo->rollBack();
        if ($e->getCode() === '23000') fail('Cette adresse e-mail est déjà utilisée.', 409);
        throw $e;
    }

    $sent = send_verification_email(['id' => $id, 'name' => $displayName, 'email' => $email]);
    $real = mailer()->isReal();
        if ($sent && $real) {
            $msg = 'Compte créé. Un code de confirmation à 6 chiffres vient d\'être envoyé à votre adresse e-mail.';
        } elseif ($sent) {
            $msg = 'Compte créé. MODE DÉVELOPPEMENT : aucun e-mail réel n\'a été envoyé ; le code est dans le fichier mails.log du dossier de stockage.';
        } else {
            $msg = 'Compte créé, mais le code n\'a pas pu être envoyé. Utilisez « Renvoyer le code ».';
        }
    json_out(['success' => true, 'message' => $msg, 'mail_sent' => $sent && $real, 'email' => $email], 201);
}

function act_verify_email(array $in): void
{
    $token = (string)($in['token'] ?? '');
    if (!preg_match('/^[a-f0-9]{64}$/', $token)) fail('Lien de vérification invalide.', 422);
    rate_guard('verify_ip', client_ip(), 20, 900);
    rate_hit('verify_ip', client_ip());

    $pdo = db();
    $hash = hash('sha256', $token);
    $pdo->beginTransaction();
    try {
        $st = $pdo->prepare('SELECT id, user_id, expires_at, used_at FROM email_tokens WHERE token_hash = ? AND purpose = ? FOR UPDATE');
        $st->execute([$hash, 'verify_email']);
        $t = $st->fetch();
        if (!$t || $t['used_at'] !== null) {
            $pdo->rollBack();
            fail('Ce lien est invalide ou a déjà été utilisé.', 410);
        }
        if (strtotime($t['expires_at']) < time()) {
            $pdo->rollBack();
            fail('Ce lien a expiré. Demandez un nouvel e-mail de confirmation depuis la page de connexion.', 410);
        }
        $pdo->prepare('UPDATE email_tokens SET used_at = NOW() WHERE id = ? AND used_at IS NULL')->execute([$t['id']]);
        $pdo->prepare('UPDATE users SET email_verified_at = NOW() WHERE id = ? AND email_verified_at IS NULL')->execute([$t['user_id']]);
        $pdo->commit();
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        throw $e;
    }
    json_out(['success' => true, 'message' => 'Adresse e-mail confirmée. Vous pouvez maintenant vous connecter.']);
}

/**
 * Vérifie le code à 6 chiffres saisi par l'utilisateur après son inscription.
 * Si le code est bon : e-mail marqué vérifié + connexion automatique (session créée),
 * le front redirige alors directement vers la page d'accueil.
 */
function act_verify_code(array $in): void
{
    // --- 1) Nettoyage et validation des entrées ---
    $email = strtolower(trim((string)($in['email'] ?? '')));
    $code = preg_replace('/\D/', '', (string)($in['code'] ?? ''));   // ne garde que les chiffres (tolère espaces/tirets)
    if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($code) !== 6) {
        fail('Saisissez le code à 6 chiffres reçu par e-mail.', 422);
    }

    // --- 2) Anti force brute ---
    // Il n'existe que 1 000 000 de codes possibles : sans limite, un pirate les testerait tous.
    // Ici : 5 échecs max par e-mail et 30 par IP, sur 15 minutes.
    $ip = client_ip();
    rate_guard('vcode_ip', $ip, 30, 900, 'Trop de tentatives. Réessayez dans 15 minutes.');
    rate_guard('vcode_email', $email, 5, 900, 'Trop de tentatives. Demandez un nouveau code ou réessayez dans 15 minutes.');

    // --- 3) Retrouver le compte ---
    $pdo = db();
    $st = $pdo->prepare('SELECT * FROM users WHERE email = ? AND is_active = 1');
    $st->execute([$email]);
    $u = $st->fetch();
    if (!$u) {
        // Même message qu'un mauvais code : on ne révèle pas si l'e-mail existe
        rate_hit('vcode_ip', $ip);
        rate_hit('vcode_email', $email);
        fail('Code incorrect ou expiré.', 422);
    }
    if ($u['email_verified_at']) fail('Cette adresse est déjà confirmée. Connectez-vous.', 409);

    // --- 4) Contrôler le code dans une transaction (évite qu'un même code serve deux fois) ---
    $pdo->beginTransaction();
    try {
        // Dernier code non utilisé de cet utilisateur ; FOR UPDATE verrouille la ligne
        $st = $pdo->prepare("SELECT id, token_hash, expires_at FROM email_tokens
                             WHERE user_id = ? AND purpose = 'verify_email' AND used_at IS NULL
                             ORDER BY id DESC LIMIT 1 FOR UPDATE");
        $st->execute([$u['id']]);
        $t = $st->fetch();

        // Code absent, expiré, ou différent. hash_equals = comparaison à temps constant (anti timing attack)
        if (!$t
            || strtotime($t['expires_at']) < time()
            || !hash_equals($t['token_hash'], hash('sha256', (int)$u['id'] . ':' . $code))) {
            $pdo->rollBack();
            rate_hit('vcode_ip', $ip);
            rate_hit('vcode_email', $email);
            fail('Code incorrect ou expiré.', 422);
        }

        // Code valide : on le consomme et on valide l'e-mail
        $pdo->prepare('UPDATE email_tokens SET used_at = NOW() WHERE id = ?')->execute([$t['id']]);
        $pdo->prepare('UPDATE users SET email_verified_at = NOW() WHERE id = ? AND email_verified_at IS NULL')->execute([$u['id']]);
        $pdo->commit();
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        throw $e;
    }

    // --- 5) Connexion automatique (mêmes étapes que act_login) ---
    session_regenerate_id(true);                         // contre la fixation de session
    $_SESSION['uid'] = (int)$u['id'];
    $_SESSION['sv'] = (int)$u['session_version'];
    $_SESSION['csrf'] = bin2hex(random_bytes(32));

    json_out([
        'success' => true,
        'csrf' => $_SESSION['csrf'],
        'user' => me_payload($u),
        'redirect' => in_array($u['role'], ['admin', 'moderator'], true) ? 'admin' : 'feed',   // 'feed' = page d'accueil
        'unread' => unread_count((int)$u['id']),
    ]);
}

function act_resend_verification(array $in): void
{
    $email = strtolower(trim((string)($in['email'] ?? '')));
    $ip = client_ip();
    rate_guard('resend_ip', $ip, 10, 3600);
    if ($email !== '') rate_guard('resend_email', $email, 3, 3600, 'Trop de demandes pour cette adresse. Réessayez dans une heure.');
    rate_hit('resend_ip', $ip);
    if ($email !== '') rate_hit('resend_email', $email);

    $generic = 'Si un compte non vérifié existe pour cette adresse, un nouveau code vient d\'être envoyé.';
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) json_out(['success' => true, 'message' => $generic]);

    $st = db()->prepare('SELECT * FROM users WHERE email = ? AND email_verified_at IS NULL AND is_active = 1');
    $st->execute([$email]);
    if ($u = $st->fetch()) send_verification_email($u);
    json_out(['success' => true, 'message' => $generic]);
}

function act_login(array $in): void
{
    $email = strtolower(trim((string)($in['email'] ?? '')));
    $pass = (string)($in['password'] ?? '');
    $ip = client_ip();

    rate_guard('login_ip', $ip, 30, 900, 'Trop de tentatives de connexion. Réessayez dans 15 minutes.');
    rate_guard('login_email', $email, 5, 900, 'Trop de tentatives pour ce compte. Réessayez dans 15 minutes.');

    $st = db()->prepare('SELECT * FROM users WHERE email = ?');
    $st->execute([$email]);
    $u = $st->fetch();

    // password_verify est toujours exécuté (même hash factice) pour ne pas révéler si l'e-mail existe
    $ok = password_verify($pass, $u['password'] ?? DUMMY_HASH);
    if (!$u || !$ok) {
        rate_hit('login_ip', $ip);
        rate_hit('login_email', $email);
        fail('E-mail ou mot de passe incorrect.', 401);
    }
    if (!$u['is_active']) fail('Ce compte est désactivé.', 403);
    if (!$u['email_verified_at']) {
        fail('Votre adresse e-mail n\'est pas encore confirmée. Consultez votre boîte de réception.', 403, ['code' => 'email_not_verified', 'email' => $email]);
    }

    if (password_needs_rehash($u['password'], PASSWORD_DEFAULT)) {
        db()->prepare('UPDATE users SET password = ? WHERE id = ?')->execute([password_hash($pass, PASSWORD_DEFAULT), $u['id']]);
    }
    db()->prepare('DELETE FROM rate_limits WHERE action = ? AND rate_key = ?')->execute(['login_email', $email]);

    session_regenerate_id(true);               // contre la fixation de session
    $_SESSION['uid'] = (int)$u['id'];
    $_SESSION['sv'] = (int)$u['session_version'];
    $_SESSION['csrf'] = bin2hex(random_bytes(32));

    json_out([
        'success' => true, 'csrf' => $_SESSION['csrf'], 'user' => me_payload($u),
        'redirect' => in_array($u['role'], ['admin', 'moderator'], true) ? 'admin' : 'feed',
        'unread' => unread_count((int)$u['id']),
    ]);
}

function act_logout(array $in): void
{
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', ['expires' => time() - 3600, 'path' => $p['path'], 'secure' => $p['secure'], 'httponly' => true, 'samesite' => 'Lax']);
    }
    session_destroy();
    json_out(['success' => true]);
}

function act_change_password(array $in): void
{
    $u = require_login();
    rate_guard('pwchange', (string)$u['id'], 5, 900, 'Trop de tentatives. Réessayez dans 15 minutes.');

    $cur = (string)($in['current_password'] ?? '');
    $new = (string)($in['new_password'] ?? '');
    $conf = (string)($in['new_password_confirm'] ?? '');

    if (!password_verify($cur, $u['password'])) {
        rate_hit('pwchange', (string)$u['id']);
        fail('Le mot de passe actuel est incorrect.', 422);
    }
    if ($err = password_policy_error($new)) fail($err, 422);
    if (!hash_equals($new, $conf)) fail('La confirmation ne correspond pas au nouveau mot de passe.', 422);
    if (hash_equals($cur, $new)) fail('Le nouveau mot de passe doit être différent de l\'actuel.', 422);

    // session_version + 1 => toutes les AUTRES sessions deviennent invalides
    $newVersion = (int)$u['session_version'] + 1;
    db()->prepare('UPDATE users SET password = ?, session_version = ? WHERE id = ?')
        ->execute([password_hash($new, PASSWORD_DEFAULT), $newVersion, $u['id']]);
    session_regenerate_id(true);
    $_SESSION['sv'] = $newVersion;
    $_SESSION['csrf'] = bin2hex(random_bytes(32));

    json_out(['success' => true, 'csrf' => $_SESSION['csrf'], 'message' => 'Mot de passe modifié. Vos autres sessions ont été déconnectées.']);
}

// =====================================================================
//  Profils
// =====================================================================

function act_profile(array $in): void
{
    $me = require_login();
    $id = isset($_GET['id']) ? (int)$_GET['id'] : (int)$me['id'];
    $isMe = $id === (int)$me['id'];
    $isAdmin = $me['role'] === 'admin';

    $st = db()->prepare('SELECT * FROM users WHERE id = ? AND is_active = 1 AND email_verified_at IS NOT NULL');
    $st->execute([$id]);
    $u = $st->fetch();
    if (!$u || (!$isMe && !$isAdmin && !in_array($u['role'], ['student', 'company'], true))) fail('Profil introuvable.', 404);

    $out = [
        'id' => (int)$u['id'], 'name' => $u['name'], 'role' => $u['role'],
        'has_avatar' => !empty($u['avatar_path']), 'created_at' => $u['created_at'], 'is_me' => $isMe,
    ];
    if ($isMe || $isAdmin) $out['email'] = $u['email'];

    if ($u['role'] === 'student') {
        $p = db()->prepare('SELECT first_name, last_name, school, field_of_study, bio, phone FROM student_profiles WHERE user_id = ?');
        $p->execute([$id]);
        $row = $p->fetch() ?: [];
        if (!$isMe) unset($row['phone']);
        $out['student'] = $row + ['first_name' => '', 'last_name' => '', 'school' => '', 'field_of_study' => '', 'bio' => ''];
    } elseif ($u['role'] === 'company') {
        $p = db()->prepare('SELECT official_name, sector, website_name, website, address, description, services, verification_status FROM company_profiles WHERE user_id = ?');
        $p->execute([$id]);
        $row = $p->fetch() ?: ['verification_status' => 'pending'];
        $out['verified'] = ($row['verification_status'] ?? '') === 'verified';
        if ($isMe || $isAdmin) $out['verification_status'] = $row['verification_status'] ?? 'pending';
        unset($row['verification_status']);
        $out['company'] = $row + ['official_name' => $u['name'], 'sector' => '', 'website_name' => '', 'website' => '', 'address' => '', 'description' => '', 'services' => ''];
        if ($isMe) {
            $v = db()->prepare('SELECT id, legal_name, registration_number, status, rejection_reason, created_at FROM company_verifications WHERE company_id = ? ORDER BY id DESC LIMIT 1');
            $v->execute([$id]);
            $out['verification_request'] = $v->fetch() ?: null;
        }
    }

    if (!$isMe) $out['connection'] = connection_state((int)$me['id'], $id);
    $c = db()->prepare("SELECT COUNT(*) FROM connections WHERE status = 'accepted' AND (sender_id = ? OR receiver_id = ?)");
    $c->execute([$id, $id]);
    $out['connections_count'] = (int)$c->fetchColumn();

    json_out(['success' => true, 'profile' => $out]);
}

function act_update_profile(array $in): void
{
    $u = require_login();
    $pdo = db();
    $id = (int)$u['id'];

    if ($u['role'] === 'student') {
        $first = clean_text($in['first_name'] ?? '', 80);
        $last = clean_text($in['last_name'] ?? '', 80);
        if ($first === '' || $last === '') fail('Le prénom et le nom sont obligatoires.', 422);
        $phone = clean_text($in['phone'] ?? '', 20);
        if ($phone !== '' && !preg_match('/^[0-9+\s().-]{6,20}$/', $phone)) fail('Numéro de téléphone invalide.', 422);
        $pdo->beginTransaction();
        $pdo->prepare('UPDATE users SET name = ? WHERE id = ?')->execute(["$first $last", $id]);
        $pdo->prepare('INSERT INTO student_profiles (user_id, first_name, last_name, school, field_of_study, bio, phone) VALUES (?,?,?,?,?,?,?)
                       ON DUPLICATE KEY UPDATE first_name = VALUES(first_name), last_name = VALUES(last_name), school = VALUES(school),
                       field_of_study = VALUES(field_of_study), bio = VALUES(bio), phone = VALUES(phone)')
            ->execute([$id, $first, $last, clean_text($in['school'] ?? '', 150), clean_text($in['field_of_study'] ?? '', 150), clean_text($in['bio'] ?? '', 2000), $phone]);
        $pdo->commit();
    } elseif ($u['role'] === 'company') {
        $official = clean_text($in['official_name'] ?? '', 100);
        if ($official === '') fail('Le nom officiel de l\'entreprise est obligatoire.', 422);
        $website = clean_text($in['website'] ?? '', 200);
        if (!valid_url_or_empty($website)) fail('L\'URL du site web doit commencer par http:// ou https://.', 422);
        // NB : verification_status n'est volontairement PAS modifiable ici.
        $pdo->beginTransaction();
        $pdo->prepare('UPDATE users SET name = ? WHERE id = ?')->execute([$official, $id]);
        $pdo->prepare('INSERT INTO company_profiles (user_id, official_name, sector, website_name, website, address, description, services) VALUES (?,?,?,?,?,?,?,?)
                       ON DUPLICATE KEY UPDATE official_name = VALUES(official_name), sector = VALUES(sector), website_name = VALUES(website_name),
                       website = VALUES(website), address = VALUES(address), description = VALUES(description), services = VALUES(services)')
            ->execute([$id, $official, clean_text($in['sector'] ?? '', 150), clean_text($in['website_name'] ?? '', 150), $website !== '' ? $website : null,
                clean_text($in['address'] ?? '', 255), clean_text($in['description'] ?? '', 3000), clean_text($in['services'] ?? '', 3000)]);
        $pdo->commit();
    } else {
        fail('Ce type de compte n\'a pas de profil modifiable.', 403);
    }
    json_out(['success' => true, 'message' => 'Profil mis à jour.']);
}

function act_avatar_set(array $in): void
{
    $u = require_login();
    if (empty($_FILES['avatar'])) fail('Aucune image reçue.', 422);
    [$name] = store_upload($_FILES['avatar'], IMAGE_MIMES, 3 * 1048576, 'avatars');
    $old = $u['avatar_path'];
    db()->prepare('UPDATE users SET avatar_path = ? WHERE id = ?')->execute([$name, $u['id']]);
    delete_stored('avatars', $old);
    json_out(['success' => true, 'message' => 'Photo de profil mise à jour.']);
}

function act_avatar_delete(array $in): void
{
    $u = require_login();
    db()->prepare('UPDATE users SET avatar_path = NULL WHERE id = ?')->execute([$u['id']]);
    delete_stored('avatars', $u['avatar_path']);
    json_out(['success' => true, 'message' => 'Photo supprimée.']);
}

function act_people(array $in): void
{
    $me = require_login();
    $q = clean_text($_GET['q'] ?? '', 60);
    $role = (string)($_GET['role'] ?? '');
    $sql = "SELECT u.id, u.name, u.role, (u.avatar_path IS NOT NULL) AS has_avatar,
                   sp.school, sp.field_of_study, cp.sector, (cp.verification_status = 'verified') AS verified
            FROM users u
            LEFT JOIN student_profiles sp ON sp.user_id = u.id
            LEFT JOIN company_profiles cp ON cp.user_id = u.id
            WHERE u.is_active = 1 AND u.email_verified_at IS NOT NULL AND u.role IN ('student','company') AND u.id <> ?";
    $params = [$me['id']];
    if (in_array($role, ['student', 'company'], true)) { $sql .= ' AND u.role = ?'; $params[] = $role; }
    if ($q !== '') {
        $like = '%' . str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], $q) . '%';
        $sql .= ' AND (u.name LIKE ? OR sp.school LIKE ? OR sp.field_of_study LIKE ? OR cp.sector LIKE ?)';
        array_push($params, $like, $like, $like, $like);
    }
    $sql .= ' ORDER BY u.name LIMIT 40';
    $st = db()->prepare($sql);
    $st->execute($params);
    $rows = $st->fetchAll();
    foreach ($rows as &$r) {
        $r['id'] = (int)$r['id'];
        $r['has_avatar'] = (bool)$r['has_avatar'];
        $r['verified'] = (bool)$r['verified'];
        $r['connection'] = connection_state((int)$me['id'], $r['id']);
    }
    json_out(['success' => true, 'people' => $rows]);
}

// =====================================================================
//  Vérification des entreprises
// =====================================================================

function act_submit_verification(array $in): void
{
    $u = require_login();
    require_role($u, ['company']);
    $pdo = db();

    $st = $pdo->prepare('SELECT status FROM company_verifications WHERE company_id = ? ORDER BY id DESC LIMIT 1');
    $st->execute([$u['id']]);
    $last = $st->fetchColumn();
    if ($last === 'pending') fail('Une demande est déjà en cours d\'examen.', 409);
    if ($last === 'approved') fail('Votre entreprise est déjà vérifiée.', 409);

    $legal = clean_text($in['legal_name'] ?? '', 190);
    $reg = clean_text($in['registration_number'] ?? '', 80);
    $extra = clean_text($in['extra_info'] ?? '', 2000);
    if ($legal === '') fail('Le nom légal de l\'entreprise est obligatoire.', 422);
    if (!preg_match('/^[\p{L}\p{N}][\p{L}\p{N}\s.\/-]{3,79}$/u', $reg)) fail('Numéro d\'immatriculation ou identifiant fiscal invalide.', 422);
    if (empty($_FILES['document'])) fail('Le justificatif est obligatoire (PDF, JPG ou PNG).', 422);

    [$stored, $mime, $orig] = store_upload($_FILES['document'], DOC_MIMES, 5 * 1048576, 'documents');
    $pdo->beginTransaction();
    $pdo->prepare('INSERT INTO company_verifications (company_id, legal_name, registration_number, document_path, document_original_name, document_mime, extra_info) VALUES (?,?,?,?,?,?,?)')
        ->execute([$u['id'], $legal, $reg, $stored, $orig, $mime, $extra]);
    $pdo->prepare("UPDATE company_profiles SET verification_status = 'pending' WHERE user_id = ?")->execute([$u['id']]);
    $pdo->commit();
    json_out(['success' => true, 'message' => 'Demande envoyée. Elle sera examinée par un administrateur.'], 201);
}

function act_admin_verifications(array $in): void
{
    $u = require_login();
    require_role($u, ['admin']);
    $status = (string)($_GET['status'] ?? 'pending');
    $where = in_array($status, ['pending', 'approved', 'rejected'], true) ? 'WHERE v.status = ?' : '';
    $sql = "SELECT v.id, v.company_id, u.name AS company_name, u.email, v.legal_name, v.registration_number, v.extra_info,
                   v.document_original_name, v.document_mime, v.status, v.rejection_reason, v.created_at, v.reviewed_at
            FROM company_verifications v JOIN users u ON u.id = v.company_id $where ORDER BY v.created_at DESC LIMIT 100";
    $st = db()->prepare($sql);
    $st->execute($where ? [$status] : []);
    json_out(['success' => true, 'items' => $st->fetchAll()]);
}

function act_admin_companies(array $in): void
{
    $u = require_login();
    require_role($u, ['admin']);
    $status = (string)($_GET['status'] ?? '');
    $where = in_array($status, ['pending', 'verified', 'rejected'], true) ? 'AND cp.verification_status = ?' : '';
    $st = db()->prepare("SELECT u.id, u.name, u.email, cp.verification_status, cp.verified_at, cp.sector, u.created_at
                         FROM users u JOIN company_profiles cp ON cp.user_id = u.id
                         WHERE u.role = 'company' AND u.email_verified_at IS NOT NULL $where ORDER BY u.created_at DESC LIMIT 200");
    $st->execute($where ? [$status] : []);
    json_out(['success' => true, 'companies' => $st->fetchAll()]);
}

function act_admin_review(array $in): void
{
    $admin = require_login();
    require_role($admin, ['admin']);
    $id = (int)($in['id'] ?? 0);
    $decision = (string)($in['decision'] ?? '');
    $reason = clean_text($in['reason'] ?? '', 1000);
    if (!in_array($decision, ['approve', 'reject'], true)) fail('Décision invalide.', 422);
    if ($decision === 'reject' && $reason === '') fail('Un motif de refus est obligatoire.', 422);

    $pdo = db();
    $pdo->beginTransaction();
    try {
        $st = $pdo->prepare('SELECT * FROM company_verifications WHERE id = ? FOR UPDATE');
        $st->execute([$id]);
        $v = $st->fetch();
        if (!$v) { $pdo->rollBack(); fail('Demande introuvable.', 404); }
        if ($v['status'] !== 'pending') { $pdo->rollBack(); fail('Cette demande a déjà été traitée.', 409); }

        $approved = $decision === 'approve';
        $pdo->prepare('UPDATE company_verifications SET status = ?, rejection_reason = ?, reviewed_by = ?, reviewed_at = NOW() WHERE id = ?')
            ->execute([$approved ? 'approved' : 'rejected', $approved ? null : $reason, $admin['id'], $id]);
        // Le SEUL endroit du code qui attribue le statut "verified"
        $pdo->prepare('UPDATE company_profiles SET verification_status = ?, verified_at = ? WHERE user_id = ?')
            ->execute([$approved ? 'verified' : 'rejected', $approved ? date('Y-m-d H:i:s') : null, $v['company_id']]);
        notify((int)$v['company_id'], 'verification_update',
            $approved ? 'Votre entreprise a été vérifiée. Le badge est maintenant affiché sur votre profil.' : 'Votre demande de vérification a été refusée : ' . $reason,
            (int)$admin['id'], $id);
        $pdo->commit();
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        throw $e;
    }
    json_out(['success' => true, 'message' => $decision === 'approve' ? 'Entreprise vérifiée.' : 'Demande refusée.']);
}

// =====================================================================
//  Fichiers protégés (avatars, images de publications, justificatifs)
// =====================================================================

function act_file(array $in): void
{
    $me = require_login();
    $kind = (string)($_GET['kind'] ?? '');
    $id = (int)($_GET['id'] ?? 0);
    $pdo = db();
    $sub = null; $name = null; $mime = null;

    if ($kind === 'avatar') {
        $st = $pdo->prepare('SELECT avatar_path FROM users WHERE id = ?'); $st->execute([$id]);
        $sub = 'avatars'; $name = $st->fetchColumn();
    } elseif ($kind === 'post') {
        $st = $pdo->prepare('SELECT image_path FROM posts WHERE id = ?'); $st->execute([$id]);
        $sub = 'posts'; $name = $st->fetchColumn();
    } elseif ($kind === 'document') {
        $st = $pdo->prepare('SELECT company_id, document_path, document_mime FROM company_verifications WHERE id = ?'); $st->execute([$id]);
        $row = $st->fetch();
        // Accès : administrateur, ou l'entreprise propriétaire. Personne d'autre.
        if (!$row || ($me['role'] !== 'admin' && (int)$row['company_id'] !== (int)$me['id'])) fail('Fichier introuvable.', 404);
        $sub = 'documents'; $name = $row['document_path']; $mime = $row['document_mime'];
    }
    if (!$sub || !$name || !preg_match('/^[a-f0-9]{32}\.[a-z]{3,4}$/', (string)$name)) {
        http_response_code(404);
        header('Content-Type: text/plain; charset=utf-8');
        echo 'Fichier introuvable.';
        exit;
    }
    $path = storage_dir($sub) . '/' . $name;
    if (!is_file($path)) { http_response_code(404); exit; }

    if (!$mime) {
        $ext = pathinfo($name, PATHINFO_EXTENSION);
        $mime = ['jpg' => 'image/jpeg', 'png' => 'image/png', 'webp' => 'image/webp', 'pdf' => 'application/pdf'][$ext] ?? 'application/octet-stream';
    }
    header('Content-Type: ' . $mime);
    header('Content-Length: ' . filesize($path));
    header('X-Content-Type-Options: nosniff');
    header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; sandbox");
    header('Cache-Control: private, max-age=' . ($kind === 'document' ? 0 : 300));
    header('Content-Disposition: inline');
    readfile($path);
    exit;
}

// =====================================================================
//  Publications, J'aime, commentaires
// =====================================================================

function can_moderate(array $u): bool
{
    return in_array($u['role'], ['admin', 'moderator'], true);
}

function act_posts(array $in): void
{
    $me = require_login();
    $before = (int)($_GET['before'] ?? 0);
    $authorId = (int)($_GET['author'] ?? 0);
    $sql = "SELECT p.id, p.user_id, p.content, (p.image_path IS NOT NULL) AS has_image, p.created_at, p.updated_at,
                   u.name AS author, u.role AS author_role, (u.avatar_path IS NOT NULL) AS has_avatar,
                   (cp.verification_status = 'verified') AS verified,
                   (SELECT COUNT(*) FROM post_likes l WHERE l.post_id = p.id) AS likes,
                   EXISTS(SELECT 1 FROM post_likes l WHERE l.post_id = p.id AND l.user_id = ?) AS liked,
                   (SELECT COUNT(*) FROM post_comments c WHERE c.post_id = p.id) AS comments
            FROM posts p JOIN users u ON u.id = p.user_id
            LEFT JOIN company_profiles cp ON cp.user_id = u.id
            WHERE u.is_active = 1";
    $params = [$me['id']];
    if ($before > 0) { $sql .= ' AND p.id < ?'; $params[] = $before; }
    if ($authorId > 0) { $sql .= ' AND p.user_id = ?'; $params[] = $authorId; }
    $sql .= ' ORDER BY p.id DESC LIMIT 30';
    $st = db()->prepare($sql);
    $st->execute($params);
    $rows = $st->fetchAll();
    foreach ($rows as &$r) {
        $r['id'] = (int)$r['id']; $r['user_id'] = (int)$r['user_id'];
        $r['has_image'] = (bool)$r['has_image']; $r['has_avatar'] = (bool)$r['has_avatar'];
        $r['verified'] = (bool)$r['verified']; $r['liked'] = (bool)$r['liked'];
        $r['likes'] = (int)$r['likes']; $r['comments'] = (int)$r['comments'];
        $r['can_edit'] = $r['user_id'] === (int)$me['id'];
        $r['can_delete'] = $r['can_edit'] || can_moderate($me);
    }
    json_out(['success' => true, 'posts' => $rows]);
}

function act_post_create(array $in): void
{
    $u = require_login();
    rate_guard('post', (string)$u['id'], 20, 600, 'Vous publiez trop vite. Patientez quelques minutes.');
    $content = clean_text($in['content'] ?? '', 3000);
    $hasImage = !empty($_FILES['image']) && ($_FILES['image']['error'] ?? 4) !== UPLOAD_ERR_NO_FILE;
    if ($content === '' && !$hasImage) fail('Écrivez un texte ou ajoutez une photo.', 422);

    $img = null;
    if ($hasImage) [$img] = store_upload($_FILES['image'], IMAGE_MIMES, 5 * 1048576, 'posts');
    db()->prepare('INSERT INTO posts (user_id, content, image_path) VALUES (?, ?, ?)')->execute([$u['id'], $content, $img]);
    $newId = (int)db()->lastInsertId();
    rate_hit('post', (string)$u['id']);
    json_out(['success' => true, 'message' => 'Publication ajoutée.', 'id' => $newId], 201);
}

function load_post(int $id): array
{
    $st = db()->prepare('SELECT * FROM posts WHERE id = ?');
    $st->execute([$id]);
    $p = $st->fetch();
    if (!$p) fail('Publication introuvable.', 404);
    return $p;
}

function act_post_update(array $in): void
{
    $u = require_login();
    $p = load_post((int)($in['id'] ?? 0));
    if ((int)$p['user_id'] !== (int)$u['id']) fail('Vous ne pouvez modifier que vos propres publications.', 403);

    $content = clean_text($in['content'] ?? '', 3000);
    $hasImage = !empty($_FILES['image']) && ($_FILES['image']['error'] ?? 4) !== UPLOAD_ERR_NO_FILE;
    $removeImage = !empty($in['remove_image']) && $in['remove_image'] !== 'false' && $in['remove_image'] !== '0';

    $img = $p['image_path'];
    if ($hasImage) {
        [$new] = store_upload($_FILES['image'], IMAGE_MIMES, 5 * 1048576, 'posts');
        delete_stored('posts', $img);
        $img = $new;
    } elseif ($removeImage) {
        delete_stored('posts', $img);
        $img = null;
    }
    if ($content === '' && !$img) fail('Une publication ne peut pas être vide.', 422);
    db()->prepare('UPDATE posts SET content = ?, image_path = ?, updated_at = NOW() WHERE id = ?')->execute([$content, $img, $p['id']]);
    json_out(['success' => true, 'message' => 'Publication modifiée.']);
}

function act_post_delete(array $in): void
{
    $u = require_login();
    $p = load_post((int)($in['id'] ?? 0));
    if ((int)$p['user_id'] !== (int)$u['id'] && !can_moderate($u)) fail('Action non autorisée.', 403);
    db()->prepare('DELETE FROM posts WHERE id = ?')->execute([$p['id']]);
    delete_stored('posts', $p['image_path']);
    json_out(['success' => true, 'message' => 'Publication supprimée.']);
}

function act_like_set(array $in): void
{
    $u = require_login();
    $p = load_post((int)($in['post_id'] ?? 0));
    $liked = !empty($in['liked']) && $in['liked'] !== 'false' && $in['liked'] !== '0';
    $pdo = db();
    if ($liked) {
        // clé primaire (post_id, user_id) : impossible d'avoir deux J'aime du même utilisateur
        $st = $pdo->prepare('INSERT IGNORE INTO post_likes (post_id, user_id) VALUES (?, ?)');
        $st->execute([$p['id'], $u['id']]);
        if ($st->rowCount() > 0 && (int)$p['user_id'] !== (int)$u['id']) {
            notify((int)$p['user_id'], 'post_liked', $u['name'] . ' a aimé votre publication.', (int)$u['id'], (int)$p['id'], true);
        }
    } else {
        $pdo->prepare('DELETE FROM post_likes WHERE post_id = ? AND user_id = ?')->execute([$p['id'], $u['id']]);
    }
    $c = $pdo->prepare('SELECT COUNT(*) FROM post_likes WHERE post_id = ?');
    $c->execute([$p['id']]);
    json_out(['success' => true, 'liked' => $liked, 'likes' => (int)$c->fetchColumn()]);
}

function act_comments(array $in): void
{
    $me = require_login();
    $p = load_post((int)($_GET['post_id'] ?? 0));
    $st = db()->prepare('SELECT c.id, c.user_id, c.content, c.created_at, u.name AS author, u.role AS author_role, (u.avatar_path IS NOT NULL) AS has_avatar
                         FROM post_comments c JOIN users u ON u.id = c.user_id WHERE c.post_id = ? ORDER BY c.id ASC LIMIT 200');
    $st->execute([$p['id']]);
    $rows = $st->fetchAll();
    foreach ($rows as &$r) {
        $r['id'] = (int)$r['id']; $r['user_id'] = (int)$r['user_id']; $r['has_avatar'] = (bool)$r['has_avatar'];
        // l'auteur du commentaire, l'auteur de la publication et les modérateurs peuvent supprimer
        $r['can_delete'] = $r['user_id'] === (int)$me['id'] || (int)$p['user_id'] === (int)$me['id'] || can_moderate($me);
    }
    json_out(['success' => true, 'comments' => $rows]);
}

function act_comment_add(array $in): void
{
    $u = require_login();
    $p = load_post((int)($in['post_id'] ?? 0));
    rate_guard('comment', (string)$u['id'], 40, 600, 'Vous commentez trop vite. Patientez quelques minutes.');
    $content = clean_text($in['content'] ?? '', 1000);
    if ($content === '') fail('Le commentaire est vide.', 422);
    db()->prepare('INSERT INTO post_comments (post_id, user_id, content) VALUES (?, ?, ?)')->execute([$p['id'], $u['id'], $content]);
    rate_hit('comment', (string)$u['id']);
    if ((int)$p['user_id'] !== (int)$u['id']) {
        notify((int)$p['user_id'], 'post_commented', $u['name'] . ' a commenté votre publication.', (int)$u['id'], (int)$p['id']);
    }
    json_out(['success' => true, 'message' => 'Commentaire ajouté.'], 201);
}

function act_comment_delete(array $in): void
{
    $u = require_login();
    $st = db()->prepare('SELECT c.id, c.user_id, p.user_id AS post_owner FROM post_comments c JOIN posts p ON p.id = c.post_id WHERE c.id = ?');
    $st->execute([(int)($in['id'] ?? 0)]);
    $c = $st->fetch();
    if (!$c) fail('Commentaire introuvable.', 404);
    $uid = (int)$u['id'];
    if ((int)$c['user_id'] !== $uid && (int)$c['post_owner'] !== $uid && !can_moderate($u)) fail('Action non autorisée.', 403);
    db()->prepare('DELETE FROM post_comments WHERE id = ?')->execute([$c['id']]);
    json_out(['success' => true, 'message' => 'Commentaire supprimé.']);
}

// =====================================================================
//  Invitations et relations
// =====================================================================

function act_invite_send(array $in): void
{
    $me = require_login();
    $targetId = (int)($in['user_id'] ?? 0);
    $meId = (int)$me['id'];
    if ($targetId === $meId) fail('Vous ne pouvez pas vous inviter vous-même.', 422);
    if (!in_array($me['role'], ['student', 'company'], true)) fail('Ce type de compte ne peut pas envoyer d\'invitations.', 403);
    rate_guard('invite', (string)$meId, 30, 3600, 'Trop d\'invitations envoyées. Réessayez plus tard.');

    $st = db()->prepare("SELECT * FROM users WHERE id = ? AND is_active = 1 AND email_verified_at IS NOT NULL AND role IN ('student','company')");
    $st->execute([$targetId]);
    $t = $st->fetch();
    if (!$t) fail('Utilisateur introuvable.', 404);
    if ($me['role'] === 'company' && $t['role'] === 'company') fail('Les invitations entre entreprises ne sont pas prises en charge.', 422);

    [$lo, $hi] = pair($meId, $targetId);
    $pdo = db();
    $pdo->beginTransaction();
    try {
        $st = $pdo->prepare('SELECT * FROM connections WHERE user_low = ? AND user_high = ? FOR UPDATE');
        $st->execute([$lo, $hi]);
        $c = $st->fetch();
        if ($c) {
            if ($c['status'] === 'accepted') { $pdo->rollBack(); fail('Vous êtes déjà en relation.', 409); }
            if ($c['status'] === 'pending') {
                $pdo->rollBack();
                fail((int)$c['sender_id'] === $meId ? 'Une invitation est déjà en attente.' : 'Cette personne vous a déjà invité : acceptez son invitation dans l\'onglet Invitations.', 409);
            }
            // refusée : l'expéditeur initial doit attendre 30 jours avant de relancer ; celui qui a refusé peut inviter
            if ((int)$c['sender_id'] === $meId && $c['responded_at'] && strtotime($c['responded_at']) > time() - 30 * 86400) {
                $pdo->rollBack();
                fail('Cette invitation a été refusée récemment. Vous pourrez réessayer plus tard.', 409);
            }
            $pdo->prepare("UPDATE connections SET sender_id = ?, receiver_id = ?, status = 'pending', responded_at = NULL, created_at = NOW() WHERE id = ?")
                ->execute([$meId, $targetId, $c['id']]);
            $cid = (int)$c['id'];
        } else {
            $pdo->prepare('INSERT INTO connections (sender_id, receiver_id, user_low, user_high) VALUES (?,?,?,?)')->execute([$meId, $targetId, $lo, $hi]);
            $cid = (int)$pdo->lastInsertId();
        }
        notify($targetId, 'invitation_received', $me['name'] . ' vous a envoyé une invitation.', $meId, $cid);
        $pdo->commit();
    } catch (PDOException $e) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        if ($e->getCode() === '23000') fail('Une invitation existe déjà.', 409);
        throw $e;
    }
    rate_hit('invite', (string)$meId);
    json_out(['success' => true, 'message' => 'Invitation envoyée.', 'id' => $cid], 201);
}

function act_invite_respond(array $in): void
{
    $me = require_login();
    $id = (int)($in['id'] ?? 0);
    $decision = (string)($in['decision'] ?? '');
    if (!in_array($decision, ['accept', 'decline'], true)) fail('Décision invalide.', 422);

    // Condition receiver_id = utilisateur connecté : on ne peut répondre qu'aux invitations reçues
    $new = $decision === 'accept' ? 'accepted' : 'declined';
    $st = db()->prepare("UPDATE connections SET status = ?, responded_at = NOW() WHERE id = ? AND receiver_id = ? AND status = 'pending'");
    $st->execute([$new, $id, $me['id']]);
    if ($st->rowCount() === 0) fail('Invitation introuvable ou déjà traitée.', 404);

    $row = db()->prepare('SELECT sender_id FROM connections WHERE id = ?');
    $row->execute([$id]);
    $senderId = (int)$row->fetchColumn();
    db()->prepare("UPDATE notifications SET is_read = 1 WHERE user_id = ? AND type = 'invitation_received' AND ref_id = ?")->execute([$me['id'], $id]);
    if ($decision === 'accept') {
        notify($senderId, 'invitation_accepted', $me['name'] . ' a accepté votre invitation.', (int)$me['id'], $id);
    }
    json_out(['success' => true, 'message' => $decision === 'accept' ? 'Invitation acceptée.' : 'Invitation refusée.']);
}

function act_invite_cancel(array $in): void
{
    $me = require_login();
    $id = (int)($in['id'] ?? 0);
    $st = db()->prepare("DELETE FROM connections WHERE id = ? AND sender_id = ? AND status = 'pending'");
    $st->execute([$id, $me['id']]);
    if ($st->rowCount() === 0) fail('Invitation introuvable ou déjà traitée.', 404);
    db()->prepare("DELETE FROM notifications WHERE type = 'invitation_received' AND ref_id = ?")->execute([$id]);
    json_out(['success' => true, 'message' => 'Invitation annulée.']);
}

function act_connection_remove(array $in): void
{
    $me = require_login();
    $st = db()->prepare("DELETE FROM connections WHERE id = ? AND status = 'accepted' AND (sender_id = ? OR receiver_id = ?)");
    $st->execute([(int)($in['id'] ?? 0), $me['id'], $me['id']]);
    if ($st->rowCount() === 0) fail('Relation introuvable.', 404);
    json_out(['success' => true, 'message' => 'Relation supprimée.']);
}

function act_connections(array $in): void
{
    $me = require_login();
    $meId = (int)$me['id'];
    $st = db()->prepare("SELECT c.id, c.status, c.sender_id, c.receiver_id, c.created_at, c.responded_at,
                                o.id AS other_id, o.name AS other_name, o.role AS other_role, (o.avatar_path IS NOT NULL) AS has_avatar,
                                (cp.verification_status = 'verified') AS verified
                         FROM connections c
                         JOIN users o ON o.id = IF(c.sender_id = ?, c.receiver_id, c.sender_id)
                         LEFT JOIN company_profiles cp ON cp.user_id = o.id
                         WHERE (c.sender_id = ? OR c.receiver_id = ?) AND c.status IN ('pending','accepted')
                         ORDER BY c.created_at DESC");
    $st->execute([$meId, $meId, $meId]);
    $out = ['received' => [], 'sent' => [], 'friends' => []];
    foreach ($st->fetchAll() as $r) {
        $item = [
            'id' => (int)$r['id'], 'user_id' => (int)$r['other_id'], 'name' => $r['other_name'], 'role' => $r['other_role'],
            'has_avatar' => (bool)$r['has_avatar'], 'verified' => (bool)$r['verified'], 'created_at' => $r['created_at'],
        ];
        if ($r['status'] === 'accepted') $out['friends'][] = $item;
        elseif ((int)$r['receiver_id'] === $meId) $out['received'][] = $item;
        else $out['sent'][] = $item;
    }
    json_out(['success' => true] + $out);
}

// =====================================================================
//  Notifications
// =====================================================================

function act_notifications(array $in): void
{
    $me = require_login();
    $st = db()->prepare('SELECT n.id, n.type, n.ref_id, n.actor_id, n.message, n.is_read, n.created_at FROM notifications n WHERE n.user_id = ? ORDER BY n.id DESC LIMIT 50');
    $st->execute([$me['id']]);
    $rows = $st->fetchAll();
    foreach ($rows as &$r) { $r['id'] = (int)$r['id']; $r['is_read'] = (bool)$r['is_read']; }
    json_out(['success' => true, 'notifications' => $rows, 'unread' => unread_count((int)$me['id'])]);
}

function act_notif_read(array $in): void
{
    $me = require_login();
    db()->prepare('UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?')->execute([(int)($in['id'] ?? 0), $me['id']]);
    json_out(['success' => true, 'unread' => unread_count((int)$me['id'])]);
}

function act_notif_read_all(array $in): void
{
    $me = require_login();
    db()->prepare('UPDATE notifications SET is_read = 1 WHERE user_id = ?')->execute([$me['id']]);
    json_out(['success' => true, 'unread' => 0]);
}

// =====================================================================
//  Offres, candidatures, marketplace, statistiques (fonctionnalités existantes, désormais sécurisées)
// =====================================================================

function act_jobs(array $in): void
{
    $me = require_login();
    $st = db()->prepare("SELECT j.id, j.title, j.type, j.description, j.created_at, j.company_id, u.name AS company_name,
                                (cp.verification_status = 'verified') AS verified,
                                EXISTS(SELECT 1 FROM applications a WHERE a.job_id = j.id AND a.student_id = ?) AS applied
                         FROM job_offers j JOIN users u ON u.id = j.company_id LEFT JOIN company_profiles cp ON cp.user_id = u.id
                         WHERE j.status = 'open' ORDER BY j.created_at DESC LIMIT 100");
    $st->execute([$me['id']]);
    $rows = $st->fetchAll();
    foreach ($rows as &$r) { $r['id'] = (int)$r['id']; $r['verified'] = (bool)$r['verified']; $r['applied'] = (bool)$r['applied']; }
    json_out(['success' => true, 'jobs' => $rows]);
}

function act_job_create(array $in): void
{
    $u = require_login();
    require_role($u, ['company', 'admin']);
    $title = clean_text($in['title'] ?? '', 150);
    $desc = clean_text($in['description'] ?? '', 5000);
    $type = (string)($in['type'] ?? '');
    if ($title === '' || $desc === '') fail('Le titre et la description sont obligatoires.', 422);
    if (!in_array($type, ['Stage', 'Emploi', 'Alternance'], true)) fail('Type d\'offre invalide.', 422);
    // company_id vient de la session, pas du navigateur ; le nom affiché est celui du compte
    db()->prepare('INSERT INTO job_offers (company_id, title, type, description) VALUES (?,?,?,?)')->execute([$u['id'], $title, $type, $desc]);
    json_out(['success' => true, 'message' => 'Offre publiée.'], 201);
}

function act_job_apply(array $in): void
{
    $u = require_login();
    require_role($u, ['student']);
    $jobId = (int)($in['job_id'] ?? 0);
    $st = db()->prepare("SELECT id FROM job_offers WHERE id = ? AND status = 'open'");
    $st->execute([$jobId]);
    if (!$st->fetch()) fail('Offre introuvable.', 404);
    $ins = db()->prepare('INSERT IGNORE INTO applications (job_id, student_id) VALUES (?, ?)');
    $ins->execute([$jobId, $u['id']]);
    if ($ins->rowCount() === 0) fail('Vous avez déjà postulé à cette offre.', 409);
    json_out(['success' => true, 'message' => 'Candidature envoyée.'], 201);
}

function act_products(array $in): void
{
    require_login();
    json_out(['success' => true, 'products' => db()->query('SELECT id, title, description, price, created_at FROM products ORDER BY created_at DESC LIMIT 200')->fetchAll()]);
}

function act_product_create(array $in): void
{
    $u = require_login();
    require_role($u, ['admin']);
    $title = clean_text($in['title'] ?? '', 150);
    $desc = clean_text($in['description'] ?? '', 3000);
    $price = $in['price'] ?? '';
    if ($title === '' || $desc === '') fail('Titre et description obligatoires.', 422);
    if (!is_numeric($price) || (float)$price < 0 || (float)$price > 99999999) fail('Prix invalide.', 422);
    db()->prepare('INSERT INTO products (title, description, price, created_by) VALUES (?,?,?,?)')->execute([$title, $desc, (float)$price, $u['id']]);
    json_out(['success' => true, 'message' => 'Produit publié.'], 201);
}

function act_stats(array $in): void
{
    $u = require_login();
    require_role($u, ['admin']);
    $pdo = db();
    $count = fn(string $sql) => (int)$pdo->query($sql)->fetchColumn();
    json_out(['success' => true, 'stats' => [
        'users' => $count('SELECT COUNT(*) FROM users'),
        'posts' => $count('SELECT COUNT(*) FROM posts'),
        'jobs' => $count('SELECT COUNT(*) FROM job_offers'),
        'products' => $count('SELECT COUNT(*) FROM products'),
        'pending_verifications' => $count("SELECT COUNT(*) FROM company_verifications WHERE status = 'pending'"),
        'verified_companies' => $count("SELECT COUNT(*) FROM company_profiles WHERE verification_status = 'verified'"),
    ]]);
}
