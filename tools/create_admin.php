<?php
/**
 * Création / promotion d'un administrateur (à lancer en ligne de commande uniquement).
 *   php tools/create_admin.php --create admin@exemple.com "Nom Admin"   (le mot de passe est demandé)
 *   php tools/create_admin.php --promote email@exemple.com               (compte existant -> admin, e-mail marqué vérifié)
 * Le compte est marqué "e-mail vérifié" car c'est vous, l'exploitant, qui le créez volontairement.
 */
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
require_once __DIR__ . '/../includes/bootstrap.php';

$mode = $argv[1] ?? '';
$email = strtolower(trim($argv[2] ?? ''));
if (!in_array($mode, ['--create', '--promote'], true) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    fwrite(STDERR, "Usage :\n  php tools/create_admin.php --create email \"Nom\"\n  php tools/create_admin.php --promote email\n");
    exit(1);
}
$pdo = db();
if ($mode === '--promote') {
    $st = $pdo->prepare("UPDATE users SET role = 'admin', email_verified_at = COALESCE(email_verified_at, NOW()), session_version = session_version + 1 WHERE email = ?");
    $st->execute([$email]);
    echo $st->rowCount() ? "Compte promu administrateur.\n" : "Aucun compte avec cet e-mail.\n";
    exit(0);
}
$name = trim($argv[3] ?? 'Administrateur');
fwrite(STDOUT, 'Mot de passe (8+ car., maj., min., chiffre) : ');
@system('stty -echo 2>/dev/null');
$pass = trim((string)fgets(STDIN));
@system('stty echo 2>/dev/null');
echo "\n";
if ($err = password_policy_error($pass)) { fwrite(STDERR, "$err\n"); exit(1); }
$st = $pdo->prepare("INSERT INTO users (name, email, password, role, email_verified_at) VALUES (?, ?, ?, 'admin', NOW())");
try { $st->execute([$name, $email, password_hash($pass, PASSWORD_DEFAULT)]); echo "Administrateur créé.\n"; }
catch (PDOException $e) { fwrite(STDERR, "Échec (e-mail déjà utilisé ?)\n"); exit(1); }
