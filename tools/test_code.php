<?php
/**
 * Test de l'envoi du code de confirmation (ligne de commande uniquement).
 * Usage : php tools/test_code.php adresse@exemple.com
 * Le compte doit déjà exister dans la table users.
 */
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }   // jamais accessible depuis le navigateur
require_once __DIR__ . '/../includes/bootstrap.php';          // charge config + base + fonctions

// Les erreurs détaillées (SMTP, SQL) s'affichent directement dans le terminal
ini_set('log_errors', '1');
ini_set('error_log', 'php://stderr');

// 1) Retrouver le compte dans la base
$email = strtolower(trim($argv[1] ?? ''));
$st = db()->prepare('SELECT id, name, email FROM users WHERE email = ?');
$st->execute([$email]);
$u = $st->fetch();
if (!$u) {
    fwrite(STDERR, "Aucun compte avec cet e-mail dans la table users.\n");
    exit(1);
}

// 2) Envoyer le code avec la MÊME fonction que l'inscription
echo "Mode d'envoi : " . cfg('mail.mode', 'log') . "\n";
$ok = send_verification_email($u);
echo $ok ? "OK : code envoyé à $email\n" : "ÉCHEC : voir l'erreur ci-dessus\n";
