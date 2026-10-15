<?php
/**
 * Test d'envoi d'e-mail, en ligne de commande uniquement.
 * Usage : php tools/test_mail.php ton.adresse@gmail.com
 */
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }   // jamais accessible depuis le navigateur

require_once __DIR__ . '/../includes/bootstrap.php';          // charge la config + le Mailer

$to = $argv[1] ?? '';
if (!filter_var($to, FILTER_VALIDATE_EMAIL)) {
    fwrite(STDERR, "Usage : php tools/test_mail.php adresse@exemple.com\n");
    exit(1);
}

// --- Même ordre de recherche que load_config() dans bootstrap.php ---
$racine = dirname(__DIR__);                                    // racine du projet
$candidats = array_filter([
    getenv('CAMPUSLINK_CONFIG') ?: null,
    dirname($racine) . '/campuslink_config.php',               // dossier PARENT (prioritaire)
    $racine . '/config.php',                                   // racine du projet
]);

$charge = null;
foreach ($candidats as $f) {
    if (is_file($f)) { $charge = $f; break; }                  // le premier trouvé est celui utilisé
}

echo "Fichier de config lu : " . ($charge ?? "AUCUN (valeurs de secours, mode log)") . "\n";
echo "Mode d'envoi         : " . cfg('mail.mode', 'log') . "\n";
echo "Serveur SMTP         : " . cfg('mail.host', '?') . ':' . cfg('mail.port', '?') . "\n";
echo "Dossier de stockage  : " . storage_dir() . "\n\n";

// Les erreurs SMTP détaillées s'affichent dans le terminal
ini_set('log_errors', '1');
ini_set('error_log', 'php://stderr');

$ok = mailer()->send($to, 'Test CampusLink', 'Ceci est un test.', '<p>Ceci est un <b>test</b>.</p>');
echo $ok ? "OK : message accepté.\n" : "ÉCHEC : voir le message [CampusLink SMTP] ci-dessus.\n";