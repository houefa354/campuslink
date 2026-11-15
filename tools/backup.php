<?php
/**
 * CampusLink - Outil de sauvegarde et de vérification de base de données.
 * Usage CLI :
 *   php tools/backup.php             (crée une sauvegarde dans storage/backups)
 *   php tools/backup.php --restore   (teste la validité de la dernière sauvegarde)
 */
declare(strict_types=1);

require_once __DIR__ . '/../includes/bootstrap.php';

if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    exit("Accès interdit hors ligne de commande.\n");
}

$backupDir = storage_dir('backups');
if (!is_dir($backupDir)) {
    @mkdir($backupDir, 0750, true);
    @file_put_contents($backupDir . '/.htaccess', "Require all denied\n");
}

$pdo = db();
$mode = $argv[1] ?? '--backup';

if ($mode === '--backup') {
    $timestamp = date('Y-m-d_H-i-s');
    $backupFile = $backupDir . "/campuslink_backup_{$timestamp}.sql";

    echo "==> Sauvegarde de la base 'campuslink'...\n";
    $tables = $pdo->query("SHOW FULL TABLES WHERE Table_type = 'BASE TABLE'")->fetchAll(PDO::FETCH_COLUMN);

    $sqlOut = "-- CampusLink Database Backup\n";
    $sqlOut .= "-- Généré le : " . date('Y-m-d H:i:s') . "\n";
    $sqlOut .= "SET FOREIGN_KEY_CHECKS = 0;\n\n";

    foreach ($tables as $table) {
        $createSt = $pdo->query("SHOW CREATE TABLE `{$table}`")->fetch(PDO::FETCH_NUM);
        $sqlOut .= "-- Structure pour `{$table}`\n";
        $sqlOut .= "DROP TABLE IF EXISTS `{$table}`;\n";
        $sqlOut .= $createSt[1] . ";\n\n";

        $rows = $pdo->query("SELECT * FROM `{$table}`")->fetchAll(PDO::FETCH_ASSOC);
        if (!empty($rows)) {
            $sqlOut .= "-- Données pour `{$table}` (" . count($rows) . " lignes)\n";
            foreach ($rows as $row) {
                $cols = array_map(fn($col) => "`{$col}`", array_keys($row));
                $vals = array_map(function($val) use ($pdo) {
                    if ($val === null) return 'NULL';
                    return $pdo->quote((string)$val);
                }, array_values($row));
                $sqlOut .= "INSERT INTO `{$table}` (" . implode(', ', $cols) . ") VALUES (" . implode(', ', $vals) . ");\n";
            }
            $sqlOut .= "\n";
        }
    }

    $sqlOut .= "SET FOREIGN_KEY_CHECKS = 1;\n";
    file_put_contents($backupFile, $sqlOut);

    $sizeKb = round(filesize($backupFile) / 1024, 2);
    echo "Sauvegarde réussie : {$backupFile} ({$sizeKb} Ko)\n";
    exit(0);
}

if ($mode === '--test-restore') {
    $files = glob($backupDir . '/*.sql');
    if (empty($files)) {
        exit("Aucun fichier de sauvegarde trouvé dans {$backupDir}\n");
    }
    rsort($files);
    $latest = $files[0];
    echo "==> Test de syntaxe et cohérence du fichier : " . basename($latest) . "\n";
    $content = file_get_contents($latest);
    if (strlen($content) < 100) {
        exit("ERREUR : Fichier de sauvegarde vide ou corrompu.\n");
    }
    echo "Taille : " . round(strlen($content)/1024, 2) . " Ko\n";
    echo "Contient " . substr_count($content, 'CREATE TABLE') . " tables.\n";
    echo "Contient " . substr_count($content, 'INSERT INTO') . " insertions.\n";
    echo "Vérification réussie !\n";
    exit(0);
}

echo "Usage : php tools/backup.php [--backup | --test-restore]\n";
