<?php
/**
 * CampusLink - configuration (SECRETS : ne jamais publier ce fichier).
 *
 * 1. Copiez ce fichier en "campuslink_config.php" dans le dossier PARENT du projet
 *    (donc en dehors du dossier public), ou en "config.php" à côté de api.php
 *    (dans ce cas, protégez-le : le .htaccess fourni bloque son accès sous Apache).
 *    Vous pouvez aussi définir la variable d'environnement CAMPUSLINK_CONFIG avec le chemin du fichier.
 * 2. Renseignez les valeurs ci-dessous.
 */
return [
    'db' => [
        'host' => 'localhost',
        'port' => 3306,
        'name' => 'campuslink',
        'user' => 'root',
        'pass' => '',
    ],

    // URL publique de l'application (avec le slash final). Sert à fabriquer le lien envoyé par e-mail.
    'app_url' => 'http://localhost:8000/',

    // Dossier des fichiers privés (justificatifs, photos). Idéalement HORS du dossier public.
    // null = ../campuslink_storage (dossier voisin du projet)
    'storage_path' => null,

    // null = détection automatique (cookie "Secure" si HTTPS). Mettre true en production HTTPS.
    'cookie_secure' => null,

    'mail' => [
        // 'smtp' = envoi réel. 'log' = DÉVELOPPEMENT UNIQUEMENT : l'e-mail n'est PAS envoyé,
        // il est écrit dans <storage>/mails.log pour que vous puissiez copier le lien.
        'mode'       => 'log',
        'host'       => 'smtp.gmail.com',
        'port'       => 587,
        'encryption' => 'tls',          // 'tls' (STARTTLS, port 587) | 'ssl' (port 465) | 'none'
        'username'   => 'votre.adresse@gmail.com',
        'password'   => 'MOT-DE-PASSE-D-APPLICATION',
        'from_email' => 'votre.adresse@gmail.com',
        'from_name'  => 'CampusLink',
    ],
];
