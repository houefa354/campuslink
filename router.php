<?php
/**
 * Routeur pour le serveur de développement PHP :  php -S localhost:8000 router.php
 * Reproduit la protection du .htaccess (le serveur intégré de PHP ignore .htaccess).
 * Inutile (et non utilisé) sous Apache / Nginx.
 */
$path = rawurldecode(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?? '/');
if (str_contains($path, '..') || preg_match('#^/(includes|tools|storage)(/|$)#', $path)
    || preg_match('#(^|/)(config(\.example)?\.php|router\.php|schema\.sql|migration\.sql|README\.md|\.[^/]+)$#', $path)) {
    http_response_code(404);
    echo 'Not found';
    return true;
}
return false;   // fichier statique ou api.php : servi normalement
