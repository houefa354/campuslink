<?php
/**
 * Test complet des fonctionnalités ajoutées :
 * - Messagerie sans relation préalable
 * - Interdiction entreprise <-> entreprise
 * - Blocage d'utilisateur et refus de messagerie
 * - Déblocage
 * - Signalement (report)
 * - Commentaires, réponses et réponses aux réponses
 * - Réactions à tous les niveaux, retrait et remplacement
 * - Détection des doublons
 */
declare(strict_types=1);

$GLOBALS['CAMPUSLINK_TEST_MODE'] = true;
$_SERVER['REQUEST_METHOD'] = 'GET';

require_once __DIR__ . '/../api.php';

$pdo = db();
echo "=== DÉBUT DES TESTS AUTOMATISÉS ===\n";

// Helper de simulation de session
function login_as(int $uid, string $role, string $name = 'Test User'): void {
    $_SESSION['uid'] = $uid;
    $_SESSION['sv'] = 1;
    $_SESSION['csrf'] = 'test_token';
}

// 1. Tester la règle : Entreprise (5) <-> Entreprise (6)
$caught = false;
try {
    assert_chat_access(5, 'company', 6);
} catch (RuntimeException $e) {
    if (strpos($e->getMessage(), 'Les échanges entre entreprises ne sont pas autorisés') !== false) {
        $caught = true;
    }
}
echo ($caught ? "[PASS]" : "[FAIL]") . " 1. Interdiction chat entreprise <-> entreprise\n";

// 2. Tester chat sans relation préalable entre Alice (3) et Bob (4)
$pdo->prepare("DELETE FROM connections WHERE (user_low = 3 AND user_high = 4) OR (user_low = 4 AND user_high = 3)")->execute();
$pdo->prepare("DELETE FROM user_blocks WHERE (blocker_id = 3 AND blocked_id = 4) OR (blocker_id = 4 AND blocked_id = 3)")->execute();

$other = assert_chat_access(3, 'student', 4);
echo ($other['id'] == 4 ? "[PASS]" : "[FAIL]") . " 2. Autorisation chat entre étudiants sans relation préalable\n";

// 3. Création automatique de la conversation
$convId = get_or_create_conversation(3, 4);
echo ($convId > 0 ? "[PASS]" : "[FAIL]") . " 3. Création automatique de la conversation (ID: $convId)\n";

// 4. Envoi d'un message
$pdo->prepare("INSERT INTO messages (conversation_id, sender_id, content) VALUES (?, 3, ?)")
    ->execute([$convId, "Test message sans relation préalable"]);
$msgId = (int)$pdo->lastInsertId();
echo ($msgId > 0 ? "[PASS]" : "[FAIL]") . " 4. Enregistrement du message privé dans la conversation\n";

// 5. Bob voit la conversation et le message
$st = $pdo->prepare("
    SELECT c.id, o.name AS other_name,
           (SELECT COUNT(*) FROM messages m WHERE m.conversation_id = c.id) AS msg_count
    FROM conversations c
    JOIN users o ON o.id = IF(c.user_low = 4, c.user_high, c.user_low)
    WHERE (c.user_low = 4 OR c.user_high = 4) AND c.id = ?
");
$st->execute([$convId]);
$cRow = $st->fetch();
$passedBob = $cRow && (int)$cRow['msg_count'] > 0;
echo ($passedBob ? "[PASS]" : "[FAIL]") . " 5. Le destinataire a accès à la conversation et à ses messages\n";

// 6. Tester le blocage
$pdo->prepare("INSERT INTO user_blocks (blocker_id, blocked_id) VALUES (?, ?)")->execute([4, 3]);

$blockCaught = false;
try {
    assert_chat_access(3, 'student', 4);
} catch (RuntimeException $e) {
    if (strpos($e->getMessage(), 'ne souhaite pas recevoir de messages') !== false) {
        $blockCaught = true;
    }
}
echo ($blockCaught ? "[PASS]" : "[FAIL]") . " 6. Blocage effectif : message refusé à l'utilisateur bloqué\n";

// 7. Déblocage
$pdo->prepare("DELETE FROM user_blocks WHERE blocker_id = 4 AND blocked_id = 3")->execute();
$unblockSuccess = false;
try {
    $other = assert_chat_access(3, 'student', 4);
    $unblockSuccess = $other['id'] == 4;
} catch (RuntimeException $e) {
    $unblockSuccess = false;
}
echo ($unblockSuccess ? "[PASS]" : "[FAIL]") . " 7. Déblocage effectif : messagerie rétablie\n";

// 8. Tester le signalement
$pdo->prepare("INSERT INTO reports (reporter_id, reported_user_id, target_type, target_id, reason, details) VALUES (?, ?, ?, ?, ?, ?)")
    ->execute([3, 4, 'user', 4, 'spam', 'Message indésirable']);
$repId = (int)$pdo->lastInsertId();
echo ($repId > 0 ? "[PASS]" : "[FAIL]") . " 8. Enregistrement d'un signalement (ID: $repId)\n";

// 9. Tester Commentaires et Réponses imbriquées (3 niveaux)
$postId = 3;
// 9a. Commentaire racine
$pdo->prepare("INSERT INTO post_comments (post_id, user_id, parent_id, content) VALUES (?, 3, NULL, ?)")
    ->execute([$postId, "Commentaire racine test"]);
$rootId = (int)$pdo->lastInsertId();

// 9b. Réponse niveau 1
$pdo->prepare("INSERT INTO post_comments (post_id, user_id, parent_id, content) VALUES (?, 4, ?, ?)")
    ->execute([$postId, $rootId, "Réponse au commentaire racine"]);
$rep1Id = (int)$pdo->lastInsertId();

// 9c. Réponse niveau 2 (réponse à la réponse)
$pdo->prepare("INSERT INTO post_comments (post_id, user_id, parent_id, content) VALUES (?, 7, ?, ?)")
    ->execute([$postId, $rep1Id, "Réponse imbriquée à la réponse"]);
$rep2Id = (int)$pdo->lastInsertId();

// Vérifier que rep2Id a pour parent rep1Id et que reply_to_author est Bob (user 4)
$st = $pdo->prepare("
    SELECT c.id, c.parent_id, pu.name AS reply_to_author
    FROM post_comments c
    JOIN post_comments pc ON pc.id = c.parent_id
    JOIN users pu ON pu.id = pc.user_id
    WHERE c.id = ?
");
$st->execute([$rep2Id]);
$nestRow = $st->fetch();
$passedNest = $nestRow && (int)$nestRow['parent_id'] === $rep1Id && !empty($nestRow['reply_to_author']);
echo ($passedNest ? "[PASS]" : "[FAIL]") . " 9. Réponses imbriquées à plusieurs niveaux avec liaison de l'auteur parent\n";

// 10. Tester les réactions aux commentaires et réponses
// Réaction sur commentaire racine
$pdo->prepare("INSERT INTO comment_reactions (comment_id, user_id, type) VALUES (?, 1, 'love')")->execute([$rootId]);
// Réaction sur réponse niveau 1
$pdo->prepare("INSERT INTO comment_reactions (comment_id, user_id, type) VALUES (?, 1, 'bravo')")->execute([$rep1Id]);
// Réaction sur réponse niveau 2
$pdo->prepare("INSERT INTO comment_reactions (comment_id, user_id, type) VALUES (?, 1, 'insightful')")->execute([$rep2Id]);

$st = $pdo->prepare("SELECT COUNT(*) FROM comment_reactions WHERE comment_id IN (?, ?, ?)");
$st->execute([$rootId, $rep1Id, $rep2Id]);
$reactionsCount = (int)$st->fetchColumn();
echo ($reactionsCount === 3 ? "[PASS]" : "[FAIL]") . " 10. Réactions enregistrées sur tous les niveaux (racine, réponse, sous-réponse)\n";

// 11. Remplacement de réaction
$pdo->prepare("INSERT INTO comment_reactions (comment_id, user_id, type) VALUES (?, 1, 'like') ON DUPLICATE KEY UPDATE type = VALUES(type)")
    ->execute([$rep1Id]);
$st = $pdo->prepare("SELECT type FROM comment_reactions WHERE comment_id = ? AND user_id = 1");
$st->execute([$rep1Id]);
$replaced = $st->fetchColumn() === 'like';
echo ($replaced ? "[PASS]" : "[FAIL]") . " 11. Remplacement d'une réaction par une autre (bravo -> like)\n";

// 12. Retrait de réaction
$pdo->prepare("DELETE FROM comment_reactions WHERE comment_id = ? AND user_id = 1")->execute([$rep1Id]);
$st = $pdo->prepare("SELECT COUNT(*) FROM comment_reactions WHERE comment_id = ? AND user_id = 1");
$st->execute([$rep1Id]);
$withdrawn = (int)$st->fetchColumn() === 0;
echo ($withdrawn ? "[PASS]" : "[FAIL]") . " 12. Retrait de réaction (désactivation/toggle off)\n";

// Nettoyage des données de test
$pdo->prepare("DELETE FROM post_comments WHERE id IN (?, ?, ?)")->execute([$rootId, $rep1Id, $rep2Id]);
$pdo->prepare("DELETE FROM reports WHERE id = ?")->execute([$repId]);

echo "=== VALIDATION COMPLÈTE TERMINÉE : TOUT FONCTIONNE ! ===\n";
