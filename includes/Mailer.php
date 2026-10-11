<?php
/**
 * Petit client SMTP sans dépendance (STARTTLS / SSL, AUTH LOGIN).
 * Mode "log" : n'envoie RIEN, écrit le message dans un fichier (développement uniquement).
 */
class Mailer
{
    private array $cfg;
    private string $logFile;

    public function __construct(array $mailCfg, string $storageDir)
    {
        $this->cfg = $mailCfg;
        $this->logFile = $storageDir . '/mails.log';
    }

    public function isReal(): bool
    {
        return ($this->cfg['mode'] ?? 'log') === 'smtp';
    }

    /** @return bool true si le serveur SMTP a accepté le message (ou, en mode log, s'il a été écrit) */
    public function send(string $to, string $subject, string $text, string $html): bool
    {
        $fromEmail = $this->cfg['from_email'] ?? 'no-reply@localhost';
        $fromName  = $this->cfg['from_name'] ?? 'CampusLink';
        $boundary  = 'b' . bin2hex(random_bytes(12));
        $domain    = substr(strrchr($fromEmail, '@') ?: '@localhost', 1);

        $headers = [
            'Date: ' . date('r'),
            'From: ' . $this->encodeHeader($fromName) . " <$fromEmail>",
            "To: <$to>",
            'Subject: ' . $this->encodeHeader($subject),
            'Message-ID: <' . bin2hex(random_bytes(10)) . "@$domain>",
            'MIME-Version: 1.0',
            "Content-Type: multipart/alternative; boundary=\"$boundary\"",
        ];
        $body = "--$boundary\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n"
            . chunk_split(base64_encode($text))
            . "--$boundary\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n"
            . chunk_split(base64_encode($html))
            . "--$boundary--\r\n";
        $data = implode("\r\n", $headers) . "\r\n\r\n" . $body;

        if (!$this->isReal()) {
            $entry = "==== " . date('c') . " (MODE LOG : message NON envoyé) ====\nTo: $to\nSubject: $subject\n\n$text\n\n";
            return @file_put_contents($this->logFile, $entry, FILE_APPEND | LOCK_EX) !== false;
        }
        try {
            return $this->smtpSend($fromEmail, $to, $data);
        } catch (Throwable $e) {
            error_log('[CampusLink SMTP] ' . $e->getMessage());
            return false;
        }
    }

    private function encodeHeader(string $s): string
    {
        return preg_match('/[^\x20-\x7e]/', $s) ? '=?UTF-8?B?' . base64_encode($s) . '?=' : $s;
    }

    private function smtpSend(string $from, string $to, string $data): bool
    {
        $host = $this->cfg['host']; $port = (int)($this->cfg['port'] ?? 587);
        $enc  = $this->cfg['encryption'] ?? 'tls';
        $ctx  = stream_context_create(['ssl' => ['verify_peer' => true, 'verify_peer_name' => true]]);
        $remote = ($enc === 'ssl' ? 'ssl://' : 'tcp://') . $host . ':' . $port;
        $fp = @stream_socket_client($remote, $errno, $errstr, 15, STREAM_CLIENT_CONNECT, $ctx);
        if (!$fp) throw new RuntimeException("Connexion SMTP impossible ($errstr)");
        stream_set_timeout($fp, 15);

        $this->expect($fp, [220]);
        $ehlo = $_SERVER['SERVER_NAME'] ?? 'localhost';
        $this->cmd($fp, "EHLO $ehlo", [250]);
        if ($enc === 'tls') {
            $this->cmd($fp, 'STARTTLS', [220]);
            if (!stream_socket_enable_crypto($fp, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
                throw new RuntimeException('Échec STARTTLS');
            }
            $this->cmd($fp, "EHLO $ehlo", [250]);
        }
        if (!empty($this->cfg['username'])) {
            $this->cmd($fp, 'AUTH LOGIN', [334]);
            $this->cmd($fp, base64_encode($this->cfg['username']), [334]);
            $this->cmd($fp, base64_encode($this->cfg['password'] ?? ''), [235]);
        }
        $this->cmd($fp, "MAIL FROM:<$from>", [250]);
        $this->cmd($fp, "RCPT TO:<$to>", [250, 251]);
        $this->cmd($fp, 'DATA', [354]);
        $data = preg_replace('/^\./m', '..', $data);   // dot-stuffing
        fwrite($fp, $data . "\r\n.\r\n");
        $this->expect($fp, [250]);
        $this->cmd($fp, 'QUIT', [221]);
        fclose($fp);
        return true;
    }

    private function cmd($fp, string $line, array $ok): string
    {
        fwrite($fp, $line . "\r\n");
        return $this->expect($fp, $ok);
    }

    private function expect($fp, array $ok): string
    {
        $resp = '';
        while (($l = fgets($fp, 515)) !== false) {
            $resp .= $l;
            if (strlen($l) < 4 || $l[3] === ' ') break;
        }
        if (!in_array((int)substr($resp, 0, 3), $ok, true)) {
            throw new RuntimeException('Réponse SMTP inattendue : ' . trim($resp));
        }
        return $resp;
    }
}
