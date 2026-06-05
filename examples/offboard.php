<?php
/**
 * Example PHP wrapper that offboards a Microsoft 365 user by invoking the
 * Invoke-M365Offboarding.ps1 script in unattended mode and returning the
 * structured audit.json result.
 *
 * Run on a Windows host that has PowerShell, the required modules, and the
 * app-registration certificate installed. Call this only from authenticated,
 * authorized, server-side code with a recorded approval. See docs/INTEGRATION.md.
 */

declare(strict_types=1);

function offboardUser(string $upn): array
{
    // Allowlist the UPN format. Never interpolate raw input into a command.
    if (!preg_match('/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$/', $upn)) {
        throw new InvalidArgumentException('Invalid UPN');
    }

    $scriptPath = 'C:\\Tools\\Invoke-M365Offboarding.ps1';
    $auditRoot  = 'C:\\Audits';
    $jsonOut    = $auditRoot . '\\' . preg_replace('/[^A-Za-z0-9]/', '_', $upn) . '.json';

    // Secrets come from the environment or a secret store, never from the request.
    $args = [
        'powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', $scriptPath,
        '-Unattended', '-NoScreenshots',
        '-UserPrincipalName', $upn,
        '-AuditRoot', $auditRoot,
        '-JsonOutPath', $jsonOut,
        '-TenantId', getenv('M365_TENANT'),
        '-ClientId', getenv('M365_CLIENT_ID'),
        '-CertificateThumbprint', getenv('M365_CERT_THUMBPRINT'),
        '-Organization', getenv('M365_ORG'),
    ];

    // proc_open with an argument array avoids shell injection.
    $descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $proc = proc_open($args, $descriptors, $pipes);
    if (!is_resource($proc)) {
        throw new RuntimeException('Failed to start PowerShell');
    }
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    foreach ($pipes as $pipe) {
        fclose($pipe);
    }
    $exitCode = proc_close($proc);

    if (!is_file($jsonOut)) {
        throw new RuntimeException("No audit.json produced (exit $exitCode): $stderr");
    }

    $result = json_decode(file_get_contents($jsonOut), true, 512, JSON_THROW_ON_ERROR);
    $result['_exitCode'] = $exitCode;
    return $result;
}

// Example CLI usage: php offboard.php jdoe@contoso.com
if (PHP_SAPI === 'cli' && isset($argv[1])) {
    try {
        $result = offboardUser($argv[1]);
        echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), PHP_EOL;
        exit($result['success'] ? 0 : 1);
    } catch (Throwable $e) {
        fwrite(STDERR, 'Error: ' . $e->getMessage() . PHP_EOL);
        exit(2);
    }
}
