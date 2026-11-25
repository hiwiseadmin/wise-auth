<?php
declare(strict_types=1);

namespace wise\login\totp;

use think\facade\Cache;
use wise\login\contract\TotpUserInterface;
use wise\login\exception\BackupCodeInvalidException;
use wise\support\rate\AtomicCounter;

/**
 * 备份码管理器
 *
 * 备份码一次性使用，每个 8 位 Base32 字符（去除易混字符）
 * 存储：sha256 哈希后存于 user.getBackupCodes()
 */
class BackupCodeManager
{
    public function __construct(protected int $count = 10, protected int $codeLength = 8)
    {
    }

    /**
     * 生成新备份码集合
     *
     * @return array{plain: string[], hashed: array<string,bool>}
     */
    public function generate(): array
    {
        $plain = [];
        $hashed = [];
        for ($i = 0; $i < $this->count; $i++) {
            $code = $this->randomCode();
            $plain[] = $code;
            $hashed[$this->hash($code)] = true;
        }
        return ['plain' => $plain, 'hashed' => $hashed];
    }

    /**
     * 验证并消费备份码
     *
     *   - consume() 调用前自动检查冷却状态
     *   - 每次验证失败递增失败计数器
     *   - 超过 max_attempts 后触发 cooldown，后续请求直接拒绝
     *
     * @param TotpUserInterface $user  用户接口
     * @param string            $input 用户输入的备份码
     * @return bool 是否验证通过
     * @throws BackupCodeInvalidException 被速率限制封锁时抛出
     */
    public function consume(TotpUserInterface $user, string $input): bool
    {
        $this->checkRateLimit($user);

        $input = strtoupper(preg_replace('/\s+/', '', $input) ?? '');
        if ($input === '') {
            $this->recordRateLimitFailure($user);
            return false;
        }
        $hash = $this->hash($input);
        $codes = $user->getBackupCodes();
        if (!isset($codes[$hash])) {
            $this->recordRateLimitFailure($user);
            return false;
        }
        unset($codes[$hash]);
        $user->setBackupCodes($codes);

        if (method_exists($user, 'saveTotpConfig')) {
            $user->saveTotpConfig();
        }

        $this->resetRateLimit($user);
        return true;
    }

    /**
     * 强制校验（不消费），用于调试
     *
     * 注意：isValid() 不受速率限制（仅用于调试/管理场景）
     */
    public function isValid(TotpUserInterface $user, string $input): bool
    {
        $input = strtoupper(preg_replace('/\s+/', '', $input) ?? '');
        if ($input === '') {
            return false;
        }
        return isset($user->getBackupCodes()[$this->hash($input)]);
    }

    public function remainingCount(TotpUserInterface $user): int
    {
        return count($user->getBackupCodes());
    }

    /**
     * @param TotpUserInterface $user
     * @throws BackupCodeInvalidException 如果已触发冷却
     */
    public function checkRateLimit(TotpUserInterface $user): void
    {
        $cfg = $this->rateLimitConfig();
        if (!($cfg['enabled'] ?? true)) {
            return;
        }

        $cooldownKey = $this->rateLimitKey($user, 'cooldown');
        $cooldownUntil = Cache::get($cooldownKey);
        if ($cooldownUntil !== null) {
            $retryAfter = max(1, (int) $cooldownUntil - time());
            throw new BackupCodeInvalidException(
                sprintf('备份码验证尝试次数过多，请在 %d 秒后重试', $retryAfter),
                ['retry_after' => $retryAfter, 'rate_limited' => true]
            );
        }
    }

    /**
     * 使用滑动窗口计数，超过阈值后触发冷却期
     */
    public function recordRateLimitFailure(TotpUserInterface $user): void
    {
        $cfg = $this->rateLimitConfig();
        if (!($cfg['enabled'] ?? true)) {
            return;
        }

        $attemptsKey = $this->rateLimitKey($user, 'attempts');
        $windowMinutes = (int) ($cfg['window_minutes'] ?? 5);
        $maxAttempts = (int) ($cfg['max_attempts'] ?? 3);
        $cooldownMinutes = (int) ($cfg['cooldown_minutes'] ?? 30);

        $attempts = AtomicCounter::increment($attemptsKey, $windowMinutes * 60, 'BackupCodeManager');

        if ($attempts >= $maxAttempts) {
            $cooldownKey = $this->rateLimitKey($user, 'cooldown');
            $cooldownUntil = time() + $cooldownMinutes * 60;
            Cache::set($cooldownKey, $cooldownUntil, $cooldownMinutes * 60);
            Cache::delete($attemptsKey);
        }
    }

    public function resetRateLimit(TotpUserInterface $user): void
    {
        $cfg = $this->rateLimitConfig();
        if (!($cfg['enabled'] ?? true)) {
            return;
        }

        Cache::delete($this->rateLimitKey($user, 'attempts'));
        Cache::delete($this->rateLimitKey($user, 'cooldown'));
    }

    /**
     * 获取当前用户剩余可尝试次数
     */
    public function getRemainingAttempts(TotpUserInterface $user): int
    {
        $cfg = $this->rateLimitConfig();
        if (!($cfg['enabled'] ?? true)) {
            return PHP_INT_MAX;
        }

        $maxAttempts = (int) ($cfg['max_attempts'] ?? 3);
        $attemptsKey = $this->rateLimitKey($user, 'attempts');
        $current = (int) Cache::get($attemptsKey, 0);
        return max(0, $maxAttempts - $current);
    }

    /**
     * sha256 哈希
     */
    public function hash(string $code): string
    {
        return hash('sha256', strtoupper($code));
    }

    /**
     * 生成单条备份码（8 位 Base32，去除易混字符 0/O/1/I）
     */
    protected function randomCode(): string
    {
        $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
        $code = '';
        $max = strlen($alphabet) - 1;
        for ($i = 0; $i < $this->codeLength; $i++) {
            $code .= $alphabet[random_int(0, $max)];
        }
        return $code;
    }

    /**
     * 速率限制存储键
     *
     * @param TotpUserInterface $user
     * @param string            $subKey 子键（attempts / cooldown）
     * @return string
     */
    protected function rateLimitKey(TotpUserInterface $user, string $subKey): string
    {
        $cfg = $this->rateLimitConfig();
        $prefix = $cfg['cache_prefix'] ?? 'wise_login_security:backup_rate:';
        $userType = method_exists($user, 'getTotpUserType') ? $user->getTotpUserType() : 'user';
        if (method_exists($user, 'getTotpUserId')) {
            $userId = $user->getTotpUserId();
        } elseif (method_exists($user, 'getKey')) {
            $userId = $user->getKey();
        } else {
            $userId = method_exists($user, 'getTotpLabel') ? $user->getTotpLabel() : spl_object_id($user);
        }
        return $prefix . $userType . '|' . md5((string) $userId) . '|' . $subKey;
    }

    protected function rateLimitConfig(): array
    {
        return (array) config('wise-auth.login.two_factor.backup_codes_rate_limit', []);
    }
}
