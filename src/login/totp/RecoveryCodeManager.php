<?php
declare(strict_types=1);

namespace wise\login\totp;

use think\facade\Cache;
use wise\login\contract\TotpUserInterface;
use wise\support\context\ContextualLogger;

/**
 * 恢复码管理器＼�
 *
 * 用户丢失 2FA 设备时，使用预先生成的恢复码来禁用 2FA 并重新设置。
 *
 * 与备份码的区别：
 *  - 备份码：替代 TOTP 完成当次登录，不改变 2FA 状态
 *  - 恢复码：一次性使用，验证后立即禁用 2FA，用户需重新设置
 *
 * 恢复码特性：
 *  - 16 位字母数字（4 组 × 4 位），便于手动输入
 *  - sha256 哈希存储
 *  - 一次性使用（验证后清除所有恢复码 + 禁用 2FA）
 *  - 生成数量：8 个（config('wise-auth.login.two_factor.recovery.count')）
 *
 * @see BackupCodeManager
 */
class RecoveryCodeManager
{
    protected int $count;
    protected int $codeLength;

    public function __construct()
    {
        $cfg = (array) config('wise-auth.login.two_factor.recovery', []);
        $this->count = (int) ($cfg['count'] ?? 8);
        $this->codeLength = (int) ($cfg['code_length'] ?? 16);
    }

    /**
     * 生成恢复码集合
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
     * 使用恢复码禁用 2FA
     *
     * 验证成功后：
     *  1. 清除所有恢复码
     *  2. 清除 TOTP 密钥
     *  3. 清除备份码
     *  4. 设置 TOTP 为禁用状态
     *
     * @param TotpUserInterface $user
     * @param string            $input 用户输入的恢复码
     * @return bool 是否验证成功
     */
    public function recover(TotpUserInterface $user, string $input): bool
    {
        $input = strtoupper(preg_replace('/[\s\-]/', '', (string) $input) ?? '');
        if ($input === '') {
            return false;
        }

        $hash = $this->hash($input);
        $codes = $user->getRecoveryCodes();
        if (!isset($codes[$hash])) {
            return false;
        }

        $user->setTotpEnabled(false);
        $user->setTotpSecret(null);
        $user->setBackupCodes([]);
        $user->setRecoveryCodes([]);

        if (method_exists($user, 'saveTotpConfig')) {
            $user->saveTotpConfig();
        }

        ContextualLogger::info('[RecoveryCodeManager] 2FA 已通过恢复码禁用', [
            'user' => $user->getTotpLabel(),
            'type' => $user->getTotpUserType(),
        ]);

        return true;
    }

    /**
     * 校验恢复码（不消费）
     */
    public function isValid(TotpUserInterface $user, string $input): bool
    {
        $input = strtoupper(preg_replace('/[\s\-]/', '', (string) $input) ?? '');
        if ($input === '') {
            return false;
        }
        return isset($user->getRecoveryCodes()[$this->hash($input)]);
    }

    /**
     * 剩余恢复码数量
     */
    public function remainingCount(TotpUserInterface $user): int
    {
        return count($user->getRecoveryCodes());
    }

    public function hash(string $code): string
    {
        return hash('sha256', strtoupper($code));
    }

    /**
     * 生成格式化恢复码（4×4 分组，如 "ABCD-EFGH-IJKL-MNOP"）
     */
    public static function format(string $code): string
    {
        return implode('-', str_split(strtoupper($code), 4));
    }

    /**
     * 生成单条恢复码（16 位字母数字，排除易混字符 0/O/1/I）
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
}
