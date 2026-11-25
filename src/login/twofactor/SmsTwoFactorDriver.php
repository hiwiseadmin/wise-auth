<?php
declare(strict_types=1);

namespace wise\login\twofactor;


use wise\support\context\ContextualLogger;
/**
 * 短信双因素认证驱动＼�
 *
 * 通过 wise-notification 包的 SmsChannel 发送 6 位数字验证码到用户手机。
 * 验证码 5 分钟有效，3 次尝试机会。
 *
 * 依赖：wiseadmin/wise-notification 包 + 阿里云/腾讯云短信 SDK
 *
 * 配置：config('wise-auth.login.two_factor.sms')
 *   - code_ttl: 验证码有效期（默认 300 秒）
 *   - code_length: 验证码长度（默认 6 位）
 *   - max_attempts: 最大尝试验证次数（默认 3）
 *   - resend_cooldown: 重发冷却时间（默认 60 秒）
 *   - template_code: 短信模板代码（对应 notification 的 template_map）
 *   - cache_prefix: 缓存键前缀
 */
class SmsTwoFactorDriver implements TwoFactorDriverInterface
{
    use TwoFactorCodeTrait;

    protected int $codeTtl;
    protected int $codeLength;
    protected int $maxAttempts;
    protected int $resendCooldown;
    protected string $templateCode;
    protected string $cachePrefix;

    public function __construct()
    {
        $cfg = (array) config('wise-auth.login.two_factor.sms', []);
        $this->codeTtl = (int) ($cfg['code_ttl'] ?? 300);
        $this->codeLength = (int) ($cfg['code_length'] ?? 6);
        $this->maxAttempts = (int) ($cfg['max_attempts'] ?? 3);
        $this->resendCooldown = (int) ($cfg['resend_cooldown'] ?? 60);
        $this->templateCode = (string) ($cfg['template_code'] ?? 'verify_code');
        $this->cachePrefix = (string) ($cfg['cache_prefix'] ?? 'wise_login_security:2fa_sms:');
    }

    public function getName(): string
    {
        return 'sms';
    }

    public function skipForTrustedDevice(): bool
    {
        return true;
    }

    public function codeTtl(): int
    {
        return $this->codeTtl;
    }

    public function codeLength(): int
    {
        return $this->codeLength;
    }

    protected function getTargetType(): string
    {
        return '短信';
    }

    protected function dispatchCode(string $target, string $code): bool
    {
        $target = $this->normalizePhone($target);
        return $this->dispatchSms($target, $code);
    }

    protected function normalizePhone(string $phone): string
    {
        $phone = preg_replace('/[\s\-\(\)]/', '', $phone);
        if (!str_starts_with($phone, '+') && !str_starts_with($phone, '0')) {
            $phone = '+86' . $phone;
        }
        return $phone;
    }

    /**
     * 通过 wise-notification 发送短信
     */
    protected function dispatchSms(string $phone, string $code): bool
    {
        try {
            if (class_exists(\wise\notification\facade\Notification::class)) {
                $notifiable = new class($phone) implements \wise\notification\contract\Notifiable {
                    public function __construct(private string $phone) {}
                    public function routeNotificationFor(string $channel): string|array
                    {
                        return $channel === 'sms' ? $this->phone : '';
                    }
                    public function wantsNotification(string $channel, ?string $type = null): bool { return true; }
                    public function quietHours(): ?array { return null; }
                    public function maxDailyNotifications(string $channel): ?int { return null; }
                    public function getNotifiableId(): string { return $this->phone; }
                    public function getNotifiableType(): string { return 'user'; }
                };

                $message = new \wise\notification\contract\Message(
                    data: [
                        'type' => $this->templateCode,
                        'code' => $code,
                    ]
                );

                $result = \wise\notification\facade\Notification::channel('sms')
                    ->sync()
                    ->send($notifiable, $message);

                return $result && $result->success;
            }

            return false;
        } catch (\Throwable $e) {
            $logChannel = config('wise-auth.login.two_factor.log_channel', 'wise_login_security');
            ContextualLogger::channel($logChannel)->error("SMS 2FA send failed: {$e->getMessage()}");
            return false;
        }
    }
}
