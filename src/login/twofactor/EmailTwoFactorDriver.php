<?php
declare(strict_types=1);

namespace wise\login\twofactor;


use wise\support\context\ContextualLogger;
/**
 * 邮件双因素认证驱动＼�
 *
 * 通过 wise-notification 包的 EmailChannel 发送 6 位数字验证码到用户邮箱。
 * 验证码 5 分钟有效，3 次尝试机会。
 *
 * 依赖：wiseadmin/wise-notification 包
 *
 * 配置：config('wise-auth.login.two_factor.email')
 *   - code_ttl: 验证码有效期（默认 300 秒）
 *   - code_length: 验证码长度（默认 6 位）
 *   - max_attempts: 最大尝试验证次数（默认 3）
 *   - resend_cooldown: 重发冷却时间（默认 60 秒）
 *   - cache_prefix: 缓存键前缀
 *
 * NOTIFIABLE 要求：用户的 TotpUserInterface 需同时实现 Notifiable 接口，
 * routeNotificationFor('email') 返回邮箱地址。
 * 如果不实现 Notifiable，通过 $target 参数传入邮箱地址。
 */
class EmailTwoFactorDriver implements TwoFactorDriverInterface
{
    use TwoFactorCodeTrait;

    protected int $codeTtl;
    protected int $codeLength;
    protected int $maxAttempts;
    protected int $resendCooldown;
    protected string $cachePrefix;

    public function __construct()
    {
        $cfg = (array) config('wise-auth.login.two_factor.email', []);
        $this->codeTtl = (int) ($cfg['code_ttl'] ?? 300);
        $this->codeLength = (int) ($cfg['code_length'] ?? 6);
        $this->maxAttempts = (int) ($cfg['max_attempts'] ?? 3);
        $this->resendCooldown = (int) ($cfg['resend_cooldown'] ?? 60);
        $this->cachePrefix = (string) ($cfg['cache_prefix'] ?? 'wise_login_security:2fa_email:');
    }

    public function getName(): string
    {
        return 'email';
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
        return '邮箱';
    }

    protected function dispatchCode(string $to, string $code): bool
    {
        try {
            if (class_exists(\wise\notification\facade\Notification::class)) {
                $notifiable = new class($to) implements \wise\notification\contract\Notifiable {
                    public function __construct(private string $email) {}
                    public function routeNotificationFor(string $channel): string|array
                    {
                        return $channel === 'email' ? $this->email : '';
                    }
                    public function wantsNotification(string $channel, ?string $type = null): bool { return true; }
                    public function quietHours(): ?array { return null; }
                    public function maxDailyNotifications(string $channel): ?int { return null; }
                    public function getNotifiableId(): string { return $this->email; }
                    public function getNotifiableType(): string { return 'user'; }
                };

                $message = new \wise\notification\contract\Message(
                    title: '登录验证码',
                    content: "<p>您的登录验证码：<strong style='font-size:24px'>{$code}</strong></p><p>有效期 5 分钟，请勿泄露。</p>",
                    data: [
                        'type'     => 'verify_code',
                        'alt_body' => "您的登录验证码：{$code}，有效期 5 分钟，请勿泄露。",
                    ]
                );

                $result = \wise\notification\facade\Notification::channel('email')
                    ->sync()
                    ->send($notifiable, $message);

                return $result && $result->success;
            }

            $subject = '=?UTF-8?B?' . base64_encode('登录验证码') . '?=';
            $body = "您的登录验证码：{$code}，有效期 5 分钟。";
            $headers = "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n";
            return @mail($to, $subject, $body, $headers);
        } catch (\Throwable $e) {
            $logChannel = config('wise-auth.login.two_factor.log_channel', 'wise_login_security');
            ContextualLogger::channel($logChannel)->error("Email 2FA send failed: {$e->getMessage()}");
            return false;
        }
    }
}
