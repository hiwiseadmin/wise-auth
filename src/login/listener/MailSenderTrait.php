<?php
declare(strict_types=1);

namespace wise\login\listener;

use wise\support\context\ContextualLogger;
use wise\login\event\LoginEvent;

/**
 * 邮件发送共享逻辑 Trait
 *
 * 为 LockedAccountMailListener 和 NewDeviceMailListener 提供统一的
 * 用户邮箱解析、wise-notification 发送、PHP mail 降级、MIME 编码能力。
 */
trait MailSenderTrait
{
    /**
     * 解析事件关联的用户对象
     *
     * 优先 data['user']；否则按 data['user_id']（主键）或事件 username
     * 反查 config('wise-auth.login.events.user_model') 指定的用户模型。
     * 未配置/类不存在/查不到记录时返回 null（调用方跳过对应逻辑，不影响主流程）。
     */
    protected function resolveUserFromEvent(LoginEvent $event, array $cfg): ?object
    {
        if (!empty($event->data['user']) && is_object($event->data['user'])) {
            return $event->data['user'];
        }

        $model = $cfg['user_model'] ?? config('wise-auth.login.events.user_model');
        if (!is_string($model) || $model === '' || !class_exists($model)) {
            return null;
        }

        try {
            if (!empty($event->data['user_id'])) {
                $user = $model::find((int) $event->data['user_id']);
                if (is_object($user)) {
                    return $user;
                }
            }

            if (!empty($event->username)) {
                $usernameField = (string) ($cfg['username_field']
                    ?? config('wise-auth.login.events.username_field', 'username'));
                $user = $model::where($usernameField, (string) $event->username)->find();
                if (is_object($user)) {
                    return $user;
                }
            }
        } catch (\Throwable $e) {
            ContextualLogger::warning('[' . static::class . '] 反查用户失败', [
                'model'    => $model,
                'username' => $event->username,
                'error'    => $e->getMessage(),
            ]);
        }

        return null;
    }

    /**
     * 从事件数据中解析用户邮箱
     *
     * 解析顺序：
     *  1. 事件 data 中直接携带的 email_field；
     *  2. 事件关联用户对象上的 email_field（方法优先，其次属性）；
     *  3. 事件未携带用户对象时，由 resolveUserFromEvent() 按 user_id / username 反查。
     *
     * 均无法解析时返回空串（调用方跳过发送，不影响主流程）。
     */
    protected function resolveEmailFromEvent(LoginEvent $event, array $cfg): string
    {
        $field = $cfg['email_field'] ?? 'email';

        if (isset($event->data[$field]) && !empty($event->data[$field])) {
            return (string) $event->data[$field];
        }

        $user = $this->resolveUserFromEvent($event, $cfg);
        if ($user === null) {
            return '';
        }

        if (method_exists($user, $field)) {
            return (string) $user->$field();
        }

        $email = $user->$field ?? '';

        return is_string($email) ? $email : '';
    }

    /**
     * 解析"本站标识"，用于安全通知邮件中区分是哪个系统
     *
     * 取域名的理由：同一运维方可能部署多套后台，收件人看到
     * `admin-a.example.com` 才能立刻判断是哪套系统；而 `app_name`
     * 往往各系统相同，起不到区分作用，且属宿主业务配置。
     *
     * 优先级：包内 `wise-login-security.site_domain` → 当前请求 Host → 空串
     * （空串时调用方省略该信息，不留占位符）。
     */
    protected function resolveSiteDomain(): string
    {
        $domain = trim((string) config('wise-auth.login.site_domain', ''));
        if ($domain !== '') {
            return $domain;
        }

        try {
            return trim((string) app('request')->host());
        } catch (\Throwable) {
            return '';
        }
    }

    /**
     * 发送邮件（优先使用 wise-notification，降级 PHP mail）
     */
    protected function sendEmail(string $to, string $subject, string $htmlBody): void
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
                    title: $subject,
                    content: $htmlBody,
                    data: [
                        'type'     => 'security',
                        'alt_body' => strip_tags(str_replace(['<br>', '</p>', '</tr>'], ["\n", "\n\n", "\n"], $htmlBody)),
                    ]
                );

                \wise\notification\facade\Notification::channel('email')
                    ->sync()
                    ->send($notifiable, $message);

                ContextualLogger::info('[' . static::class . '] 邮件已发送', ['to' => $to]);
                return;
            }
        } catch (\Throwable $e) {
            ContextualLogger::error('[' . static::class . '] wise-notification 发送失败，降级 PHP mail: ' . $e->getMessage());
        }

        $headers = implode("\r\n", [
            'MIME-Version: 1.0',
            'Content-Type: text/html; charset=UTF-8',
            'From: noreply@example.com',
        ]);

        if (@mail($to, '=?UTF-8?B?' . base64_encode($subject) . '?=', $htmlBody, $headers)) {
            ContextualLogger::info('[' . static::class . '] 邮件已发送（PHP mail 降级）', ['to' => $to]);
        } else {
            ContextualLogger::error('[' . static::class . '] 邮件发送失败', ['to' => $to]);
        }
    }

}
