<?php
declare(strict_types=1);

namespace wise\login\listener;

use wise\support\context\ContextualLogger;
use wise\login\event\LoginEvent;

/**
 * 新设备登录邮件提醒监听器＼�
 *
 * 当检测到新设备登录时，通过 wise-notification 发送邮件提醒用户。
 *
 * 依赖：wiseadmin/wise-notification 包
 * 配置：config('wise-auth.login.events.new_device_email')
 *   - enabled: 是否启用（默认 true）
 *   - email_field: 接收邮件的字段或方法名（默认 'email'）
 *   - subject: 邮件主题模板（默认 "新设备登录提醒 - {app_name}"）
 *   - notify_admin: 是否抄送管理员（默认 false）
 *   - admin_email: 管理员邮箱
 *
 * 注册方式（在 app/event.php 中）：
 *   'listen' => [
 *       \wise\login\event\LoginEvent::class => [
 *           \wise\login\listener\NewDeviceMailListener::class,
 *       ],
 *   ];
 *   或在 Service::boot() 中注册：
 *   $this->app->event->listen(LoginEvent::class, NewDeviceMailListener::class);
 *
 * 要求：用户模型需实现 routeNotificationFor('email') 方法（如使用 NotifiableTrait）。
 *   如果不使用 wise-notification，降级为 PHP mail()。
 */
class NewDeviceMailListener
{
    use MailSenderTrait;

    /**
     * @param LoginEvent $event
     */
    public function handle(LoginEvent $event): void
    {
        if ($event->eventType !== LoginEvent::TYPE_DEVICE_NEW) {
            return;
        }

        $cfg = $this->config();
        if (!($cfg['enabled'] ?? true)) {
            return;
        }

        $user = $this->resolveUserFromEvent($event, $cfg);
        $username = $event->username;
        if (!$username && $user !== null) {
            $usernameField = (string) ($cfg['username_field']
                ?? config('wise-auth.login.events.username_field', 'username'));
            $username = (string) ($user->$usernameField ?? '');
        }
        $username = $username ?: 'unknown';

        $ip = $event->ip ?? 'unknown';
        $ua = $event->userAgent ?? 'unknown';
        $deviceName = $event->data['device_name'] ?? $this->parseDeviceName($ua);
        $timestamp = date('Y-m-d H:i:s');

        $email = $this->resolveEmailFromEvent($event, $cfg);

        if (empty($email)) {
            ContextualLogger::info('[NewDeviceMailListener] 无法获取用户邮箱，跳过发送', [
                'username' => $username,
            ]);
            return;
        }

        $subject = $this->renderSubject($cfg, $username);
        $htmlBody = $this->buildHtmlBody($username, $ip, $deviceName, $timestamp, $ua);

        $this->sendEmail($email, $subject, $htmlBody);
    }

    /**
     * 渲染邮件主题
     */
    protected function renderSubject(array $cfg, string $username): string
    {
        $template = (string) ($cfg['subject'] ?? '新设备登录提醒 - {site_domain}');

        $siteDomain = $this->resolveSiteDomain();

        $subject = str_replace(
            ['{site_domain}', '{app_name}', '{username}'],
            [$siteDomain, $siteDomain, $username],
            $template
        );

        return trim(preg_replace('/[\s\-|·]+$/u', '', $subject) ?? $subject);
    }

    /**
     * 构建 HTML 邮件内容
     */
    protected function buildHtmlBody(
        string $username,
        string $ip,
        string $deviceName,
        string $timestamp,
        string $ua
    ): string {
        $safeUsername = htmlspecialchars($username, ENT_QUOTES, 'UTF-8');
        $safeIp = htmlspecialchars($ip, ENT_QUOTES, 'UTF-8');
        $safeDeviceName = htmlspecialchars($deviceName, ENT_QUOTES, 'UTF-8');
        $safeTimestamp = htmlspecialchars($timestamp, ENT_QUOTES, 'UTF-8');

        $safeDomain = htmlspecialchars($this->resolveSiteDomain(), ENT_QUOTES, 'UTF-8');
        $intro = $safeDomain !== ''
            ? "您的 <strong>{$safeDomain}</strong> 账号检测到新设备登录："
            : '您的账号检测到新设备登录：';

        return <<<HTML
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: Arial, sans-serif; padding: 20px; background: #f5f5f5;">
<div style="max-width: 600px; margin: 0 auto; background: #fff; border-radius: 8px; padding: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
    <h2 style="color: #333; margin-top: 0;">🔔 新设备登录提醒</h2>
    <p style="color: #666;">{$intro}</p>
    <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
        <tr><td style="padding: 8px; border: 1px solid #eee; background: #fafafa; width: 100px;">账号</td><td style="padding: 8px; border: 1px solid #eee;"><strong>{$safeUsername}</strong></td></tr>
        <tr><td style="padding: 8px; border: 1px solid #eee; background: #fafafa;">IP 地址</td><td style="padding: 8px; border: 1px solid #eee;">{$safeIp}</td></tr>
        <tr><td style="padding: 8px; border: 1px solid #eee; background: #fafafa;">设备</td><td style="padding: 8px; border: 1px solid #eee;">{$safeDeviceName}</td></tr>
        <tr><td style="padding: 8px; border: 1px solid #eee; background: #fafafa;">时间</td><td style="padding: 8px; border: 1px solid #eee;">{$safeTimestamp}</td></tr>
    </table>
    <p style="color: #e74c3c; font-size: 14px;">如果这不是您本人的操作，请立即修改密码并联系管理员。</p>
    <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
    <p style="color: #999; font-size: 12px;">此邮件由系统自动发送，请勿回复。</p>
</div>
</body>
</html>
HTML;
    }

    /**
     * 从 UA 解析设备名称
     */
    protected function parseDeviceName(string $ua): string
    {
        if (str_contains($ua, 'Windows NT')) {
            return 'Windows PC';
        }
        if (str_contains($ua, 'Macintosh')) {
            return 'Mac';
        }
        if (str_contains($ua, 'iPhone') || str_contains($ua, 'iPad')) {
            return 'iOS 设备';
        }
        if (str_contains($ua, 'Android')) {
            if (str_contains($ua, 'Mobile')) {
                return 'Android 手机';
            }
            return 'Android 设备';
        }
        if (str_contains($ua, 'Linux')) {
            return 'Linux';
        }
        return '未知设备';
    }

    protected function config(): array
    {
        return (array) config('wise-auth.login.events.new_device_email', []);
    }
}
