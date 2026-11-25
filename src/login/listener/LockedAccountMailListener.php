<?php
declare(strict_types=1);

namespace wise\login\listener;

use wise\support\context\ContextualLogger;
use wise\login\event\LoginEvent;

/**
 * 账户锁定邮件通知监听器＼�
 *
 * 当账户因多次登录失败被锁定时，通过 wise-notification 发送邮件通知用户。
 * 同时告知锁定持续时间和剩余解锁时间。
 *
 * 依赖：wiseadmin/wise-notification 包
 *
 * 配置：config('wise-auth.login.events.lock_notify')
 *   - enabled: 是否启用
 *   - email_field: 用户邮箱字段或 data key
 *   - subject: 邮件主题模板
 *   - app_name: 应用名称
 *
 * 注册方式（app/event.php）：
 *   'listen' => [
 *       \wise\login\event\LoginEvent::class => [
 *           \wise\login\listener\LockedAccountMailListener::class,
 *       ],
 *   ];
 */
class LockedAccountMailListener
{
    use MailSenderTrait;

    public function handle(LoginEvent $event): void
    {
        if ($event->eventType !== LoginEvent::TYPE_ACCOUNT_LOCKED) {
            return;
        }

        $cfg = $this->config();
        if (!($cfg['enabled'] ?? true)) {
            return;
        }

        $username = $event->username ?? 'unknown';
        $ip = $event->ip ?? 'unknown';
        $lockMinutes = array_key_exists('lock_minutes', $event->data) ? (int) $event->data['lock_minutes'] : null;
        $lockDuration = $lockMinutes !== null ? $this->formatDuration($lockMinutes) : '未知';
        $timestamp = date('Y-m-d H:i:s');
        $unlockTime = ($lockMinutes !== null && $lockMinutes > 0) ? date('Y-m-d H:i:s', time() + $lockMinutes * 60) : '手动解锁';

        $email = $this->resolveEmailFromEvent($event, $cfg);
        if (empty($email)) {
            ContextualLogger::info('[LockedAccountMailListener] 无法获取用户邮箱', ['username' => $username]);
            return;
        }

        $subject = $this->renderSubject($cfg, $username);
        $htmlBody = $this->buildHtmlBody($username, $ip, $lockDuration, $unlockTime, $timestamp);

        $this->sendEmail($email, $subject, $htmlBody);
    }

    protected function renderSubject(array $cfg, string $username): string
    {
        $template = (string) ($cfg['subject'] ?? '账户安全提醒 - {site_domain}');

        $siteDomain = $this->resolveSiteDomain();

        $subject = str_replace(
            ['{site_domain}', '{app_name}', '{username}'],
            [$siteDomain, $siteDomain, $username],
            $template
        );

        return trim(preg_replace('/[\s\-|·]+$/u', '', $subject) ?? $subject);
    }

    protected function buildHtmlBody(
        string $username,
        string $ip,
        string $lockDuration,
        string $unlockTime,
        string $timestamp
    ): string {
        $safeUsername = htmlspecialchars($username, ENT_QUOTES, 'UTF-8');
        $safeIp = htmlspecialchars($ip, ENT_QUOTES, 'UTF-8');
        $safeLockDuration = htmlspecialchars($lockDuration, ENT_QUOTES, 'UTF-8');
        $safeUnlockTime = htmlspecialchars($unlockTime, ENT_QUOTES, 'UTF-8');
        $safeTimestamp = htmlspecialchars($timestamp, ENT_QUOTES, 'UTF-8');

        $safeDomain = htmlspecialchars($this->resolveSiteDomain(), ENT_QUOTES, 'UTF-8');
        $intro = $safeDomain !== ''
            ? "您的 <strong>{$safeDomain}</strong> 账号因多次登录失败已被临时锁定："
            : '您的账号因多次登录失败已被临时锁定：';

        return <<<HTML
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: Arial, sans-serif; padding: 20px; background: #f5f5f5;">
<div style="max-width: 600px; margin: 0 auto; background: #fff; border-radius: 8px; padding: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
    <h2 style="color: #e74c3c; margin-top: 0;">⚠️ 账户已锁定</h2>
    <p style="color: #666;">{$intro}</p>
    <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
        <tr><td style="padding: 8px; border: 1px solid #eee; background: #fafafa; width: 100px;">账号</td><td style="padding: 8px; border: 1px solid #eee;"><strong>{$safeUsername}</strong></td></tr>
        <tr><td style="padding: 8px; border: 1px solid #eee; background: #fafafa;">来源 IP</td><td style="padding: 8px; border: 1px solid #eee;">{$safeIp}</td></tr>
        <tr><td style="padding: 8px; border: 1px solid #eee; background: #fafafa;">锁定时间</td><td style="padding: 8px; border: 1px solid #eee;">{$safeTimestamp}</td></tr>
        <tr><td style="padding: 8px; border: 1px solid #eee; background: #fafafa;">锁定时长</td><td style="padding: 8px; border: 1px solid #eee;">{$safeLockDuration}</td></tr>
        <tr><td style="padding: 8px; border: 1px solid #eee; background: #fafafa;">预计解锁</td><td style="padding: 8px; border: 1px solid #eee;">{$safeUnlockTime}</td></tr>
    </table>
    <p style="color: #e74c3c; font-size: 14px;">如果这不是您本人的操作，您的密码可能已被泄露，请在解锁后立即修改密码。</p>
    <p style="color: #666; font-size: 13px;">提示：如果遗忘密码，可使用"忘记密码"功能重置。</p>
    <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
    <p style="color: #999; font-size: 12px;">此邮件由系统自动发送，请勿回复。</p>
</div>
</body>
</html>
HTML;
    }

    protected function formatDuration(int $minutes): string
    {
        if ($minutes <= 0) {
            return '永久';
        }
        if ($minutes < 60) {
            return "{$minutes} 分钟";
        }
        $hours = floor($minutes / 60);
        $remain = $minutes % 60;
        if ($remain === 0) {
            return "{$hours} 小时";
        }
        return "{$hours} 小时 {$remain} 分钟";
    }

    protected function config(): array
    {
        return (array) config('wise-auth.login.events.lock_notify', []);
    }
}
