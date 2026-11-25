<?php
declare(strict_types=1);

namespace wise\login\device;

use think\Request;
use wise\support\context\ContextualLogger;

/**
 * "记住此设备"辅助类＼�
 *
 * 用户首次完成 2FA 时可勾选"信任此设备"，
 * 后端签发加密 Cookie，后续 30 天内该设备跳过 2FA。
 *
 * Cookie Token 格式：
 *   base64($userId . '|' . $fingerprint . '|' . $expiry . '|' . $hmac)
 *
 * 安全机制：
 *  - HMAC-SHA256 签名防篡改
 *  - 设备指纹绑定（换设备自动失效）
 *  - 到期自动失效
 *  - HttpOnly + SameSite 防 XSS/CSRF
 */
class RememberDeviceHelper
{
    protected string $secret;
    protected string $cookieName;
    protected int $durationDays;

    public function __construct()
    {
        $cfg = (array) config('wise-auth.login.device_management', []);
        $this->durationDays = (int) ($cfg['trust_duration_days'] ?? 30);
        $this->cookieName = (string) ($cfg['remember_cookie_name'] ?? 'ws_remember_2fa');
        $this->secret = (string) ($cfg['fingerprint_salt'] ?? 'change-me-to-random-string');

        if ($this->secret === '' || $this->secret === 'change-me-to-random-string') {
            ContextualLogger::warning(
                'RememberDeviceHelper: 使用默认 HMAC 密钥不安全，请在配置 wise-login-security.device_management.fingerprint_salt 中设置随机字符串'
            );
        }
    }

    /**
     * 签发"记住此设备"Cookie
     *
     * @param int    $userId      用户 ID
     * @param string $fingerprint 设备指纹
     * @param int    $days        有效期天数（默认读取配置）
     * @return string Cookie 值
     */
    public function createToken(int $userId, string $fingerprint, ?int $days = null): string
    {
        $days = $days ?? $this->durationDays;
        $expiry = time() + $days * 86400;
        $payload = implode('|', [$userId, $fingerprint, $expiry]);
        $hmac = hash_hmac('sha256', $payload, $this->secret);
        return base64_encode("{$payload}|{$hmac}");
    }

    /**
     * 设置 Cookie（在 TwoFactorMiddleware 验证成功后调用）
     */
    public function setCookie(string $token, int $days): void
    {
        $this->writeCookie(function () use ($token, $days): void {
            \think\facade\Cookie::set($this->cookieName, $token, [
                'expire'   => $days * 86400,
                'path'     => '/',
                'httponly' => true,
                'secure'   => self::isHttps(),
                'samesite' => 'Lax',
            ]);
        });
    }

    /**
     * 验证"记住此设备"Cookie
     *
     * @param Request $request
     * @param int     $userId      当前登录用户 ID
     * @param string  $fingerprint 当前设备指纹
     * @return bool 是否有效
     */
    public function validate(Request $request, int $userId, string $fingerprint): bool
    {
        $token = $request->cookie($this->cookieName);
        if (empty($token)) {
            return false;
        }

        $decoded = base64_decode($token, true);
        if ($decoded === false) {
            return false;
        }

        $parts = explode('|', $decoded);
        if (count($parts) !== 4) {
            return false;
        }

        [$uid, $fp, $expiry, $hmac] = $parts;
        $payload = implode('|', [$uid, $fp, $expiry]);

        $expectedHmac = hash_hmac('sha256', $payload, $this->secret);
        if (!hash_equals($expectedHmac, $hmac)) {
            return false;
        }

        if ((int) $uid !== $userId) {
            return false;
        }

        if ($fp !== $fingerprint) {
            return false;
        }

        if ((int) $expiry < time()) {
            return false;
        }

        return true;
    }

    /**
     * 清除"记住此设备"Cookie（用户登出时调用）
     */
    public function clearCookie(): void
    {
        $this->writeCookie(function (): void {
            \think\facade\Cookie::delete($this->cookieName, [
                'path'     => '/',
                'httponly' => true,
                'secure'   => self::isHttps(),
                'samesite' => 'Lax',
            ]);
        });
    }

    /**
     * 通过框架 Cookie 队列写 Cookie
     *
     * 不使用原生 `setcookie()`：
     *  - think-swoole 常驻/协程下，原生 setcookie 不会写回协程响应；
     *  - 框架 Cookie 在 Response 发送时统一落盘，FPM 与常驻行为一致。
     * 无框架上下文（CLI / 单测）时静默跳过——该场景不存在浏览器 Cookie。
     *
     * @param callable(): void $writer
     */
    private function writeCookie(callable $writer): void
    {
        try {
            $writer();
        } catch (\Throwable) {
        }
    }

    /**
     * 获取 Cookie 名称
     */
    public function getCookieName(): string
    {
        return $this->cookieName;
    }

    /**
     * 检测当前请求是否 HTTPS（FPM + Swoole 兼容）
     *
     * 优先使用 ThinkPHP request()->server()，
     * 回退 $_SERVER（CLI 或未初始化场景）。
     */
    private static function isHttps(): bool
    {
        try {
            $request = request();
            if ($request) {
                $https = $request->server('HTTPS');
                if ($https !== null) {
                    return !empty($https) && strtolower($https) !== 'off';
                }
            }
        } catch (\Throwable) {
        }

        return false;
    }
}
