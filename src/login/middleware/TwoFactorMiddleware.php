<?php
declare(strict_types=1);

namespace wise\login\middleware;

use think\Request;
use think\Response;
use wise\login\contract\TotpUserInterface;
use wise\login\device\RememberDeviceHelper;
use wise\login\event\EventLogger;
use wise\login\totp\TotpManager;
use wise\support\traits\JsonResponse;

/**
 * 双因素认证中间件
 *
 * 用法：
 *   - 放在登录成功之后，访问受保护资源之前的中间件链中
 *   - 通过用户解析器获取当前用户（必须实现 TotpUserInterface）
 *
 * 状态判断（按优先级）：
 *  1. 已通过 2FA（session 标记）→ 放行
 *  2. 未登录 → 放行
 *  3. 用户未启用 TOTP → 放行
 *  4. 记住设备 Cookie 有效 → 放行
 *  5. 全局已信任设备 → 放行
 *  6. 否则 → AJAX 返回 JSON（含 totp_url），浏览器直接 redirect
 *
 * 拦截时返回 Response 而非抛出异常，响应格式与项目 JsonResponse trait 一致。
 */
class TwoFactorMiddleware
{
    use JsonResponse;
    protected RememberDeviceHelper $rememberHelper;

    public function __construct(
        protected TotpManager $totp,
        protected EventLogger $eventLogger,
        ?RememberDeviceHelper $rememberHelper = null
    ) {
        $this->rememberHelper = $rememberHelper ?? new RememberDeviceHelper();
    }

    public function handle(Request $request, \Closure $next): Response
    {
        $enabled = (bool) config(
            'wise-auth.login.middleware.two_factor.enabled',
            config('wise-auth.login.two_factor.enabled', true)
        );
        if (!$enabled) {
            return $next($request);
        }

        if ($this->isVerified($request)) {
            return $next($request);
        }

        $user = $this->resolveUser($request);
        if ($user === null) {
            return $next($request);
        }

        if (!$user instanceof TotpUserInterface) {
            throw new \wise\login\exception\TotpUserInterfaceException(
                '当前用户模型未实现 TotpUserInterface',
                ['user_class' => $user::class]
            );
        }

        if (!$user->isTotpEnabled()) {
            return $next($request);
        }

        if ($this->isRememberedDevice($request, $user)) {
            return $next($request);
        }

        if ($this->isTrustedDevice($request)) {
            return $next($request);
        }

        $this->eventLogger->log('totp_failed', [
            'reason' => 'required',
            'ip'     => $request->ip(),
        ], $request);

        $totpUrl = $this->buildTotpChallengeUrl($request);

        if ($this->isAjaxRequest($request)) {
            return $this->error('请完成双因素认证', [
                'action'   => 'require_2fa',
                'totp_url' => $totpUrl,
            ], 401);
        }

        return redirect($totpUrl);
    }

    /**
     * 标记当前会话已通过 2FA
     */
    public static function markVerified(Request $request): void
    {
        \think\facade\Session::set('wise_login_security.totp_verified', true);
    }

    /**
     * 清除已验证标记（登出时调用）
     */
    public static function clearVerified(Request $request): void
    {
        \think\facade\Session::delete('wise_login_security.totp_verified');
        $helper = new RememberDeviceHelper();
        $helper->clearCookie();
    }

    /**
     * 签发"记住此设备"Cookie
     *
     * 在 2FA 验证成功后的控制器中调用。
     *
     * @param Request $request
     * @param int     $userId   用户 ID
     * @param string  $fingerprint 设备指纹（可选，默认从请求生成）
     */
    public static function markRemembered(Request $request, int $userId, ?string $fingerprint = null): void
    {
        $helper = new RememberDeviceHelper();

        if ($fingerprint === null) {
            $fp = app(\wise\login\device\DeviceFingerprint::class);
            $fingerprint = $fp->fromRequest($request->server(), $request->ip());
        }

        $token = $helper->createToken($userId, $fingerprint);
        $cfg = (array) config('wise-auth.login.device_management', []);
        $days = (int) ($cfg['trust_duration_days'] ?? 30);
        $helper->setCookie($token, $days);
    }

    /**
     * 检查"记住此设备"Cookie 是否有效
     */
    protected function isRememberedDevice(Request $request, TotpUserInterface $user): bool
    {
        if (!(bool) config('wise-auth.login.device_management.remember_device_enabled', true)) {
            return false;
        }

        try {
            $fp = app(\wise\login\device\DeviceFingerprint::class);
            $fingerprint = $fp->fromRequest($request->server(), $request->ip());
        } catch (\Throwable $e) {
            return false;
        }

        $userId = $this->getUserId($user);
        if ($userId === null) {
            return false;
        }

        return $this->rememberHelper->validate($request, $userId, $fingerprint);
    }

    /**
     * 从 TotpUserInterface 获取用户 ID
     */
    protected function getUserId(TotpUserInterface $user): ?int
    {
        if (method_exists($user, 'getKey')) {
            $key = $user->getKey();
            return $key !== null ? (int) $key : null;
        }
        return null;
    }

    protected function isVerified(Request $request): bool
    {
        if (function_exists('session')) {
            return (bool) session('wise_login_security.totp_verified');
        }
        return false;
    }

    protected function isTrustedDevice(Request $request): bool
    {
        $skip = (bool) config('wise-auth.login.two_factor.skip_for_trusted_device', true)
            && (bool) config('wise-auth.login.device_management.skip_totp_for_trusted_device', true);
        if (!$skip) {
            return false;
        }

        $user = $this->resolveUser($request);
        if (!$user instanceof TotpUserInterface) {
            return false;
        }

        $userId = $this->getUserId($user);
        if ($userId === null) {
            return false;
        }

        try {
            return app(\wise\login\device\DeviceManager::class)
                ->isTrusted($userId, $request->server());
        } catch (\Throwable $e) {
            return false;
        }
    }

    protected function buildTotpChallengeUrl(Request $request): string
    {
        return (string) config('wise-auth.login.two_factor.challenge_url', url('auth/2fa'));
    }

    protected function resolveUser(Request $request): ?object
    {
        if (!app()->has('wise_login_security.user_resolver')) {
            return null;
        }

        $resolver = app('wise_login_security.user_resolver');

        if (is_callable($resolver)) {
            $resolver = $resolver($request);
        }

        return is_object($resolver) ? $resolver : null;
    }

    /**
     * 判断是否为 AJAX/API 请求
     */
    protected function isAjaxRequest(Request $request): bool
    {
        if ($request->isAjax()) {
            return true;
        }
        if ($request->isJson()) {
            return true;
        }
        return false;
    }
}
