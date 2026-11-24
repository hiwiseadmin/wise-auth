<?php
declare(strict_types=1);

namespace wise\login\middleware;

use think\Request;
use think\Response;
use wise\login\event\EventLogger;
use wise\login\event\LoginEvent;
use wise\login\ip\CidrMatcher;
use wise\login\ip\IpAccessDecision;
use wise\login\ip\IpListProviderInterface;
use wise\support\traits\JsonResponse;

/**
 * IP 黑白名单守卫中间件
 *
 * 匹配规则（由 ip_list.mode 显式控制）：
 *   'blacklist' — 仅检查黑名单，白名单不生效（默认，安全）
 *   'whitelist' — 仅检查白名单，只允许列表中的 IP 访问
 *   'both'      — 白名单优先：白名单 IP 直接放行，其余走黑名单检查
 *
 * 拦截时返回 JSON Response 而非抛出异常，响应格式与项目 JsonResponse trait 一致。
 *
 * 用法：
 *  - 全局：放入 app/admin/middleware.php
 *  - 路由组：Route::group('admin', ...)
 */
class IpGuardMiddleware
{
    use JsonResponse;
    public function __construct(
        protected IpListProviderInterface $ipProvider,
        protected EventLogger $eventLogger
    ) {
    }

    public function handle(Request $request, \Closure $next): Response
    {
        $config = config('wise-auth.login.ip_list', []);
        $trustHeader = (bool) ($config['trust_proxy_header'] ?? true);
        $enabled = (bool) (config('wise-auth.login.middleware.ip_guard.enabled', true));

        if (!$enabled) {
            return $next($request);
        }

        if ($this->delegatedToLoginPipeline($request)) {
            return $next($request);
        }

        $trustedProxies = (array) ($config['trusted_proxies'] ?? []);
        $ip = CidrMatcher::getClientIp($request->server(), $trustHeader, $trustedProxies);

        $blacklist = $this->ipProvider->getBlacklist();
        $whitelist = $this->ipProvider->getWhitelist();
        $mode      = (string) ($config['mode'] ?? 'blacklist');

        $decision = (new IpAccessDecision($blacklist, $whitelist, $mode))->evaluate($ip);

        if (!$decision['allowed']) {
            $this->eventLogger->log(LoginEvent::TYPE_IP_BLACKLISTED, [
                'ip'     => $ip,
                'reason' => $decision['reason'],
            ], $request);

            return $decision['reason'] === IpAccessDecision::REASON_NOT_IN_WHITELIST
                ? $this->error('IP 不在白名单中，拒绝访问', ['ip' => $ip], 403)
                : $this->error('IP 已被列入黑名单，拒绝访问', ['ip' => $ip], 403);
        }

        $request = $request->withHeader(['X-Real-Client-Ip' => $ip]);

        return $next($request);
    }

    /**
     * 登录端点是否已由 LoginGuard 管道接管 IP 检查（C5-3）
     *
     * 登录请求会同时经过「admin 应用级中间件」与「登录守卫管道」两处 IP 检查，
     * 结果一致但重复查库/查缓存。此处让位给管道版本 —— 它带白名单优先语义、
     * 事件日志与失败计数联动，语义更完整。
     *
     * **安全前提**：只有管道确实会执行 IP 检查时才让位。守卫总开关或
     * `check_ip_list` 任一关闭时，本方法返回 false，中间件继续检查；
     * 否则登录端点会退化为「完全没有 IP 检查」＝绕过。
     */
    protected function delegatedToLoginPipeline(Request $request): bool
    {
        $guard = (array) config('wise-auth.login.middleware.login_guard', []);

        if (!($guard['enabled'] ?? true) || !($guard['check_ip_list'] ?? true)) {
            return false;
        }

        $path = strtolower(trim($request->pathinfo(), '/'));

        return preg_match('#(^|/)login/dologin$#', $path) === 1;
    }
}
