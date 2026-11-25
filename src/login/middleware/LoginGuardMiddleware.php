<?php
declare(strict_types=1);

namespace wise\login\middleware;

use think\Request;
use think\Response;
use wise\login\action\CaptchaCheckAction;
use wise\login\action\IpGuardAction;
use wise\login\action\LockCheckAction;
use wise\login\action\SameOriginCheckAction;
use wise\login\contract\LoginPayload;
use wise\login\event\EventLogger;
use wise\login\ip\CidrMatcher;
use wise\login\ip\IpListProviderInterface;
use wise\login\lock\LoginLockManager;
use wise\login\LoginPipeline;
use wise\login\LoginRegistry;
use wise\support\traits\JsonResponse;

/**
 * 统一登录守卫中间件（V2: Pipeline 架构）
 *
 * 将原来的硬编码三步检查（IP → 锁定 → 验证码）改为可编排的 Action 管道。
 * 插件可通过 LoginRegistry::registerGuard() 插入自定义检查步骤。
 *
 * 执行流程：
 *   1. IpGuardAction       — IP 黑白名单检查
 *   2. LockCheckAction     — 失败次数锁定检查
 *   3. CaptchaCheckAction  — 验证码检查（需失败次数达到阈值）
 *   4. 业务层：用户名密码验证（由控制器完成）
 *
 * 用法：
 *   Route::post('login', 'Auth/login')->middleware([LoginGuardMiddleware::class]);
 */
class LoginGuardMiddleware
{
    use JsonResponse;
    public function __construct(
        protected IpListProviderInterface $ipProvider,
        protected LoginLockManager $lockManager,
        protected EventLogger $eventLogger
    ) {
    }

    public function handle(Request $request, \Closure $next): Response
    {
        $cfg = (array) config('wise-auth.login.middleware.login_guard', []);
        if (!($cfg['enabled'] ?? true)) {
            return $next($request);
        }

        $username    = $this->getUsername($request, $cfg);
        $trustProxy  = (bool) (config('wise-auth.login.ip_list.trust_proxy_header', true));
        $trustedProxies = (array) config('wise-auth.login.ip_list.trusted_proxies', []);
        $ip = CidrMatcher::getClientIp($request->server(), $trustProxy, $trustedProxies);

        $payload = new LoginPayload($request, $username, $ip, $cfg);

        $pipeline = new LoginPipeline();

        return $pipeline
            ->through($this->resolveGuardActions($cfg))
            ->guardThen($payload, function (LoginPayload $p) use ($next, $request) {
                return $next($request);
            });
    }

    /**
     * 解析守卫 Action 列表（配置 + 插件注册）
     */
    protected function resolveGuardActions(array $cfg): array
    {
        $actions = [];

        $originCfg = (array) ($cfg['origin_check'] ?? []);
        if ($originCfg['enabled'] ?? true) {
            $actions[] = new SameOriginCheckAction(
                (array) ($originCfg['allowed_hosts'] ?? []),
                (bool) ($originCfg['require_source'] ?? true),
                (bool) ($originCfg['reject_same_site'] ?? true),
                (bool) ($originCfg['trust_fetch_metadata'] ?? true)
            );
        }

        if ($cfg['check_ip_list'] ?? true) {
            $actions[] = new IpGuardAction(
                $this->ipProvider->getBlacklist(),
                $this->ipProvider->getWhitelist(),
                (string) config('wise-auth.login.ip_list.mode', 'blacklist')
            );
        }

        if ($cfg['check_lock'] ?? true) {
            $actions[] = new LockCheckAction($this->lockManager);
        }

        if (($cfg['check_captcha'] ?? true) && config('wise-auth.login.captcha.enabled', true)) {
            $threshold = (int) config('wise-auth.login.middleware.login_guard.require_captcha_after_failures', 2);
            $actions[] = new CaptchaCheckAction($this->lockManager, $this->eventLogger, $threshold, true);
        }

        $pluginActions = LoginRegistry::getGuardActions();
        foreach ($pluginActions as $action) {
            $actions[] = is_string($action) ? app()->make($action) : $action;
        }

        return $actions;
    }

    protected function getUsername(Request $request, array $cfg): ?string
    {
        $field = $cfg['username_input'] ?? 'username';
        $value = $request->param($field);

        if (!is_scalar($value)) {
            return null;
        }

        $value = trim((string) $value);
        return $value === '' ? null : $value;
    }
}
