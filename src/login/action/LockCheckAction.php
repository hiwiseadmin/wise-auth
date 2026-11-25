<?php
declare(strict_types=1);

namespace wise\login\action;

use Closure;
use wise\login\contract\LoginGuardAction;
use wise\login\contract\LoginPayload;
use wise\login\lock\LoginLockManager;
use wise\support\traits\JsonResponse;

/**
 * 登录失败锁定检查 Action
 *
 * 检查当前用户/IP 是否已被锁定，如果锁定则返回 423 响应。
 *
 * 从 LoginGuardMiddleware::checkLock() 提取
 */
class LockCheckAction implements LoginGuardAction
{
    use JsonResponse;

    protected LoginLockManager $lockManager;

    /**
     * @param LoginLockManager $lockManager
     */
    public function __construct(LoginLockManager $lockManager)
    {
        $this->lockManager = $lockManager;
    }

    /**
     * 检查当前用户/IP 是否已被锁定
     *
     * @param LoginPayload $payload
     * @param Closure      $next
     * @return mixed 锁定返回 423 JSON Response，否则放行
     */
    public function handle(LoginPayload $payload, Closure $next)
    {
        $username = $payload->username;
        $ip       = $payload->ip;

        if ($username === '' && $this->lockManager->getScope() === 'username') {
            $payload->log(static::class, 'skipped', '用户名为空且scope=username');
            return $next($payload);
        }

        if ($this->lockManager->isLocked($username, $ip)) {
            $ttl = $this->lockManager->lockTtl($username, $ip);
            $payload->log(static::class, 'blocked', "账户已锁定, TTL={$ttl}s");
            return $this->error('账户已被锁定，请稍后再试', [
                'ttl_seconds' => $ttl,
                'is_locked'   => true,
            ], 423);
        }

        $payload->log(static::class, 'passed');
        return $next($payload);
    }
}
