<?php
declare(strict_types=1);

namespace wise\login\contract;

use Closure;
use think\Request;

/**
 * 登录守卫动作接口（Login Guard Action）
 *
 * 登录前的安全校验步骤，每个 Action 实现一个独立的检查。
 * 参考 Laravel Fortify 的 Action 模式设计。
 *
 * 三种返回值语义：
 *   - return $next($payload)        继续传递给下一个 Action
 *   - return Response                拦截请求，返回错误响应（如 IP 被拦截、账号锁定）
 *   - throw LoginException  抛出异常中止（验证码错误等）
 *
 * @package wise\login\contract
 */
interface LoginGuardAction
{
    /**
     * 执行登录守卫检查
     *
     * @param LoginPayload $payload 登录载荷（含 Request、username、ip 等）
     * @param Closure      $next    传递给下一个 Action
     * @return mixed  Response（拦截）或 $next($payload)（放行）
     */
    public function handle(LoginPayload $payload, Closure $next);
}
