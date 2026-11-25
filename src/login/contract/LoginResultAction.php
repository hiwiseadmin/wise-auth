<?php
declare(strict_types=1);

namespace wise\login\contract;

use Closure;

/**
 * 登录结果处理接口（Login Result Action）
 *
 * 登录成功/失败后的后置处理步骤，每个 Action 实现一个独立的后置动作。
 *
 * 三种返回值语义：
 *   - return $next($payload)   继续传递给下一个 Action
 *   - return $payload          提前返回（不需要执行后续步骤）
 *   - throw Exception          异常由中间件捕获，不影响主流程
 *
 * @package wise\login\contract
 */
interface LoginResultAction
{
    /**
     * 执行登录结果处理
     *
     * @param LoginResultPayload $payload 登录结果载荷
     * @param Closure            $next    传递给下一个 Action
     * @return LoginResultPayload
     */
    public function handle(LoginResultPayload $payload, Closure $next): LoginResultPayload;
}
