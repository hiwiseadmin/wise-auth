<?php
declare(strict_types=1);

namespace wise\login\action;

use Closure;
use wise\login\contract\LoginResultAction;
use wise\login\contract\LoginResultPayload;
use wise\login\event\LoginEvent;
use wise\login\facade\Lock;
use wise\login\facade\Logger;
use wise\login\ip\CidrMatcher;

/**
 * 登录失败处理 Action
 *
 * 处理登录失败后续动作：
 *   1. 记录失败次数（Lock::recordFailure）
 *   2. 触发锁定事件（TYPE_ACCOUNT_LOCKED）
 *   3. 记录失败事件（TYPE_LOGIN_FAILURE）
 *
 * 从 LoginResultMiddleware::handleFailure() 提取
 */
class FailureRecordAction implements LoginResultAction
{
    /**
     * 记录登录失败：递增失败计数、触发锁定事件、记录失败日志
     *
     * @param LoginResultPayload $payload
     * @param Closure            $next
     * @return LoginResultPayload
     */
    public function handle(LoginResultPayload $payload, Closure $next): LoginResultPayload
    {
        if ($payload->isSuccess) {
            return $next($payload);
        }

        $username = $payload->username;
        $request  = $payload->request;

        $clientIp = CidrMatcher::fromRequest($request);

        if ($payload->actionEnabled('failure_lock')) {
            $result = Lock::recordFailure($username, $clientIp);

            if (($result['locked'] ?? false) && $payload->actionEnabled('lock_notify')) {
                Logger::log(
                    LoginEvent::TYPE_ACCOUNT_LOCKED,
                    [
                        'username'     => $username,
                        'lock_minutes' => $result['lock_minutes'] ?? 0,
                        'lock_level'   => $result['lock_level'] ?? 0,
                    ],
                    $request,
                    $username
                );
            }
        }

        if ($payload->actionEnabled('failure_event')) {
            Logger::log(
                LoginEvent::TYPE_LOGIN_FAILURE,
                ['username' => $username],
                $request,
                $username
            );
        }

        return $next($payload);
    }
}
