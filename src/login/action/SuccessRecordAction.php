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
 * 登录成功处理 Action
 *
 * 处理登录成功后置动作：
 *   1. 清除失败计数（Lock::clear）
 *   2. 记录成功事件（TYPE_LOGIN_SUCCESS）
 *
 * 从 LoginResultMiddleware::handleSuccess() 提取
 */
class SuccessRecordAction implements LoginResultAction
{
    /**
     * 记录登录成功：清除失败计数、记录成功事件
     *
     * @param LoginResultPayload $payload
     * @param Closure            $next
     * @return LoginResultPayload
     */
    public function handle(LoginResultPayload $payload, Closure $next): LoginResultPayload
    {
        if (!$payload->isSuccess) {
            return $next($payload);
        }

        $username = $payload->username;
        $request  = $payload->request;

        $clientIp = CidrMatcher::fromRequest($request);

        if ($payload->actionEnabled('success_clear')) {
            Lock::clear($username, $clientIp);
        }

        if ($payload->actionEnabled('success_event')) {
            Logger::log(
                LoginEvent::TYPE_LOGIN_SUCCESS,
                ['user_id' => $payload->userId],
                $request,
                $username
            );
        }

        return $next($payload);
    }
}
