<?php
declare(strict_types=1);

namespace wise\login\action;

use Closure;
use wise\login\contract\LoginResultAction;
use wise\login\contract\LoginResultPayload;
use wise\login\device\DeviceManager;

/**
 * 设备记录与 TOTP 标记 Action
 *
 * 登录成功后：
 *   1. 记录设备信息（DeviceManager::record）
 *
 * 注意：本 Action 不再标记 TOTP 已验证——账号密码通过不等于 2FA 通过，
 *      TOTP 打标需由校验动态码成功的控制器显式调用 markVerified() 完成。
 *
 * 从 LoginResultMiddleware::handleSuccess() 提取
 */
class DeviceRecordAction implements LoginResultAction
{
    /**
     * 记录设备信息
     *
     * @param LoginResultPayload $payload
     * @param Closure            $next
     * @return LoginResultPayload
     */
    public function handle(LoginResultPayload $payload, Closure $next): LoginResultPayload
    {
        if (!$payload->isSuccess || !$payload->userId) {
            return $next($payload);
        }


        if ($payload->actionEnabled('device_record')) {
            app(DeviceManager::class)->record((int) $payload->userId, $payload->request->server());
        }

        return $next($payload);
    }
}
