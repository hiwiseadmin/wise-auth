<?php
declare(strict_types=1);

namespace wise\login\config;

use wise\support\config\CheckLevel;
use wise\support\config\CheckResult;
use wise\support\config\ConfigCheckInterface;

/**
 * wise-login-security 安全配置检测
 *
 * 检测指纹盐值的硬编码默认值。
 */
class LoginCheck implements ConfigCheckInterface
{
    private const DEFAULT_FINGERPRINT_SALT = 'change-me-to-random-string';

    public function __construct(
        private readonly \think\Config $config,
    ) {
    }

    public function id(): string
    {
        return 'wise-login-security:salt';
    }

    public function package(): string
    {
        return 'wise-auth.login';
    }

    public function level(): CheckLevel
    {
        return CheckLevel::ERROR;
    }

    public function check(): CheckResult
    {
        $salt = (string) $this->config->get('wise-auth.login.device_management.fingerprint_salt', '');

        if ($salt === self::DEFAULT_FINGERPRINT_SALT || $salt === '') {
            return CheckResult::fail(
                'WISE_LOGIN_FINGERPRINT_SALT 仍为默认值或未设置，设备指纹安全强度不足',
                '请在 .env 中设置 WISE_LOGIN_FINGERPRINT_SALT 为随机字符串'
            );
        }

        return CheckResult::ok();
    }
}
