<?php
declare(strict_types=1);

namespace wise\login\exception;

use wise\support\exception\ErrorCodeInterface;

/**
 * wise-login-security 业务错误码（号段 60000~69999）
 *
 *  60000          通用/默认
 *  60010~60019    IP 黑白名单
 *  60020~60029    账户锁定
 *  60030~60039    验证码
 *  60040~60049    双因素认证
 *  60050~60059    备份码
 *  60060~60069    TOTP 用户模型
 *  60070~60079    设备管理
 *
 * @package wise\login\exception
 */
enum ErrorCode: int implements ErrorCodeInterface
{
    /** 通用登录安全错误 */
    case GENERAL             = 60000;

    /** IP 被封禁 */
    case IP_BLOCKED          = 60010;

    /** 账户已锁定 */
    case ACCOUNT_LOCKED      = 60020;

    /** 验证码无效或缺失 */
    case CAPTCHA_INVALID     = 60030;

    /** 验证码请求过于频繁 */
    case CAPTCHA_RATE_LIMIT  = 60035;

    /** 需要双因素认证 */
    case TWO_FACTOR_REQUIRED = 60040;

    /** 备份码无效 */
    case BACKUP_CODE_INVALID = 60050;

    /** 用户模型未实现 TotpUserInterface */
    case TOTP_USER_INTERFACE = 60060;

    /** 设备操作失败 */
    case DEVICE_ERROR        = 60070;

    /**
     * 错误码对应的默认中文说明
     */
    public function defaultMessage(): string
    {
        return match ($this) {
            self::GENERAL             => '登录安全校验失败',
            self::IP_BLOCKED          => 'IP 已被封禁，拒绝访问',
            self::ACCOUNT_LOCKED      => '账户已被锁定，请稍后再试',
            self::CAPTCHA_INVALID     => '验证码错误或已过期',
            self::CAPTCHA_RATE_LIMIT  => '验证码请求过于频繁，请稍后再试',
            self::TWO_FACTOR_REQUIRED => '需要完成双因素认证',
            self::BACKUP_CODE_INVALID => '备份码无效或已被使用',
            self::TOTP_USER_INTERFACE => '用户模型未实现 TotpUserInterface',
            self::DEVICE_ERROR        => '设备操作失败',
        };
    }
}
