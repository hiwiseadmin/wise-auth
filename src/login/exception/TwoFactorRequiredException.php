<?php
declare(strict_types=1);

namespace wise\login\exception;

/**
 * 双因素认证未通过异常
 *
 * 中间件检测到用户已启用 2FA 但本次请求未通过验证时抛出，
 * 业务层可捕获并重定向到 /2fa/challenge 页面。
 *
 * 错误码：ErrorCode::TWO_FACTOR_REQUIRED (60040)
 * HTTP：401
 */
class TwoFactorRequiredException extends LoginException
{
    protected int $statusCode = 401;

    public function __construct(string $message = '需要完成双因素认证', array $data = [], ?\Throwable $previous = null)
    {
        parent::__construct($message, $data, ErrorCode::TWO_FACTOR_REQUIRED->value, $previous);
    }
}
