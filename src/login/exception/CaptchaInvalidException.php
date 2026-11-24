<?php
declare(strict_types=1);

namespace wise\login\exception;

/**
 * 验证码无效或缺失异常
 *
 * 错误码：ErrorCode::CAPTCHA_INVALID (60030)
 * HTTP：422
 */
class CaptchaInvalidException extends LoginException
{
    protected int $statusCode = 422;

    public function __construct(string $message = '验证码错误或已过期', array $data = [], ?\Throwable $previous = null)
    {
        parent::__construct($message, $data, ErrorCode::CAPTCHA_INVALID->value, $previous);
    }
}
