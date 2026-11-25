<?php
declare(strict_types=1);

namespace wise\login\exception;

/**
 * CAPTCHA 频率限制异常
 *
 * 当客户端在单位时间内频繁请求生成验证码时抛出。
 *
 * 错误码：ErrorCode::CAPTCHA_RATE_LIMIT (60035)
 * HTTP：429
 */
class CaptchaRateLimitException extends LoginException
{
    protected int $statusCode = 429;

    public function __construct(string $message = '验证码请求过于频繁，请稍后再试', array $data = [], ?\Throwable $previous = null)
    {
        parent::__construct($message, $data, ErrorCode::CAPTCHA_RATE_LIMIT->value, $previous);
    }
}
