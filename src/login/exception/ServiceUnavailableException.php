<?php
declare(strict_types=1);

namespace wise\login\exception;

use wise\support\circuit\CircuitBreakerExceptionInterface;
use wise\support\exception\GeneralErrorCode;
use wise\support\exception\WiseException;

/**
 * 服务不可用异常（熔断触发）
 *
 * 当验证码服务的断路器处于 OPEN 状态时抛出。
 * 由 CaptchaController 捕获，通过 JsonResponse::circuitResponse()
 * 返回 HTTP 503 + Retry-After 头。
 *
 * 错误码：GeneralErrorCode::SERVICE_UNAVAILABLE (151)
 * HTTP：503
 */
class ServiceUnavailableException extends WiseException implements CircuitBreakerExceptionInterface
{
    protected int $retryAfter;

    public function __construct(
        string $message = 'Captcha service is temporarily unavailable (circuit breaker open)',
        int $retryAfter = 30,
        ?\Throwable $previous = null
    ) {
        $this->retryAfter = $retryAfter;
        parent::__construct(
            GeneralErrorCode::SERVICE_UNAVAILABLE->value,
            $message,
            503,
            $previous,
            ['retry_after' => $retryAfter],
        );
    }

    public function getRetryAfter(): int
    {
        return $this->retryAfter;
    }
}
