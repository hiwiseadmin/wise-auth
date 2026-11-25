<?php
declare(strict_types=1);

namespace wise\login\exception;

/**
 * IP 黑白名单拦截异常
 *
 * 错误码：ErrorCode::IP_BLOCKED (60010)
 * HTTP：403
 */
class IpBlockedException extends LoginException
{
    protected int $statusCode = 403;

    public function __construct(string $message = 'IP 已被封禁，拒绝访问', array $data = [], ?\Throwable $previous = null)
    {
        parent::__construct($message, $data, ErrorCode::IP_BLOCKED->value, $previous);
    }
}
