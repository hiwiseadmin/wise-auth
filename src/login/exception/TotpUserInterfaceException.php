<?php
declare(strict_types=1);

namespace wise\login\exception;

/**
 * 用户未实现 TotpUserInterface 接口时抛出
 *
 * 错误码：ErrorCode::TOTP_USER_INTERFACE (60060)
 * HTTP：500
 */
class TotpUserInterfaceException extends LoginException
{
    protected int $statusCode = 500;

    public function __construct(string $message = '用户模型未实现 TotpUserInterface', array $data = [], ?\Throwable $previous = null)
    {
        parent::__construct($message, $data, ErrorCode::TOTP_USER_INTERFACE->value, $previous);
    }
}
