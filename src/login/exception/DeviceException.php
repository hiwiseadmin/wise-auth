<?php
declare(strict_types=1);

namespace wise\login\exception;

/**
 * 设备管理相关异常
 *
 * 错误码：ErrorCode::DEVICE_ERROR (60070)
 * HTTP：400
 */
class DeviceException extends LoginException
{
    protected int $statusCode = 400;

    public function __construct(string $message = '设备操作失败', array $data = [], ?\Throwable $previous = null)
    {
        parent::__construct($message, $data, ErrorCode::DEVICE_ERROR->value, $previous);
    }
}
