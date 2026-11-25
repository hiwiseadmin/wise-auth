<?php
declare(strict_types=1);

namespace wise\login\exception;

/**
 * 备份码无效或已使用异常
 *
 * 错误码：ErrorCode::BACKUP_CODE_INVALID (60050)
 * HTTP：422
 */
class BackupCodeInvalidException extends LoginException
{
    protected int $statusCode = 422;

    public function __construct(string $message = '备份码无效或已被使用', array $data = [], ?\Throwable $previous = null)
    {
        parent::__construct($message, $data, ErrorCode::BACKUP_CODE_INVALID->value, $previous);
    }
}
