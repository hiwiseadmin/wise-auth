<?php
declare(strict_types=1);

namespace wise\login\exception;

/**
 * 账户锁定异常（失败次数超限 / 管理员手动锁定）
 *
 * 错误码：ErrorCode::ACCOUNT_LOCKED (60020)
 * HTTP：423
 */
class AccountLockedException extends LoginException
{
    protected int $statusCode = 423;

    public function __construct(string $message = '账户已被锁定，请稍后再试', array $data = [], ?\Throwable $previous = null)
    {
        parent::__construct($message, $data, ErrorCode::ACCOUNT_LOCKED->value, $previous);
    }
}
