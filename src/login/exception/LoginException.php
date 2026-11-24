<?php
declare(strict_types=1);

namespace wise\login\exception;

use wise\support\exception\WiseException;

/**
 * 登录安全包基础异常
 *
 * 所有由 wise-login-security 抛出的异常都继承自本类，
 * 业务层可通过 catch (LoginException $e) 统一捕获。
 *
 * 参数映射（相对 WiseException）：
 *   - $errorCode  → 业务错误码（ErrorCode 枚举，号段 60000~69999）
 *   - $statusCode → HTTP 状态码
 *   - $data       → 上下文数据（context）
 */
class LoginException extends WiseException
{
    /**
     * HTTP 状态码（子类可重写）
     */
    protected int $statusCode = 400;

    /**
     * @param string          $message  异常消息
     * @param array           $data     附加数据（上下文）
     * @param int             $code     业务错误码（传 0 时回退到 ErrorCode::GENERAL）
     * @param \Throwable|null $previous 前置异常
     */
    public function __construct(string $message = '', array $data = [], int $code = 0, ?\Throwable $previous = null)
    {
        $code = $code ?: ErrorCode::GENERAL->value;
        parent::__construct($code, $message, $this->statusCode, $previous, $data);
    }

    /**
     * 获取 HTTP 状态码
     */
    public function getStatusCode(): int
    {
        return $this->statusCode;
    }

    /**
     * 获取附加数据（上下文）
     */
    public function getData(): array
    {
        return $this->getContext();
    }
}
