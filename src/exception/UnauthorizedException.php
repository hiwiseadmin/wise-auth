<?php
/**
 * 未授权异常
 *
 * 当用户尝试访问无权限的资源时抛出。
 */
declare(strict_types=1);

namespace wise\auth\exception;

use wise\support\exception\WiseException;

class UnauthorizedException extends WiseException
{
    /**
     * @var string 所需权限标识
     */
    protected string $permission = '';

    /**
     * @var int HTTP 状态码（可动态调整，默认 403）
     */
    protected int $statusCode = 403;

    /**
     * UnauthorizedException constructor.
     *
     * @param string $message    错误消息
     * @param string $permission 所需权限标识
     * @param int    $code       业务错误码（默认 ErrorCode::UNAUTHORIZED）
     */
    public function __construct(string $message = 'Unauthorized', string $permission = '', int $code = ErrorCode::UNAUTHORIZED->value)
    {
        parent::__construct($code, $message, $this->statusCode);
        $this->permission = $permission;
    }

    /**
     * 获取所需权限标识
     *
     * @return string
     */
    public function getPermission(): string
    {
        return $this->permission;
    }

    /**
     * 获取 HTTP 状态码
     *
     * @return int
     */
    public function getStatusCode(): int
    {
        return $this->statusCode;
    }

    /**
     * 设置 HTTP 状态码
     *
     * @param int $code
     * @return $this
     */
    public function setStatusCode(int $code): static
    {
        $this->statusCode = $code;
        return $this;
    }

    /**
     * 覆盖父类 getHttpCode()，使全局渲染器能拿到动态 statusCode
     *
     * 与 getStatusCode() 保持一致，setStatusCode() 调整后同步生效。
     */
    public function getHttpCode(): int
    {
        return $this->statusCode;
    }
}
