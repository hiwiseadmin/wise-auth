<?php
/**
 * 未授权异常
 *
 * 当用户尝试访问无权限的资源时抛出。
 */
namespace wise\auth\exception;

use think\Exception;

class UnauthorizedException extends Exception
{
    /**
     * @var string 所需权限标识
     */
    protected $permission = '';

    /**
     * @var int HTTP 状态码
     */
    protected $statusCode = 403;

    /**
     * UnauthorizedException constructor.
     *
     * @param string $message    错误消息
     * @param string $permission 所需权限标识
     * @param int    $code       错误码
     */
    public function __construct(string $message = 'Unauthorized', string $permission = '', int $code = 0)
    {
        parent::__construct($message, $code);
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
    public function setStatusCode(int $code): self
    {
        $this->statusCode = $code;
        return $this;
    }
}
