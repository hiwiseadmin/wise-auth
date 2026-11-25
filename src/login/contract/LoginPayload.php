<?php
declare(strict_types=1);

namespace wise\login\contract;

use think\Request;

/**
 * 登录载荷（Login Payload）
 *
 * 登录守卫管道中流转的上下文对象。
 * 每个 LoginGuardAction 可以读取和修改载荷中的状态。
 *
 * @package wise\login\contract
 */
class LoginPayload
{
    /**
     * HTTP 请求对象
     * @var Request
     */
    public $request;

    /**
     * 用户名字符串
     * @var string|null
     */
    public $username;

    /**
     * 客户端IP
     * @var string
     */
    public $ip;

    /**
     * 配置数组
     * @var array
     */
    public $config;

    /**
     * 管道执行日志
     * @var array
     */
    public $pipeLog = [];

    /**
     * 构造函数
     */
    public function __construct(Request $request, ?string $username, string $ip, array $config = [])
    {
        $this->request  = $request;
        $this->username = $username;
        $this->ip       = $ip;
        $this->config   = $config;
    }

    /**
     * 记录管道日志
     */
    public function log(string $actionClass, string $status, string $message = ''): void
    {
        $this->pipeLog[] = [
            'action'  => $actionClass,
            'status'  => $status,
            'message' => $message,
            'time'    => microtime(true),
        ];
    }
}
