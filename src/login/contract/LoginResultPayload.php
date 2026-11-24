<?php
declare(strict_types=1);

namespace wise\login\contract;

use think\Request;
use think\Response;

/**
 * 登录结果载荷（Login Result Payload）
 *
 * 登录结果管道中流转的上下文对象。
 * 每个 LoginResultAction 处理登录成功/失败的具体操作。
 *
 * @package wise\login\contract
 */
class LoginResultPayload
{
    /**
     * HTTP 请求对象
     * @var Request
     */
    public $request;

    /**
     * HTTP 响应对象
     * @var Response
     */
    public $response;

    /**
     * 解析后的响应体数组
     * @var array
     */
    public $body;

    /**
     * 是否登录成功
     * @var bool
     */
    public $isSuccess = false;

    /**
     * 用户名字符串
     * @var string|null
     */
    public $username;

    /**
     * 用户ID
     * @var int|null
     */
    public $userId;

    /**
     * 配置数组
     * @var array
     */
    public $config;

    /**
     * 动作开关配置
     * @var array
     */
    public $actions = [];

    /**
     * 构造函数
     */
    public function __construct(Request $request, Response $response, array $body, bool $isSuccess, array $config = [])
    {
        $this->request   = $request;
        $this->response  = $response;
        $this->body      = $body;
        $this->isSuccess = $isSuccess;
        $this->config    = $config;
        $this->actions   = $config['actions'] ?? [];
    }

    /**
     * 判断某个动作是否启用
     */
    public function actionEnabled(string $key): bool
    {
        return !empty($this->actions[$key]);
    }
}
