<?php
declare(strict_types=1);

namespace wise\login\action;

use Closure;
use wise\login\contract\LoginGuardAction;
use wise\login\contract\LoginPayload;
use wise\login\ip\IpAccessDecision;
use wise\support\traits\JsonResponse;

/**
 * IP 黑白名单检查 Action
 *
 * 检查客户端IP是否在配置的白名单/黑名单中。
 * 支持三种模式：blacklist / whitelist / both
 *
 * 从 LoginGuardMiddleware::checkIp() 提取
 */
class IpGuardAction implements LoginGuardAction
{
    use JsonResponse;

    /** @var array 黑名单 */
    protected array $blacklist;

    /** @var array 白名单 */
    protected array $whitelist;

    /** @var string 检查模式：blacklist | whitelist | both */
    protected string $mode;

    /** 共享判定器（与 admin 应用级 IpGuardMiddleware 同一实现） */
    protected IpAccessDecision $decision;

    /**
     * @param array  $blacklist CIDR 黑名单列表
     * @param array  $whitelist CIDR 白名单列表
     * @param string $mode      检查模式：blacklist | whitelist | both
     * @throws \InvalidArgumentException 无效模式时抛出
     */
    public function __construct(array $blacklist = [], array $whitelist = [], string $mode = 'blacklist')
    {
        $this->decision = new IpAccessDecision($blacklist, $whitelist, $mode);

        $this->blacklist = $blacklist;
        $this->whitelist = $whitelist;
        $this->mode      = $mode;
    }

    /**
     * 执行 IP 守卫检查（白名单优先，黑名单兜底）
     *
     * 「怎么判」由 {@see IpAccessDecision} 统一实现；本类只负责把结论
     * 翻译成登录尝试链的日志与响应（与中间件的事件表留痕口径不同，属有意设计）。
     *
     * @param LoginPayload $payload
     * @param Closure      $next
     * @return mixed
     */
    public function handle(LoginPayload $payload, Closure $next)
    {
        $ip       = $payload->ip;
        $decision = $this->decision->evaluate($ip);

        if (!$decision['allowed']) {
            $notInWhitelist = $decision['reason'] === IpAccessDecision::REASON_NOT_IN_WHITELIST;

            $payload->log(static::class, 'blocked', $notInWhitelist ? '不在白名单中' : '黑名单命中');

            return $notInWhitelist
                ? $this->error('IP 不在白名单中', ['ip' => $ip], 403)
                : $this->error('IP 已被列入黑名单', ['ip' => $ip], 403);
        }

        $payload->log(static::class, 'passed', $decision['whitelist_hit'] ? '白名单命中' : '');

        return $next($payload);
    }
}
