<?php
declare(strict_types=1);

namespace wise\login;

use Closure;
use wise\login\contract\LoginPayload;
use wise\login\contract\LoginResultPayload;
use wise\login\exception\LoginException;

/**
 * 登录管道（Login Pipeline）
 *
 * 登录守卫和处理流程的编排器，将中间件中的硬编码步骤
 * 拆分为独立的 Action 链，通过洋葱模型依次执行。
 *
 * 两种管道模式：
 *   - guardPipeline:   前置安全校验（IP → 锁定 → 验证码）
 *   - resultPipeline:  后置结果处理（记录失败 → 记录成功 → 设备 → TOTP → 异常检测）
 *
 * @package wise\login
 */
class LoginPipeline
{
    /**
     * 管道工序列表
     * @var array
     */
    protected $pipes = [];

    /**
     * 要调用的方法名
     * @var string
     */
    protected $method = 'handle';

    /**
     * 设置管道工序
     */
    public function through(array $pipes): self
    {
        $this->pipes = $pipes;
        return $this;
    }

    /**
     * 设置调用方法名
     */
    public function via(string $method): self
    {
        $this->method = $method;
        return $this;
    }

    /**
     * 执行守卫管道（LoginGuardAction 链）
     *
     * 任何步骤返回 Response 时中止管道并返回该 Response。
     *
     * @param LoginPayload $payload
     * @param Closure      $destination  最终回调
     * @return mixed  Response（被拦截）或 $destination 返回值
     */
    public function guardThen(LoginPayload $payload, Closure $destination)
    {
        $pipeline = array_reduce(
            array_reverse($this->pipes),
            $this->guardCarry(),
            function (LoginPayload $p) use ($destination) {
                return $destination($p);
            }
        );

        return $pipeline($payload);
    }

    /**
     * 执行结果管道（LoginResultAction 链）
     *
     * @param LoginResultPayload $payload
     * @param Closure            $destination
     * @return LoginResultPayload
     */
    public function resultThen(LoginResultPayload $payload, Closure $destination): LoginResultPayload
    {
        $pipeline = array_reduce(
            array_reverse($this->pipes),
            $this->resultCarry(),
            function (LoginResultPayload $p) use ($destination) {
                return $destination($p);
            }
        );

        return $pipeline($payload);
    }

    /**
     * 守卫洋葱包裹器
     */
    protected function guardCarry(): Closure
    {
        return function ($stack, $pipe) {
            return function (LoginPayload $payload) use ($stack, $pipe) {
                if ($pipe instanceof Closure) {
                    return $pipe($payload, $stack);
                }

                if (is_string($pipe)) {
                    $pipe = $this->resolvePipe($pipe);
                }

                return call_user_func_array([$pipe, $this->method], [$payload, $stack]);
            };
        };
    }

    /**
     * 结果洋葱包裹器
     */
    protected function resultCarry(): Closure
    {
        return function ($stack, $pipe) {
            return function (LoginResultPayload $payload) use ($stack, $pipe) {
                if ($pipe instanceof Closure) {
                    return $pipe($payload, $stack);
                }

                if (is_string($pipe)) {
                    $pipe = $this->resolvePipe($pipe);
                }

                return call_user_func_array([$pipe, $this->method], [$payload, $stack]);
            };
        };
    }

    /**
     * 解析 Pipe 实例
     */
    protected function resolvePipe(string $pipeClass): object
    {
        if (!class_exists($pipeClass)) {
            throw new LoginException("管道工序类不存在: [{$pipeClass}]");
        }
        return app()->make($pipeClass);
    }
}
