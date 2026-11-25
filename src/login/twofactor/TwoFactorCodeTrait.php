<?php
declare(strict_types=1);

namespace wise\login\twofactor;

use think\facade\Cache;
use wise\login\contract\TotpUserInterface;
use wise\support\rate\RateLimiter;

/**
 * 双因素验证码发送/校验共享逻辑
 *
 * 为 EmailTwoFactorDriver 和 SmsTwoFactorDriver 提供统一的
 * 验证码生成、缓存存储、尝试次数管理和校验逻辑。
 *
 * @property int    $codeTtl         验证码有效期
 * @property int    $codeLength      验证码长度
 * @property int    $maxAttempts     最大尝试次数
 * @property int    $resendCooldown  重发冷却时间
 * @property string $cachePrefix     缓存键前缀
 */
trait TwoFactorCodeTrait
{
    /**
     * 派发验证码（由具体驱动实现）
     *
     * @return bool 是否发送成功
     */
    abstract protected function dispatchCode(string $target, string $code): bool;

    /**
     * 获取目标类型的中文描述（用于错误消息）
     */
    abstract protected function getTargetType(): string;

    /**
     * 发送验证码
     *
     * @param TotpUserInterface $user
     * @param string            $target 邮箱地址/手机号等
     * @return array{success: bool, error?: string}
     */
    public function sendCode(TotpUserInterface $user, string $target): array
    {
        if ($target === '') {
            return ['success' => false, 'error' => $this->getTargetType() . '地址为空'];
        }

        $cooldownKey = $this->buildKey($user, 'cooldown');
        $cooldown    = (int) Cache::get($cooldownKey, 0);
        if ($cooldown > time()) {
            $retryAfter = $cooldown - time();
            return ['success' => false, 'error' => "请 {$retryAfter} 秒后再试"];
        }

        $code = $this->generateCode();

        $codeKey = $this->buildKey($user, 'code');
        Cache::set($codeKey, hash('sha256', $code), $this->codeTtl);
        $this->attemptsLimiter($user)->clear();

        Cache::set($cooldownKey, time() + $this->resendCooldown, $this->resendCooldown);

        return $this->dispatchCode($target, $code)
            ? ['success' => true]
            : ['success' => false, 'error' => $this->getTargetType() . '发送失败'];
    }

    /**
     * 校验验证码
     *
     * @param TotpUserInterface $user
     * @param string            $code 用户输入的验证码
     * @return bool
     */
    public function verify(TotpUserInterface $user, string $code): bool
    {
        $code = trim($code);
        if ($code === '' || strlen($code) !== $this->codeLength) {
            return false;
        }

        $limiter = $this->attemptsLimiter($user);

        if ($limiter->tooManyAttempts()) {
            return false;
        }

        $limiter->hit();

        $codeKey = $this->buildKey($user, 'code');

        $storedHash = $this->pullOnce($codeKey);
        if (empty($storedHash)) {
            return false;
        }

        if (!hash_equals((string) $storedHash, hash('sha256', $code))) {
            Cache::set($codeKey, $storedHash, $this->codeTtl);

            return false;
        }

        $limiter->clear();

        return true;
    }

    /**
     * 原子地取出并删除一次性验证码
     *
     * Redis 6.2+ 走 GETDEL（单命令完成取+删）；
     * 其它驱动 / 旧版 Redis 退化为 get + delete（仍有极小窗口，属已知残余风险）。
     *
     * @param string $key 缓存键
     * @return string|null 取到的值，键不存在返回 null
     */
    protected function pullOnce(string $key): ?string
    {
        try {
            $handler = Cache::store('redis')->handler();
            if ($handler instanceof \Redis && method_exists($handler, 'getDel')) {
                $value = $handler->getDel($key);

                return ($value === false || $value === null) ? null : (string) $value;
            }
        } catch (\Throwable) {
        }

        $value = Cache::get($key);
        Cache::delete($key);

        return $value === null ? null : (string) $value;
    }

    /**
     * 生成 N 位数字验证码
     */
    protected function generateCode(): string
    {
        $min = 10 ** ($this->codeLength - 1);
        $max = (10 ** $this->codeLength) - 1;
        return (string) random_int($min, $max);
    }

    /**
     * 构建缓存键
     */
    protected function buildKey(TotpUserInterface $user, string $subKey): string
    {
        return $this->cachePrefix . md5($user->getTotpLabel()) . ':' . $subKey;
    }

    /**
     * 创建验证尝试次数限流器
     *
     * key 格式与原 Cache 键一致（prefix 去尾冒号后由 RateLimiter 自动加 `:`）。
     */
    protected function attemptsLimiter(TotpUserInterface $user): RateLimiter
    {
        return RateLimiter::for($this->maxAttempts, $this->codeTtl)
            ->withPrefix(rtrim($this->cachePrefix, ':'))
            ->by(md5($user->getTotpLabel()) . ':attempts');
    }
}
