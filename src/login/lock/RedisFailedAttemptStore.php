<?php
declare(strict_types=1);

namespace wise\login\lock;

use think\App;
use wise\support\rate\RateLimiter;

/**
 * 基于 Redis 的失败计数器
 *
 * 计数委托给 wise-support RateLimiter（via redis），
 * set/expire/ttl 等锁定语义直接使用 Redis 原生操作。
 * 适用于 Swoole 等常驻内存环境 / 分布式部署。
 */
class RedisFailedAttemptStore implements FailedAttemptStoreInterface
{
    public function __construct(
        protected App $app,
        protected string $prefix = 'wise_login_security:failed:',
        protected int $decayMinutes = 60
    ) {
    }

    protected function redis(): \Redis
    {
        return $this->app->cache->store('redis')->handler();
    }

    public function getAttempts(string $key): int
    {
        return $this->limiter($key)->attempts();
    }

    public function increment(string $key): int
    {
        $limiter = $this->limiter($key);
        $remaining = $limiter->hit();
        return $this->maxAttemptsForLimiter() - $remaining;
    }

    public function set(string $key, int $value): void
    {
        $r = $this->redis();
        $fullKey = $this->prefix . $key;
        $r->set($fullKey, $value);
        $r->expire($fullKey, $this->decayMinutes * 60);
    }

    /**
     * 设置值并同时设置 TTL（SETEX，原子）
     *
     * {@inheritDoc}
     */
    public function setWithTtl(string $key, int $value, int $minutes): void
    {
        $this->redis()->setex($this->prefix . $key, max(1, $minutes * 60), (string) $value);
    }

    public function reset(string $key): void
    {
        $this->limiter($key)->clear();
    }

    public function expire(string $key, int $minutes): void
    {
        $this->redis()->expire($this->prefix . $key, $minutes * 60);
    }

    public function ttl(string $key): int
    {
        $ttl = $this->redis()->ttl($this->prefix . $key);
        return $ttl === -2 ? -1 : (int) $ttl;
    }


    /**
     * 创建内部 RateLimiter 实例（via redis，与 Store 后端一致）
     */
    private function limiter(string $key): RateLimiter
    {
        return RateLimiter::for($this->maxAttemptsForLimiter(), $this->decayMinutes * 60)
            ->via('redis')
            ->withPrefix(rtrim($this->prefix, ':'))
            ->by($key);
    }

    private function maxAttemptsForLimiter(): int
    {
        return 999999;
    }
}
