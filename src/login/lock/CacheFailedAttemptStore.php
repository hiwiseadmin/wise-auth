<?php
declare(strict_types=1);

namespace wise\login\lock;

use think\App;
use wise\support\rate\RateLimiter;

/**
 * 基于 ThinkPHP Cache 的失败计数器
 *
 * 适用于：单实例应用、调试环境、对原子性要求不高的场景
 * 生产环境建议使用 RedisFailedAttemptStore 以获得更好的原子性保证
 */
class CacheFailedAttemptStore implements FailedAttemptStoreInterface
{
    /**
     * @param App    $app
     * @param string $prefix       缓存键前缀
     * @param int    $decayMinutes 衰减窗口（分钟）
     * @param string $cacheStore   使用的缓存驱动；留空 = 跟随应用默认缓存（cache.default）
     */
    public function __construct(
        protected App $app,
        protected string $prefix = 'wise_login_security:failed:',
        protected int $decayMinutes = 60,
        protected string $cacheStore = ''
    ) {
    }

    public function getAttempts(string $key): int
    {
        return $this->limiter($key)->attempts();
    }

    public function increment(string $key): int
    {
        $limiter = $this->limiter($key);
        $remaining = $limiter->hit();
        $count = $this->maxAttemptsForLimiter() - $remaining;

        $fullKey = $this->prefix . $key;
        $ttl = $this->decayMinutes * 60;
        $this->app->cache->set($fullKey . ':expire_at', time() + $ttl, $ttl);

        return $count;
    }

    public function set(string $key, int $value): void
    {
        $fullKey = $this->prefix . $key;
        $ttl = $this->decayMinutes * 60;
        $this->app->cache->set($fullKey, $value, $ttl);
        $this->app->cache->set($fullKey . ':expire_at', time() + $ttl, $ttl);
    }

    /**
     * 设置值并同时设置 TTL（一次写入）
     *
     * {@inheritDoc}
     */
    public function setWithTtl(string $key, int $value, int $minutes): void
    {
        $fullKey = $this->prefix . $key;
        $ttl     = max(1, $minutes * 60);

        $this->app->cache->set($fullKey, $value, $ttl);
        $this->app->cache->set($fullKey . ':expire_at', time() + $ttl, $ttl);
    }

    public function reset(string $key): void
    {
        $this->limiter($key)->clear();
        $fullKey = $this->prefix . $key;
        $this->app->cache->delete($fullKey . ':expire_at');
    }

    public function expire(string $key, int $minutes): void
    {
        $fullKey = $this->prefix . $key;
        $ttl     = max(1, $minutes * 60);

        $handler = $this->redisHandler();
        if ($handler !== null) {
            $handler->expire($fullKey, $ttl);
            $this->app->cache->set($fullKey . ':expire_at', time() + $ttl, $ttl);

            return;
        }

        $value = $this->app->cache->get($fullKey, null);
        if ($value === null) {
            return;
        }
        $this->app->cache->set($fullKey, (int) $value, $ttl);
        $this->app->cache->set($fullKey . ':expire_at', time() + $ttl, $ttl);
    }

    /**
     * 取 Redis 原生句柄（非 Redis 驱动返回 null）
     *
     * 用于在 Redis 上走「只改 TTL」的 EXPIRE，避免读改写丢计数。
     *
     * @return \Redis|null
     */
    private function redisHandler(): ?\Redis
    {
        try {
            $store   = $this->cacheStore !== '' ? $this->cacheStore : (string) $this->app->config->get('cache.default', 'file');
            $handler = $this->app->cache->store($store)->handler();

            return $handler instanceof \Redis ? $handler : null;
        } catch (\Throwable) {
            return null;
        }
    }

    public function ttl(string $key): int
    {
        $fullKey = $this->prefix . $key;
        if (!$this->app->cache->has($fullKey)) {
            return -1;
        }
        $expireAt = (int) $this->app->cache->get($fullKey . ':expire_at', 0);
        if ($expireAt <= 0) {
            return -1;
        }
        return max(0, $expireAt - time());
    }


    /**
     * 创建内部 RateLimiter 实例
     *
     * prefix 去尾部冒号，由 RateLimiter::buildCacheKey() 自动添加 `:` 连接。
     * 结果 key 与原 `$this->prefix . $key` 格式一致。
     */
    private function limiter(string $key): RateLimiter
    {
        $store = $this->cacheStore !== ''
            ? $this->cacheStore
            : (string) $this->app->config->get('cache.default', 'file');

        return RateLimiter::for($this->maxAttemptsForLimiter(), $this->decayMinutes * 60)
            ->via($store)
            ->withPrefix(rtrim($this->prefix, ':'))
            ->by($key);
    }

    /**
     * RateLimiter 需要一个足够大的上限值来承载 Store 的计数逻辑。
     * set() 可能写入比 increment 累积更大的值，在此使用安全上限。
     */
    private function maxAttemptsForLimiter(): int
    {
        return 999999;
    }
}
