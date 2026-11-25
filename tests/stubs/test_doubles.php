<?php
declare(strict_types=1);

/**
 * 单元测试用的容器替身
 *
 * 为什么需要这一层：
 *   `tests/stubs/think_stubs.php` 以 `if (!class_exists(...))` 声明 ThinkPHP 类，
 *   但 PHPUnit 启动时已经通过 `src/vendor/autoload.php` 加载了真实 topthink/framework，
 *   因此 `think\Cache` / `think\Container` / `think\Facade` 命中真实类，stub 被跳过。
 *   真实 `think\Cache` 是 Manager，要求容器中存在 `$app->config`，否则抛
 *   「Unable to resolve NULL driver for [think\Cache]」。
 *
 * 本文件提供两个内存替身，由 bootstrap 绑定进容器：
 *   - WiseAuthTestCache              : 缓存替身（不落盘，用例间互不干扰）
 *   - WiseAuthTestFailedAttemptStore : 失败计数器替身（不连 Redis / 数据库）
 *
 * 语义与生产实现保持"够用的一致"：TTL 过期后不可见、inc 自增、set 覆盖。
 */

/**
 * 内存缓存替身
 *
 * 覆盖被业务代码实际调用的方法：get / set / has / delete / inc / dec / pull /
 * store / tag / handler / clear。未实现的方法走 __call 返回 null，
 * 避免「多一个缓存 API 就炸一批用例」。
 */
class WiseAuthTestCache
{
    /** @var array<string, mixed> */
    private array $data = [];

    /** @var array<string, int> 过期时间戳（0 = 永不过期） */
    private array $expires = [];

    /**
     * think\facade\Cache::store('redis')->handler() 会走到这里；
     * 返回自身（不是 \Redis 实例），业务代码据此走「非 Redis 降级路径」。
     */
    public function store(?string $name = null): static
    {
        return $this;
    }

    public function tag($tag): static
    {
        return $this;
    }

    public function handler(): static
    {
        return $this;
    }

    public function get(string $key, $default = null)
    {
        if (!$this->has($key)) {
            return $default;
        }

        return $this->data[$key];
    }

    public function set(string $key, $value, $ttl = null): bool
    {
        $this->data[$key] = $value;
        $this->expires[$key] = $this->toExpireAt($ttl);

        return true;
    }

    public function has(string $key): bool
    {
        if (!array_key_exists($key, $this->data)) {
            return false;
        }

        $expireAt = $this->expires[$key] ?? 0;
        if ($expireAt !== 0 && $expireAt <= time()) {
            unset($this->data[$key], $this->expires[$key]);

            return false;
        }

        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->data[$key], $this->expires[$key]);

        return true;
    }

    public function pull(string $key, $default = null)
    {
        $value = $this->get($key, $default);
        $this->delete($key);

        return $value;
    }

    /**
     * 原子自增；行为对齐 think Cache::inc()：键不存在时从 0 起算
     */
    public function inc(string $key, int $step = 1): int
    {
        $value = (int) $this->get($key, 0) + $step;
        $expireAt = $this->expires[$key] ?? 0;
        $this->data[$key] = $value;
        $this->expires[$key] = $expireAt;

        return $value;
    }

    public function dec(string $key, int $step = 1): int
    {
        return $this->inc($key, -$step);
    }

    public function clear(): bool
    {
        $this->data = [];
        $this->expires = [];

        return true;
    }

    /**
     * 兜底：未显式实现的方法（remember / push / expire / ...）不抛异常。
     */
    public function __call($method, $args)
    {
        return null;
    }

    private function toExpireAt($ttl): int
    {
        if ($ttl instanceof \DateInterval) {
            $now = new \DateTimeImmutable();
            $ttl = $now->add($ttl)->getTimestamp() - $now->getTimestamp();
        } elseif ($ttl instanceof \DateTimeInterface) {
            return $ttl->getTimestamp();
        }

        $ttl = (int) $ttl;

        return $ttl > 0 ? time() + $ttl : 0;
    }
}

/**
 * 失败计数器内存替身
 *
 * 生产有三种驱动（cache / redis / database），单测只需一种确定性的：
 * 进程内数组 + 过期时间戳。
 */
class WiseAuthTestFailedAttemptStore implements \wise\login\lock\FailedAttemptStoreInterface
{
    /** @var array<string, int> */
    private array $counts = [];

    /** @var array<string, int> 过期时间戳（0 = 永不过期） */
    private array $expires = [];

    public function getAttempts(string $key): int
    {
        if (!$this->alive($key)) {
            return 0;
        }

        return $this->counts[$key] ?? 0;
    }

    public function increment(string $key): int
    {
        $this->alive($key);
        $this->counts[$key] = (int) ($this->counts[$key] ?? 0) + 1;

        return $this->counts[$key];
    }

    public function set(string $key, int $value): void
    {
        $this->counts[$key] = $value;
    }

    /**
     * 设置值并同时设置 TTL（与生产实现语义一致：值与过期时间一次写入）
     *
     * @param int $minutes 过期分钟数
     */
    public function setWithTtl(string $key, int $value, int $minutes): void
    {
        $this->counts[$key]  = $value;
        $this->expires[$key] = $minutes > 0 ? time() + $minutes * 60 : 0;
    }

    public function reset(string $key): void
    {
        unset($this->counts[$key], $this->expires[$key]);
    }

    /**
     * @param int $minutes 过期分钟数（与生产实现签名一致：分钟，不是秒）
     */
    public function expire(string $key, int $minutes): void
    {
        $this->expires[$key] = $minutes > 0 ? time() + $minutes * 60 : 0;
    }

    public function ttl(string $key): int
    {
        if (!$this->alive($key) || !isset($this->counts[$key])) {
            return -1;
        }

        $expireAt = $this->expires[$key] ?? 0;

        return $expireAt === 0 ? -1 : max(0, $expireAt - time());
    }

    /**
     * 清空全部键（供用例隔离）
     */
    public function flush(): void
    {
        $this->counts = [];
        $this->expires = [];
    }

    private function alive(string $key): bool
    {
        $expireAt = $this->expires[$key] ?? 0;
        if ($expireAt !== 0 && $expireAt <= time()) {
            unset($this->counts[$key], $this->expires[$key]);

            return false;
        }

        return true;
    }
}
