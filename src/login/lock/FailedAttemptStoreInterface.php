<?php
declare(strict_types=1);

namespace wise\login\lock;

/**
 * 登录失败计数器存储接口
 *
 * 三种实现：
 *  - CacheFailedAttemptStore（基于 ThinkPHP 缓存）
 *  - RedisFailedAttemptStore（直接操作 Redis，保证 Swoole 下原子性）
 *  - DatabaseFailedAttemptStore（持久化到数据库）
 */
interface FailedAttemptStoreInterface
{
    /**
     * 获取指定键的失败次数
     *
     * @param string $key 计数器键
     * @return int 失败次数
     */
    public function getAttempts(string $key): int;

    /**
     * 增加失败计数（返回新的计数）
     *
     * @param string $key 计数器键
     * @return int 递增后的失败次数
     */
    public function increment(string $key): int;

    /**
     * 设置指定键的失败次数（覆盖写入，用于手动锁定等场景）
     *
     * Bug-6 修复：新增 set() 方法替代 increment() 以避免多次调用累加
     *
     * @param string $key 计数器键
     * @param int    $value 要设置的值
     * @return void
     */
    public function set(string $key, int $value): void;

    /**
     * 设置值并指定过期时间（一次写入，原子语义）
     *
     * 为什么需要它：锁定标记用 `set()` + `expire()` 两条命令写入时，
     * 进程若在两条命令之间中断（Swoole 下 worker 会被 reload / 异常重启），
     * 键就没有 TTL，`isLocked()` 永远为真 —— 账号被永久锁定。
     * Redis 实现应使用 `SETEX`（或 `SET ... EX`）保证原子。
     *
     * @param string $key     计数器键
     * @param int    $value   要设置的值
     * @param int    $minutes 过期分钟数
     * @return void
     */
    public function setWithTtl(string $key, int $value, int $minutes): void;

    /**
     * 重置失败计数
     *
     * @param string $key 计数器键
     * @return void
     */
    public function reset(string $key): void;

    /**
     * 设置过期时间（分钟）
     *
     * @param string $key 计数器键
     * @param int    $minutes 过期分钟数
     * @return void
     */
    public function expire(string $key, int $minutes): void;

    /**
     * 获取剩余 TTL（秒），-1 表示不存在或永不过期
     *
     * @param string $key 计数器键
     * @return int 剩余秒数，-1 表示键不存在
     */
    public function ttl(string $key): int;
}
