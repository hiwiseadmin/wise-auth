<?php
declare(strict_types=1);

namespace wise\login\lock;

use think\App;
use think\facade\Db;
use wise\login\ip\CidrMatcher;
use wise\support\context\ContextualLogger;

/**
 * 登录锁管理器
 *
 * 职责：
 *  - 维护失败计数
 *  - 达到阈值后自动锁定（写入 store，作为失败锁定的"锁标记"）
 *  - 提供手动加锁 / 解锁能力
 *  - 支持按 IP / 用户名 / 组合 三种 scope
 *
 * 锁标记存储：使用同一个 store（避免多存储带来的不一致）
 *  - 键格式：locked:{$scope}:{$value}
 *  - 值：锁定原因（json 或简单字符串）
 *  - TTL：lockout_minutes
 */
class LoginLockManager
{
    protected ?string $deviceFingerprint = null;

    /**
     * Redis 不可用的告警只打一次（避免批量解锁时刷屏）
     */
    protected static bool $redisMissingLogged = false;

    public function __construct(
        protected App $app,
        protected FailedAttemptStoreInterface $store,
        protected array $config
    ) {
    }

    /**
     * 中间件在调用 lock 相关方法前通过此方法注入设备指纹，
     * 当 scope 包含 device_fingerprint 时自动参与 key 计算。
     */
    public function withDeviceFingerprint(?string $fp): static
    {
        $this->deviceFingerprint = $fp;
        return $this;
    }

    /**
     * 获取最大允许失败次数
     *
     * @return int 最大失败次数阈值
     */
    public function getMaxAttempts(): int
    {
        return (int) ($this->config['max_attempts'] ?? 5);
    }

    /**
     * 获取锁定时长（分钟）
     *
     * @return int 锁定分钟数
     */
    public function getLockoutMinutes(): int
    {
        return (int) ($this->config['lockout_minutes'] ?? 15);
    }

    /**
     * 获取渐进式锁定配置
     *
     * @return array{enabled:bool, levels:array, reset_after_success:bool, history_ttl_days:int}
     */
    public function getProgressiveConfig(): array
    {
        $cfg = $this->config['progressive_lockout'] ?? [];
        return [
            'enabled'            => (bool) ($cfg['enabled'] ?? false),
            'levels'             => (array) ($cfg['levels'] ?? [1, 5, 15, 30, 60, 1440]),
            'reset_after_success' => (bool) ($cfg['reset_after_success'] ?? true),
            'history_ttl_days'   => (int) ($cfg['history_ttl_days'] ?? 7),
        ];
    }

    /**
     * 设计思路：
     *  - 锁定历史计数器 key 格式：lock_hist:{buildKey()}，值为已锁定次数
     *  - 首次锁定 = levels[0]，二次 = levels[1]，以此类推
     *  - 超过 levels 数组长度则使用最后一个值（最大惩罚）
     *
     * @param string|null $username 用户名
     * @param string      $ip       客户端 IP
     * @return int 本次应使用的锁定分钟数
     */
    public function getProgressiveLockoutMinutes(?string $username, string $ip): int
    {
        $cfg = $this->getProgressiveConfig();
        if (!$cfg['enabled']) {
            return $this->getLockoutMinutes();
        }

        $levels = $cfg['levels'];
        if (empty($levels)) {
            return $this->getLockoutMinutes();
        }

        $historyCount = $this->getLockHistory($username, $ip);
        $index = min($historyCount, count($levels) - 1);
        return $levels[$index];
    }

    /**
     * 获取锁定历史次数（累计被锁定过的次数）
     *
     * @param string|null $username 用户名
     * @param string      $ip       客户端 IP
     * @return int 历史锁定次数
     */
    public function getLockHistory(?string $username, string $ip): int
    {
        $histKey = $this->buildLockHistoryKey($username, $ip);
        return $this->store->getAttempts($histKey);
    }

    /**
     * 递增锁定历史计数器
     *
     * @param string|null $username 用户名
     * @param string      $ip       客户端 IP
     * @return int 递增后的历史次数
     */
    protected function incrementLockHistory(?string $username, string $ip): int
    {
        $histKey = $this->buildLockHistoryKey($username, $ip);
        $count = $this->store->increment($histKey);

        $cfg = $this->getProgressiveConfig();
        $ttlDays = $cfg['history_ttl_days'];
        $this->store->expire($histKey, $ttlDays * 24 * 60);

        return $count;
    }

    /**
     * 重置锁定历史计数器（成功登录后可选重置）
     *
     * @param string|null $username 用户名
     * @param string      $ip       客户端 IP
     */
    protected function resetLockHistory(?string $username, string $ip): void
    {
        $histKey = $this->buildLockHistoryKey($username, $ip);
        $this->store->reset($histKey);
    }

    /**
     * 锁定历史的存储键
     */
    protected function buildLockHistoryKey(?string $username, string $ip): string
    {
        return 'lock_hist|' . $this->buildKey($username, $ip);
    }

    /**
     * 获取统计维度
     *
     * @return string 'ip' | 'username' | 'ip_username' | 'device_fingerprint' | 'ip_device'
     */
    public function getScope(): string
    {
        return (string) ($this->config['scope'] ?? 'ip_username');
    }

    /**
     * 计算 scope 对应的 key
     *
     * @param string|null $username 用户名
     * @param string      $ip       客户端 IP
     * @return string 存储键
     */
    public function buildKey(?string $username, string $ip): string
    {
        $scope = $this->getScope();
        $fp   = $this->deviceFingerprint ?: md5($ip);
        $ipHash = md5($ip);
        return match ($scope) {
            'ip'                 => 'ip|' . $ipHash,
            'username'           => 'user|' . ($username ?? ''),
            'ip_username'        => 'ip_user|' . $ipHash . '|' . ($username ?? ''),
            'device_fingerprint' => 'fp|' . $fp,
            'ip_device'          => 'ip|' . $ipHash . '|fp|' . $fp,
            default              => 'ip_user|' . $ipHash . '|' . ($username ?? ''),
        };
    }

    /**
     * 获取当前失败次数
     *
     * Bug-2 修复：新增方法供 LoginGuardMiddleware::checkCaptcha() 复用失败计数，
     * 替代原来独立且从未递增的 pre_check_attempts 缓存键
     *
     * @param string|null $username 用户名
     * @param string      $ip       客户端 IP
     * @return int 当前失败次数
     */
    public function getAttempts(?string $username, string $ip): int
    {
        $key = $this->buildKey($username, $ip);
        return $this->store->getAttempts($key);
    }

    /**
     * 是否已锁定
     *
     * @param string|null $username 用户名
     * @param string      $ip       客户端 IP
     * @return bool 是否已锁定
     */
    public function isLocked(?string $username, string $ip): bool
    {
        $lockKey = $this->buildLockKey($username, $ip);
        return $this->store->getAttempts($lockKey) >= 1;
    }

    /**
     * 获取锁定剩余秒数
     *
     * @param string|null $username 用户名
     * @param string      $ip       客户端 IP
     * @return int 剩余秒数，0 表示未锁定或已过期
     */
    public function lockTtl(?string $username, string $ip): int
    {
        $lockKey = $this->buildLockKey($username, $ip);
        $ttl = $this->store->ttl($lockKey);
        return $ttl > 0 ? $ttl : 0;
    }

    /**
     * 记录一次失败
     *
     *   - 启用后根据锁定历史次数自动递增锁定时长
     *   - 锁定触发后同时递增锁定历史计数器
     *
     * Bug-8 修复：锁定触发后同时重置失败计数，防止锁定过期后下一次失败立即重新锁定
     *
     * @param string|null $username 用户名
     * @param string      $ip       客户端 IP
     * @return array{attempts:int, locked:bool, ttl:int, lock_minutes:int} 失败结果
     */
    public function recordFailure(?string $username, string $ip): array
    {
        $key = $this->buildKey($username, $ip);
        $attempts = $this->store->increment($key);

        if ($attempts >= $this->getMaxAttempts()) {
            $lockKey = $this->buildLockKey($username, $ip);

            $lockMinutes = $this->getProgressiveLockoutMinutes($username, $ip);

            $this->store->setWithTtl($lockKey, 1, $lockMinutes);

            $historyCount = $this->incrementLockHistory($username, $ip);

            $this->store->reset($key);

            return [
                'attempts'     => $attempts,
                'locked'       => true,
                'ttl'          => $lockMinutes * 60,
                'lock_minutes' => $lockMinutes,
                'lock_level'   => $historyCount,
            ];
        }

        return [
            'attempts'     => $attempts,
            'locked'       => false,
            'ttl'          => 0,
            'lock_minutes' => 0,
        ];
    }

    /**
     * 成功登录后清除失败计数
     *
     * @param string|null $username 用户名
     * @param string      $ip       客户端 IP
     * @return void
     */
    public function clear(?string $username, string $ip): void
    {
        $this->store->reset($this->buildKey($username, $ip));

        $cfg = $this->getProgressiveConfig();
        if ($cfg['enabled'] && $cfg['reset_after_success']) {
            $this->resetLockHistory($username, $ip);
        }
    }

    /**
     * 管理员手动锁定（不依赖失败次数）
     *
     * Bug-6 修复：使用 set() 替代 increment()，避免多次调用 lock() 累加锁标记值
     *
     * @param string|null $username 用户名
     * @param string      $ip       客户端 IP
     * @param int         $minutes  锁定分钟数，0 = 永久（不过期，store 类型为 cache 时不可永久，会用 10 年兜底）
     * @return void
     */
    public function lock(?string $username, string $ip, int $minutes = 0): void
    {
        $lockKey = $this->buildLockKey($username, $ip);
        $ttl     = $minutes > 0 ? $minutes : 60 * 24 * 365 * 10;

        $this->store->setWithTtl($lockKey, 1, $ttl);
    }

    /**
     * 管理员手动解锁
     *
     * @param string|null $username 用户名
     * @param string      $ip       客户端 IP
     * @return void
     */
    public function unlock(?string $username, string $ip): void
    {
        $this->store->reset($this->buildLockKey($username, $ip));
        $this->store->reset($this->buildKey($username, $ip));
        $this->resetLockHistory($username, $ip);
    }

    /**
     * 按用户名解锁（不限 IP）—— 用于 `php think login-security:unlock {username}` 命令
     *
     * 注意：cache 驱动无法按模式扫描，仅在 username scope 下有效；
     * redis / database 驱动可通过 SCAN / LIKE 覆盖 ip_username 等复合 scope。
     *
     * @param string $username 要解锁的用户名
     * @return int 解锁的记录数
     */
    public function unlockByUsername(string $username): int
    {
        $storeName = (string) ($this->config['store'] ?? 'cache');
        $prefix = (string) ($this->config['cache_prefix'] ?? 'wise_login_security:failed:');
        $count = 0;

        $exactKeys = [
            'user|' . $username,
            'locked|user|' . $username,
        ];
        foreach ($exactKeys as $k) {
            if ($this->store->getAttempts($k) > 0 || $this->store->ttl($k) > 0) {
                $this->store->reset($k);
                $count++;
            }
        }

        if ($storeName === 'redis') {
            $count += $this->unlockByPatternRedis($prefix, $username);
        } elseif ($storeName === 'database') {
            $count += $this->unlockByPatternDatabase($username);
        } elseif ($this->getScope() !== 'username') {
            ContextualLogger::warning(
                '[login-security] 当前 scope=' . $this->getScope() . ' 且 store=' . $storeName
                . ' 无法按用户名枚举复合键，请改用 --ip 精确解锁，或切换 redis/database 存储。'
            );
        }

        return $count;
    }

    /**
     * 获取底层 Redis 连接
     *
     * ext-redis 未安装时 `\Redis` 类根本不存在，任何对 `\Redis::常量` 的引用
     * 都会抛不可捕获的 Error（尤其容易出现在静态上下文里）。因此这里先判类
     * 是否存在，缺失即返回 null，由调用方降级处理，**不中断登录流程**。
     *
     * @return object|null \Redis 实例；不可用时返回 null
     */
    protected function getRedisConnection(): ?object
    {
        if (!class_exists(\Redis::class)) {
            if (!self::$redisMissingLogged) {
                self::$redisMissingLogged = true;
                ContextualLogger::warning(
                    '[login-security] 未安装 ext-redis，Redis 相关能力已跳过'
                    . '（当前 failed_attempts.store=' . (string) ($this->config['store'] ?? 'cache') . '）'
                );
            }

            return null;
        }

        try {
            $redis = $this->app->cache->store('redis')->handler();

            return $redis instanceof \Redis ? $redis : null;
        } catch (\Throwable $e) {
            if (!self::$redisMissingLogged) {
                self::$redisMissingLogged = true;
                ContextualLogger::warning('[login-security] Redis 连接不可用，已降级：' . $e->getMessage());
            }

            return null;
        }
    }

    /**
     * Redis: 用 SCAN 匹配 ip_username 复合 scope 的锁键
     */
    protected function unlockByPatternRedis(string $prefix, string $username): int
    {
        try {
            $r = $this->getRedisConnection();
            if ($r === null) {
                return 0;
            }

            $iterator = null;
            $r->setOption(\Redis::OPT_SCAN, \Redis::SCAN_RETRY);
            $count = 0;

            $pattern = $prefix . 'ip_user|*|' . $username;
            while (($keys = $r->scan($iterator, $pattern, 200)) !== false) {
                foreach ($keys as $k) {
                    $r->del($k);
                    $count++;
                    $lockKey = $prefix . 'locked|' . substr($k, strlen($prefix));
                    if ($r->exists($lockKey)) {
                        $r->del($lockKey);
                        $count++;
                    }
                }
            }
            return $count;
        } catch (\Throwable) {
            return 0;
        }
    }

    /**
     * Database: 用 LIKE 匹配 ip_username 复合 scope 的锁键
     */
    protected function unlockByPatternDatabase(string $username): int
    {
        try {
            $table = config('wise-auth.login.tables.failed_attempts', 'auth_login_attempts');
            $prefix = (string) ($this->config['cache_prefix'] ?? 'wise_login_security:failed:');

            $patterns = [
                $prefix . 'ip_user|%|' . $username . '%',
                $prefix . 'locked|ip_user|%|' . $username . '%',
            ];
            $count = 0;
            foreach ($patterns as $pattern) {
                $count += Db::name($table)->where('cache_key', 'like', $pattern)->delete();
            }
            return $count;
        } catch (\Throwable) {
            return 0;
        }
    }

    /**
     * 强制全局解锁（清空所有失败计数与锁定标记）
     *
     * 支持的存储：
     *   - database：DELETE ... WHERE cache_key LIKE '{prefix}%'
     *   - redis   ：SCAN '{prefix}*' 逐个 DEL
     *   - cache   ：无法枚举键，返回 0（调用方应提示改用按用户名解锁）
     *
     * 注意：此前的实现
     *   1. 对 database 直接返回 0（与"数据库场景"的注释矛盾，等于 --all 静默失效）；
     *   2. redis 只扫 `locked|` 前缀的锁标记，遗留计数键，导致解锁后计数仍达标、立即又被锁。
     * 现统一清 `{prefix}*`，同时覆盖计数与锁标记。
     *
     * @return int 清除的记录数（cache 驱动恒为 0）
     */
    public function forceUnlockAll(): int
    {
        $storeName = (string) ($this->config['store'] ?? 'cache');
        $prefix    = (string) ($this->config['cache_prefix'] ?? 'wise_login_security:failed:');

        if ($storeName === 'database') {
            return $this->forceUnlockAllDatabase($prefix);
        }

        if ($storeName !== 'redis') {
            return 0;
        }

        $r = $this->getRedisConnection();
        if ($r === null) {
            return 0;
        }

        $count    = 0;
        $iterator = null;
        $r->setOption(\Redis::OPT_SCAN, \Redis::SCAN_RETRY);
        while (($keys = $r->scan($iterator, $prefix . '*', 200)) !== false) {
            foreach ($keys as $k) {
                $r->del($k);
                $count++;
            }
        }

        return $count;
    }

    /**
     * 数据库存储下的全局解锁
     */
    protected function forceUnlockAllDatabase(string $prefix): int
    {
        try {
            $table = config('wise-auth.login.tables.failed_attempts', 'auth_login_attempts');

            return (int) Db::name($table)->where('cache_key', 'like', $prefix . '%')->delete();
        } catch (\Throwable) {
            return 0;
        }
    }

    /**
     * 锁标记 key（在原 key 前加 'locked:' 前缀）
     *
     * @param string|null $username 用户名
     * @param string      $ip       客户端 IP
     * @return string 锁标记存储键
     */
    protected function buildLockKey(?string $username, string $ip): string
    {
        return 'locked|' . $this->buildKey($username, $ip);
    }
}
