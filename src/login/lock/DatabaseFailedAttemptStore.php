<?php
declare(strict_types=1);

namespace wise\login\lock;

use think\App;
use think\facade\Db;

/**
 * 基于数据库的失败计数器
 *
 * 适用场景：多实例、需审计/分析、可接受 1 次 DB 写入的场景
 */
class DatabaseFailedAttemptStore implements FailedAttemptStoreInterface
{
    public function __construct(
        protected App $app,
        protected string $prefix = 'wise_login_security:failed:',
        protected int $decayMinutes = 60
    ) {
    }

    protected function table(): string
    {
        return config('wise-auth.login.tables.failed_attempts', 'auth_login_attempts');
    }

    public function getAttempts(string $key): int
    {
        $row = Db::name($this->table())
            ->where('cache_key', $this->prefix . $key)
            ->find();
        return $row ? (int) $row['attempts'] : 0;
    }

    public function increment(string $key): int
    {
        $fullKey     = $this->prefix . $key;
        $expire      = time() + $this->decayMinutes * 60;
        $nowDateTime = date('Y-m-d H:i:s');
        $table       = $this->table();

        $updated = Db::name($table)
            ->where('cache_key', $fullKey)
            ->inc('attempts')
            ->update(['expire_at' => $expire, 'update_time' => $nowDateTime]);

        if ($updated === 0) {
            try {
                Db::name($table)->insert([
                    'cache_key'   => $fullKey,
                    'attempts'    => 1,
                    'expire_at'   => $expire,
                    'create_time' => $nowDateTime,
                    'update_time' => $nowDateTime,
                ]);

                return 1;
            } catch (\Throwable) {
                Db::name($table)
                    ->where('cache_key', $fullKey)
                    ->inc('attempts')
                    ->update(['expire_at' => $expire, 'update_time' => $nowDateTime]);
            }
        }

        $row = Db::name($table)->where('cache_key', $fullKey)->find();
        return $row ? (int) $row['attempts'] : 1;
    }

    public function set(string $key, int $value): void
    {
        $this->write($key, $value, $this->decayMinutes);
    }

    /**
     * 设置值并同时设置 TTL
     *
     * {@inheritDoc}
     */
    public function setWithTtl(string $key, int $value, int $minutes): void
    {
        $this->write($key, $value, max(1, $minutes));
    }

    /**
     * 覆盖写入一行（update → insert → 冲突再 update）
     *
     * 原实现的 find() → insert/update 在并发下会重复插入并撞唯一索引；
     * 统一收敛为「先更新，受影响行数为 0 再插入，插入冲突则回到更新」。
     *
     * @param string $key     计数器键（不含前缀）
     * @param int    $value   写入值
     * @param int    $minutes 过期分钟数
     * @return void
     */
    protected function write(string $key, int $value, int $minutes): void
    {
        $fullKey     = $this->prefix . $key;
        $nowDateTime = date('Y-m-d H:i:s');
        $expire      = time() + $minutes * 60;
        $table       = $this->table();
        $payload     = [
            'attempts'    => $value,
            'update_time' => $nowDateTime,
            'expire_at'   => $expire,
        ];

        $updated = Db::name($table)->where('cache_key', $fullKey)->update($payload);
        if ($updated !== 0) {
            return;
        }

        try {
            Db::name($table)->insert($payload + [
                'cache_key'   => $fullKey,
                'create_time' => $nowDateTime,
            ]);
        } catch (\Throwable) {
            Db::name($table)->where('cache_key', $fullKey)->update($payload);
        }
    }

    public function reset(string $key): void
    {
        Db::name($this->table())
            ->where('cache_key', $this->prefix . $key)
            ->delete();
    }

    public function expire(string $key, int $minutes): void
    {
        Db::name($this->table())
            ->where('cache_key', $this->prefix . $key)
            ->update(['expire_at' => time() + $minutes * 60]);
    }

    public function ttl(string $key): int
    {
        $row = Db::name($this->table())
            ->where('cache_key', $this->prefix . $key)
            ->find();
        if (!$row) {
            return -1;
        }
        $ttl = (int) $row['expire_at'] - time();
        return max(0, $ttl);
    }
}
