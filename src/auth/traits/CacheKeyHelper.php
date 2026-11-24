<?php
/**
 * 缓存键辅助 Trait
 *
 * 提供统一的缓存键生成与缓存驱动初始化方法，
 * 供 RbacManager 和 PermissionRegistrar 共用，消除重复代码。
 */
namespace wise\auth\traits;

use think\facade\Cache;
use wise\support\runtime\Runtime;

trait CacheKeyHelper
{
    /**
     * 缓存实例
     *
     * @var \think\Cache|null
     */
    protected $cache = null;

    /**
     * 是否已初始化缓存
     *
     * @var bool
     */
    protected bool $cacheInitialized = false;

    /**
     * 缓存是否已启用
     *
     * @var bool|null
     */
    protected ?bool $cacheEnabled = null;

    /**
     * 初始化缓存驱动（统一入口）
     *
     * 从 wise-auth.cache_enabled / wise-auth.cache_store 配置读取，
     * 将初始化后的缓存实例存入 $this->cache，并设置 $this->cacheEnabled 标记。
     * 多次调用只初始化一次。
     */
    protected function initCache(): void
    {
        if ($this->cacheInitialized) {
            return;
        }

        $this->cacheEnabled = config('wise-auth.cache_enabled', true);
        if ($this->cacheEnabled) {
            $store = config('wise-auth.cache_store');
            $registeredStores = (array) config('cache.stores', []);
            if ($store && !isset($registeredStores[$store])) {
                $store = null;
            }
            if ($store) {
                $this->cache = Cache::store($store);
            } else {
                $this->cache = Cache::store();
            }
        }

        $this->cacheInitialized = true;
    }

    /**
     * 获取缓存键名
     *
     * @param string $key
     * @return string
     */
    protected function getCacheKey(string $key): string
    {
        $prefix = config('wise-auth.cache_prefix', 'wise-auth:');
        return $prefix . $key;
    }


    /**
     * 失败告警去重（key = op|key）
     *
     * 必须是**实例属性**：key 含 user_id 等请求维度（如 user_perms:admin:123），
     * 做成 static 后常驻 worker 下会随访问过的用户数无界增长且永不释放
     * （FPM 每请求重建进程，察觉不到）。实例级同样保留「同一请求内同 key 只警告一次」。
     *
     * @var array<string, bool>
     */
    protected array $cacheWarned = [];

    /**
     * 读缓存（失败返回 $default）
     */
    protected function cacheGet(string $key, mixed $default = null): mixed
    {
        if (!$this->cacheAvailable()) {
            return $default;
        }

        try {
            return $this->cache->get($key, $default);
        } catch (\Throwable $e) {
            $this->cacheWarn('get', $key, $e);

            return $default;
        }
    }

    /**
     * 写缓存（失败返回 false；对瞬时占用做一次重试）
     */
    protected function cacheSet(string $key, mixed $value, ?int $ttl = null): bool
    {
        return (bool) $this->cacheRetry('set', $key, function () use ($key, $value, $ttl) {
            return null === $ttl
                ? $this->cache->set($key, $value)
                : $this->cache->set($key, $value, $ttl);
        });
    }

    /**
     * 删除缓存键（失败返回 false）
     */
    protected function cacheDelete(string $key): bool
    {
        return (bool) $this->cacheRetry('delete', $key, function () use ($key) {
            return $this->cache->delete($key);
        });
    }

    /**
     * 自增缓存值（失败返回 false）
     *
     * @return false|int
     */
    protected function cacheInc(string $key, int $step = 1)
    {
        return $this->cacheRetry('inc', $key, function () use ($key, $step) {
            return $this->cache->inc($key, $step);
        });
    }

    /**
     * 带一次重试的执行器（Windows 下文件占用多为瞬时）
     *
     * @param  callable $fn
     * @return mixed
     */
    private function cacheRetry(string $op, string $key, callable $fn): mixed
    {
        if (!$this->cacheAvailable()) {
            return false;
        }

        $mark = $op . '|' . $key;

        try {
            return $fn();
        } catch (\Throwable $e) {
            if (isset($this->cacheWarned[$mark])) {
                return false;
            }

            Runtime::sleep(0.02);

            try {
                return $fn();
            } catch (\Throwable $e2) {
                $this->cacheWarn($op, $key, $e2);

                return false;
            }
        }
    }

    /**
     * 缓存是否可用
     */
    private function cacheAvailable(): bool
    {
        $this->initCache();

        return (bool) $this->cacheEnabled && $this->cache !== null;
    }

    /**
     * 记录缓存失败告警（同 op+key 每进程一次）
     */
    private function cacheWarn(string $op, string $key, \Throwable $e): void
    {
        $mark = $op . '|' . $key;
        if (isset($this->cacheWarned[$mark])) {
            return;
        }
        $this->cacheWarned[$mark] = true;

        $message = sprintf('[wise-auth][cache-degraded] 缓存 %s 失败，已降级（不影响业务）：%s —— %s', $op, $key, $e->getMessage());

        if (function_exists('trace')) {
            trace($message, 'info');
        } else {
            error_log($message);
        }
    }
}
