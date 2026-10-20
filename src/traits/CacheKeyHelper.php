<?php
/**
 * 缓存键辅助 Trait
 *
 * 提供统一的缓存键生成与缓存驱动初始化方法，
 * 供 RbacManager 和 PermissionRegistrar 共用，消除重复代码。
 */
namespace wise\auth\traits;

use think\facade\Cache;

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
            // 指定 store 未注册时回退到框架默认 store：Cache::store() 对未注册的
            // store 会抛 InvalidArgumentException，不能让鉴权链路因此中断。
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
}
