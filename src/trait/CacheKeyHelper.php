<?php
/**
 * 缓存键辅助 Trait
 *
 * 提供统一的缓存键生成方法，供 RbacManager 和 PermissionRegistrar 共用。
 */
namespace wise\auth\trait;

trait CacheKeyHelper
{
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
