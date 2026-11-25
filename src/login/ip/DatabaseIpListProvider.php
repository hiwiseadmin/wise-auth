<?php
declare(strict_types=1);

namespace wise\login\ip;

use think\facade\Cache;
use wise\login\model\IpList;

/**
 * 数据库 IP 列表提供器＼�
 *
 * 从 auth_ip_lists 表读取 IP 黑白名单。
 * 支持 5 分钟缓存，减少数据库查询。
 *
 * 切换方式：config('wise-auth.login.ip_list.provider') = 'database'
 */
class DatabaseIpListProvider implements IpListProviderInterface
{
    protected int $cacheTtl;

    public function __construct()
    {
        $this->cacheTtl = (int) config('wise-auth.login.ip_list.provider_cache_ttl', 300);
    }

    public function getWhitelist(): array
    {
        $key = 'wise_login_security:ip:whitelist';
        $cached = Cache::get($key);
        if (is_array($cached)) {
            return $cached;
        }

        $list = (array) IpList::getActiveWhitelist();
        Cache::set($key, $list, $this->cacheTtl);
        return $list;
    }

    public function getBlacklist(): array
    {
        $key = 'wise_login_security:ip:blacklist';
        $cached = Cache::get($key);
        if (is_array($cached)) {
            return $cached;
        }

        $list = (array) IpList::getActiveBlacklist();
        Cache::set($key, $list, $this->cacheTtl);
        return $list;
    }

    /**
     * 清除缓存（在后台修改 IP 列表后调用）
     */
    public static function clearCache(): void
    {
        Cache::delete('wise_login_security:ip:whitelist');
        Cache::delete('wise_login_security:ip:blacklist');
    }
}
