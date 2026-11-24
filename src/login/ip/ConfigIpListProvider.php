<?php
declare(strict_types=1);

namespace wise\login\ip;

use think\App;

/**
 * 从配置文件读取 IP 黑白名单的默认实现
 *
 * 配置项：config('wise-auth.login.ip_list.whitelist') / blacklist
 */
class ConfigIpListProvider implements IpListProviderInterface
{
    /** @var array<string>|null 白名单缓存 */
    protected ?array $whitelistCache = null;

    /** @var array<string>|null 黑名单缓存 */
    protected ?array $blacklistCache = null;

    public function __construct(protected App $app)
    {
    }

    public function getWhitelist(): array
    {
        if ($this->whitelistCache === null) {
            $list = $this->app->config->get('wise-auth.login.ip_list.whitelist', []);
            $this->whitelistCache = is_array($list) ? $list : [];
        }
        return $this->whitelistCache;
    }

    public function getBlacklist(): array
    {
        if ($this->blacklistCache === null) {
            $list = $this->app->config->get('wise-auth.login.ip_list.blacklist', []);
            $this->blacklistCache = is_array($list) ? $list : [];
        }
        return $this->blacklistCache;
    }
}
