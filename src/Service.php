<?php
/**
 * WiseAuth 服务提供者
 *
 * 在 ThinkPHP6 框架启动时自动注册（通过 composer.json 的 extra.think.services）。
 *
 * 职责：
 * 1. 注册核心服务到容器
 * 2. 注册控制台命令
 * 3. 注册事件订阅者
 */
namespace wise\auth;

use think\facade\Config;

class Service extends \think\Service
{
    use trait\ServiceTrait;

    /**
     * 注册服务
     */
    public function register(): void
    {
        // 合并包默认配置到全局配置
        $authConfig = $this->mergeConfig('wise-auth');

        // 自动将重定向目标 URL 加入白名单，防止拦截死循环
        $whitelistUrls = [];

        if (!empty($authConfig['unauthorized_redirect'])) {
            $whitelistUrls[] = $authConfig['unauthorized_redirect'];
        }
        if (!empty($authConfig['forbidden_redirect']) && $authConfig['forbidden_redirect'] !== ($authConfig['unauthorized_redirect'] ?? '')) {
            $whitelistUrls[] = $authConfig['forbidden_redirect'];
        }
        if (!empty($authConfig['not_logged_in_redirect']) && $authConfig['not_logged_in_redirect'] !== ($authConfig['unauthorized_redirect'] ?? '')) {
            $whitelistUrls[] = $authConfig['not_logged_in_redirect'];
        }

        if (!empty($whitelistUrls)) {
            if (is_array($authConfig['whitelist_routes'])) {
                foreach ($whitelistUrls as $url) {
                    if (!in_array($url, $authConfig['whitelist_routes'], true)) {
                        $authConfig['whitelist_routes'][] = $url;
                    }
                }
            } else {
                $authConfig['whitelist_routes'] = $whitelistUrls;
            }
            Config::set($authConfig, 'wise-auth');
        }

        // 绑定核心服务到容器（单例）
        $this->app->bind('wise.auth.manager', \wise\auth\service\RbacManager::class);
        $this->app->bind(\wise\auth\service\RbacManager::class, \wise\auth\service\RbacManager::class);

        $this->app->bind('wise.auth.registrar', \wise\auth\service\PermissionRegistrar::class);
        $this->app->bind(\wise\auth\service\PermissionRegistrar::class, \wise\auth\service\PermissionRegistrar::class);

        $this->app->bind('wise.auth.permission', \wise\auth\service\PermissionService::class);
        $this->app->bind(\wise\auth\service\PermissionService::class, \wise\auth\service\PermissionService::class);
    }

    /**
     * 启动服务
     */
    public function boot(): void
    {
        // 注册控制台命令
        $this->registerCommands();

        // 注册事件订阅者
        $this->registerEventSubscriber();
    }

    /**
     * 注册控制台命令
     */
    protected function registerCommands(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([
                \wise\auth\command\Publish::class,
                \wise\auth\command\ClearCache::class,
                \wise\auth\command\ImportPermissions::class,
            ]);
        }
    }

    /**
     * 注册事件订阅者
     */
    protected function registerEventSubscriber(): void
    {
        $this->app->event->subscribe(\wise\auth\subscribe\AuthEventSubscriber::class);
    }
}
