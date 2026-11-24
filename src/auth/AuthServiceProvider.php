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
use think\Service as ThinkService;
use wise\support\traits\RegistersMigrations;
use wise\support\traits\ServiceTrait;

class AuthServiceProvider extends ThinkService
{
    use ServiceTrait;
    use RegistersMigrations;

    /**
     * 包根目录覆盖：本 Provider 位于 `src/auth/`（比默认约定深一层），
     * `dirname(__FILE__, 2)` 会得到 `src/`，而迁移在包根 `database/migrations`。
     * 覆盖 trait 的 `migrationPackageRoot()` 以正确定位。
     */
    protected function migrationPackageRoot(): string
    {
        return dirname(__DIR__, 2);
    }

    /**
     * 包根目录覆盖：配置同样在包根 `config/`，而非 `src/config/`。
     */
    protected function getPackageConfigFilePath(string $configName): string
    {
        return dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . $configName . '.php';
    }

    /**
     * 注册服务
     */
    public function register(): void
    {
        $authConfig = $this->mergeConfig('wise-auth');

        $this->registerCacheStore($authConfig);

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

        $this->app->bind('wise.auth.manager', \wise\auth\service\RbacManager::class);
        $this->app->bind(\wise\auth\service\RbacManager::class, \wise\auth\service\RbacManager::class);

        $this->app->bind('wise.auth.registrar', \wise\auth\service\PermissionRegistrar::class);
        $this->app->bind(\wise\auth\service\PermissionRegistrar::class, \wise\auth\service\PermissionRegistrar::class);

        $this->app->bind('wise.auth.permission', \wise\auth\service\PermissionService::class);
        $this->app->bind(\wise\auth\service\PermissionService::class, \wise\auth\service\PermissionService::class);

        $this->app->bind('wise.auth.constraint', \wise\auth\service\ConstraintEngine::class);
        $this->app->bind(\wise\auth\service\ConstraintEngine::class, \wise\auth\service\ConstraintEngine::class);

        $this->app->bind('wise.auth.datascope', \wise\auth\service\DataScope::class);
        $this->app->bind(\wise\auth\service\DataScope::class, \wise\auth\service\DataScope::class);

        $this->registerCommands();
    }

    /**
     * 注册本包专属缓存 store 到框架 cache 配置
     *
     * 背景：clearAllCache() 在不支持「按前缀删除」的驱动（File/Memcache 等）下会退化为
     * $handler->clear()，即清空整个 store。为包指定独立 store 后，该操作只影响本包缓存。
     *
     * 实现约束：
     *   - 只做新增：宿主若已定义同名 store，完全尊重宿主配置；
     *   - 只合并 cache.stores 节点：Config::set() 是浅合并，必须整份写回才不丢宿主驱动；
     *   - 不修改框架 config/cache.php，也不修改 runtime 配置缓存文件。
     *
     * @param array $authConfig 合并后的 wise-auth 配置
     */
    protected function registerCacheStore(array $authConfig): void
    {
        $storeName = $authConfig['cache_store'] ?? null;
        if (!is_string($storeName) || $storeName === '') {
            return;
        }

        $cacheConfig = (array) Config::get('cache', []);
        $stores      = (array) ($cacheConfig['stores'] ?? []);

        if (isset($stores[$storeName])) {
            return;
        }

        $storeConfig = $authConfig['cache_store_config'] ?? null;
        if (!is_array($storeConfig) || $storeConfig === []) {
            $storeConfig = $this->buildDefaultCacheStoreConfig($cacheConfig);
        }
        if (empty($storeConfig['type'])) {
            return;
        }

        $stores[$storeName] = $storeConfig;
        Config::set(['stores' => $stores], 'cache');
    }

    /**
     * 依据宿主 cache 配置推导包专属 store 的驱动参数（做目录/前缀隔离）
     *
     * @param array $cacheConfig 宿主 cache 配置
     * @return array store 驱动参数；无法推导时返回空数组
     */
    protected function buildDefaultCacheStoreConfig(array $cacheConfig): array
    {
        $stores      = (array) ($cacheConfig['stores'] ?? []);
        $defaultName = $cacheConfig['default'] ?? null;

        if (!is_string($defaultName) || !isset($stores[$defaultName]) || !is_array($stores[$defaultName])) {
            $defaultName = array_key_first($stores);
        }
        if (!is_string($defaultName) || !isset($stores[$defaultName]) || !is_array($stores[$defaultName])) {
            return [];
        }

        $base = $stores[$defaultName];
        $base['type'] = $base['type'] ?? $defaultName;

        if (strtolower((string) $base['type']) === 'file') {
            $base['path'] = $this->resolveIsolatedCachePath((string) ($base['path'] ?? ''));
        } else {
            $base['prefix'] = 'wise_auth_' . (string) ($base['prefix'] ?? '');
        }

        return $base;
    }

    /**
     * 计算 File 驱动下的隔离缓存目录
     *
     * @param string $path 宿主默认 store 的 path（为空时框架回退到 runtime/cache）
     * @return string 以目录分隔符结尾的路径
     */
    protected function resolveIsolatedCachePath(string $path): string
    {
        $path = rtrim($path, '/\\');
        if ($path === '') {
            $path = rtrim($this->app->getRuntimePath(), '/\\') . DIRECTORY_SEPARATOR . 'cache';
        }

        return $path . DIRECTORY_SEPARATOR . 'wise_auth' . DIRECTORY_SEPARATOR;
    }

    /**
     * 启动服务
     */
    public function boot(): void
    {
        $this->registerMorphMap();
        $this->registerMigrations();

        $this->registerEventSubscriber();
    }

    /**
     * 注册多态映射：将用户模型 FQCN 映射为 user_type 短标识。
     *
     * 关键：HasRoles::roles() 使用 morphToMany 关联，默认写入的
     * user_type 是用户模型的 FQCN（如 app\admin\model\Admin），
     * 而 RbacManager 等查询均使用 'admin' 短标识。若不注册映射，
     * 写入与查询口径不一致，会导致角色成员数统计、权限查询全部失效。
     */
    protected function registerMorphMap(): void
    {
        $userModels = (array) config('wise-auth.user_models', []);
        $map = [];
        foreach ($userModels as $type => $class) {
            if (is_string($class) && class_exists($class)) {
                $map[$class] = $type;
            }
        }

        if (!empty($map)) {
            \think\model\relation\MorphToMany::morphMap($map);
        }
    }

    /**
     * 注册控制台命令
     */
    protected function registerCommands(): void
    {
        $this->commands([
            \wise\auth\command\ClearCache::class,
            \wise\auth\command\ImportPermissions::class,
            \wise\auth\command\AdminModify::class,
        ]);
    }

    /**
     * 注册事件订阅者
     */
    protected function registerEventSubscriber(): void
    {
        $this->app->event->subscribe(\wise\auth\subscribe\AuthEventSubscriber::class);
    }
}
