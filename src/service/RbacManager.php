<?php
/**
 * RBAC 权限验证与角色管理核心服务
 *
 * 负责权限检查、缓存管理、用户-角色-权限的关联查询。
 */
namespace wise\auth\service;

use think\facade\Db;
use wise\auth\model\Role;
use wise\auth\model\Permission;
use wise\auth\model\UserRole;
use wise\auth\exception\ConstraintViolationException;
use wise\auth\traits\CacheKeyHelper;

class RbacManager
{
    use CacheKeyHelper;

    /**
     * 路由匹配缓存代际键名（见 {@see routeMatchEpoch()}）
     */
    protected const ROUTE_MATCH_EPOCH_KEY = 'route_match_epoch';

    // =============================
    // user_type 统一解析
    // =============================

    /**
     * 默认 user_type 标识（权威来源：配置 user_models 的第一个 key）
     *
     * 注意：auth_user_role.user_type 字段存的是「配置 key」（如 'admin'、'member'），
     * 而非模型 FQCN。这是由 morphMap 写入逻辑保证的：
     *   MorphToMany::__construct 会把 FQCN 经 morphMap 转成 key 后写入。
     * 因此所有查询/统计也必须用同一个 key，保持一致。
     *
     * @return string
     */
    public function getDefaultUserType(): string
    {
        $userModels = (array) config('wise-auth.user_models', []);
        foreach ($userModels as $type => $class) {
            if (is_string($class) && class_exists($class)) {
                return (string) $type;
            }
        }

        // 回退：从默认用户模型 FQCN 取短名
        $default = config('wise-auth.default_user_model');
        if (is_string($default)) {
            $parts = explode('\\', $default);
            return strtolower((string) array_pop($parts));
        }

        return 'admin';
    }

    /**
     * 解析 user_type：null/空 时回退到默认值
     *
     * @param string|null $userType
     * @return string
     */
    protected function resolveUserType(?string $userType): string
    {
        return $userType !== null && $userType !== ''
            ? $userType
            : $this->getDefaultUserType();
    }

    /**
     * 获取用户权限版本号（用于会话失效判断）
     *
     * 当用户角色变更时，版本号递增。中间件可对比 session 中的版本号
     * 与当前版本号，不一致时强制重新鉴权。
     *
     * @param int|string $userId
     * @param string     $userType
     * @return int
     */
    public function getUserPermissionVersion($userId, string $userType): int
    {
        $this->initCache();
        $versionKey = $this->getCacheKey("perm_version:{$userType}:{$userId}");

        if ($this->cache) {
            $version = $this->cache->get($versionKey);
            if ($version !== null) {
                return (int) $version;
            }
        }

        return 0;
    }

    /**
     * 递增用户权限版本号（角色变更时调用）
     *
     * @param int|string $userId
     * @param string     $userType
     * @return int 新版本号
     */
    public function incrementPermissionVersion($userId, string $userType): int
    {
        $this->initCache();
        if (!$this->cache) {
            return 0;
        }

        $versionKey = $this->getCacheKey("perm_version:{$userType}:{$userId}");
        $newVersion = $this->cache->inc($versionKey);

        // 设置较长的 TTL（版本号不因缓存过期而丢失）
        if ($newVersion === 1) {
            $this->cache->set($versionKey, 1, 86400 * 30);
        }

        return (int) $newVersion;
    }
    // =============================

    /**
     * 检查用户是否拥有指定权限（支持通配符）
     *
     * 支持 `*` 通配符匹配：
     *   - admin.*         → 匹配所有 admin. 开头的权限
     *   - admin.user.*    → 匹配 admin.user.create, admin.user.edit 等
     *   - *               → 匹配所有权限
     *
     * @param int|string $userId       用户ID
     * @param string     $userType     用户类型
     * @param string     $permission   权限标识（支持通配符）
     * @return bool
     */
    public function check($userId, string $userType, string $permission): bool
    {
        // 超级管理员
        if ($this->isSuperAdmin($userId, $userType)) {
            return true;
        }

        // 通配符检查
        if ($permission === '*' || str_contains($permission, '*')) {
            return $this->checkWildcard($userId, $userType, $permission);
        }

        $permissions = $this->getUserPermissions($userId, $userType);
        return in_array($permission, $permissions);
    }

    /**
     * 通配符权限检查
     *
     * @param int|string $userId
     * @param string     $userType
     * @param string     $wildcard 如 'admin.user.*'
     * @return bool
     */
    protected function checkWildcard($userId, string $userType, string $wildcard): bool
    {
        if ($wildcard === '*') {
            return true;
        }

        $userPerms = $this->getUserPermissions($userId, $userType);

        // 将通配符模式转为正则
        $regex = '#^' . str_replace('\*', '.+', preg_quote($wildcard, '#')) . '$#';

        foreach ($userPerms as $perm) {
            if (preg_match($regex, $perm)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 检查用户是否拥有指定权限中的任意一个（OR模式，支持通配符）
     *
     * @param int|string $userId
     * @param string     $userType
     * @param array      $permissions
     * @return bool
     */
    public function checkAny($userId, string $userType, array $permissions): bool
    {
        if ($this->isSuperAdmin($userId, $userType)) {
            return true;
        }

        $userPerms = $this->getUserPermissions($userId, $userType);

        foreach ($permissions as $perm) {
            if (str_contains($perm, '*') || $perm === '*') {
                // 通配符模式：展开匹配
                $regex = $perm === '*' ? '#.+#'
                    : '#^' . str_replace('\*', '.+', preg_quote($perm, '#')) . '$#';
                foreach ($userPerms as $up) {
                    if (preg_match($regex, $up)) {
                        return true;
                    }
                }
            } elseif (in_array($perm, $userPerms)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 检查用户是否拥有全部指定权限（AND模式，支持通配符）
     *
     * @param int|string $userId
     * @param string     $userType
     * @param array      $permissions
     * @return bool
     */
    public function checkAll($userId, string $userType, array $permissions): bool
    {
        if ($this->isSuperAdmin($userId, $userType)) {
            return true;
        }

        $userPerms = $this->getUserPermissions($userId, $userType);

        foreach ($permissions as $perm) {
            if (str_contains($perm, '*') || $perm === '*') {
                $regex = $perm === '*' ? '#.+#'
                    : '#^' . str_replace('\*', '.+', preg_quote($perm, '#')) . '$#';
                $matched = false;
                foreach ($userPerms as $up) {
                    if (preg_match($regex, $up)) {
                        $matched = true;
                        break;
                    }
                }
                if (!$matched) {
                    return false;
                }
            } elseif (!in_array($perm, $userPerms)) {
                return false;
            }
        }

        return true;
    }

    /**
     * 超级管理员 ID 列表（运行时只读缓存）
     *
     * 首次访问时从 PHP 配置文件直接加载，后续请求复用。
     * static 确保同一进程内只加载一次，避免每次鉴权都 require 文件。
     *
     * @var array|null
     */
    private static $superAdminIds = null;

    /**
     * 从 PHP 配置文件直接加载超级管理员 ID 列表
     *
     * 优先级（绕过可变的 config() 系统，防止运行时篡改）：
     *   1. config/wise-auth.php → super_admin_ids
     *   2. config/app.php       → super_admin_ids
     *   3. [1] 作为最终兜底
     *
     * @return array
     */
    private static function loadSuperAdminIds(): array
    {
        $configPath = app()->getConfigPath();

        // 1. 优先读取 wise-auth.php 配置
        $wiseAuthFile = $configPath . 'wise-auth.php';
        if (is_file($wiseAuthFile)) {
            $config = require $wiseAuthFile;
            if (is_array($config) && !empty($config['super_admin_ids'])) {
                return (array) $config['super_admin_ids'];
            }
        }

        // 2. 回退到 app.php 的系统配置
        $appConfigFile = $configPath . 'app.php';
        if (is_file($appConfigFile)) {
            $config = require $appConfigFile;
            if (is_array($config) && !empty($config['super_admin_ids'])) {
                return (array) $config['super_admin_ids'];
            }
        }

        // 3. 两个配置文件均未设置 → 返回空列表，通过 super_role 机制判定超管
        return [];
    }

    /**
     * 检查用户是否为超级管理员
     *
     * @param int|string $userId
     * @param string     $userType 用户类型，用于多态关联查询
     * @return bool
     */
    public function isSuperAdmin($userId, ?string $userType = null): bool
    {
        $userType = $this->resolveUserType($userType);

        // 从文件直接加载超管 ID（绕过可变 config() 系统，防御运行时篡改）
        if (self::$superAdminIds === null) {
            self::$superAdminIds = self::loadSuperAdminIds();
        }
        if (in_array($userId, self::$superAdminIds)) {
            return true;
        }

        // 检查 super_role 配置（需要匹配 user_type，结果缓存以避免每次鉴权重复查询）
        $superRole = config('wise-auth.super_role');
        if ($superRole) {
            $this->initCache();
            $cacheKey = $this->getCacheKey("super_admin:{$userType}:{$userId}");
            if ($this->cache) {
                $cached = $this->cache->get($cacheKey);
                if ($cached !== null) {
                    return (bool) $cached;
                }
            }
            $userRoleTable = 'auth_user_role';
            $roleId = Role::where('slug', $superRole)->value('id');
            $result = false;
            if ($roleId) {
                $count = \think\facade\Db::name($userRoleTable)
                    ->where('user_id', $userId)
                    ->where('user_type', $userType)
                    ->where('role_id', $roleId)
                    ->where(function ($query) {
                        $this->addExpiredFilter($query);
                    })
                    ->count();
                $result = $count > 0;
            }
            if ($this->cache) {
                $ttl = config('wise-auth.cache_ttl', 3600);
                $this->cache->set($cacheKey, (int) $result, $ttl);
            }
            if ($result) {
                return true;
            }
        }

        return false;
    }

    // =============================
    // 用户权限获取
    // =============================

    /**
     * 获取用户所有权限标识
     *
     * @param int|string $userId
     * @param string     $userType
     * @return array
     */
    public function getUserPermissions($userId, string $userType): array
    {
        if ($this->isSuperAdmin($userId, $userType)) {
            return ['*'];
        }

        // 缓存读取
        $this->initCache();
        if ($this->cache) {
            $cacheKey = $this->getCacheKey("user_perms:{$userType}:{$userId}");
            $cached = $this->cache->get($cacheKey);
            if ($cached !== null) {
                return $cached;
            }
        }

        // 从数据库计算
        $permissions = $this->resolveUserPermissions($userId, $userType);

        // 缓存写入
        if ($this->cache) {
            $ttl = config('wise-auth.cache_ttl', 3600);
            $cacheKey = $this->getCacheKey("user_perms:{$userType}:{$userId}");
            if ($ttl) {
                $this->cache->set($cacheKey, $permissions, $ttl);
            } else {
                $this->cache->set($cacheKey, $permissions);
            }
        }

        return $permissions;
    }

    /**
     * 实际解析用户权限（含 JOIN 优化）
     *
     * 将原来的 3-4 轮 DB 查询缩减为 2 轮：
     *   1. 查询用户角色 ID + 展开继承（不可避免的树形查询）
     *   2. 单次 JOIN 查询获取所有权限 ident（合并 role_permission + permissions）
     *
     * @param int|string $userId
     * @param string     $userType
     * @return array
     */
    protected function resolveUserPermissions($userId, string $userType): array
    {
        // 获取用户直接分配的角色ID（排除已过期）
        $userRoles = UserRole::where('user_id', $userId)
            ->where('user_type', $userType)
            ->where(function ($query) {
                $this->addExpiredFilter($query);
            })
            ->column('role_id');

        if (empty($userRoles)) {
            return [];
        }

        // 递归获取所有角色权限（含继承）
        return $this->resolveRolesPermissions($userRoles);
    }

    /**
     * 通用过期时间过滤条件
     *
     * @param \think\db\Query|\think\db\BaseQuery $query
     */
    private function addExpiredFilter($query): void
    {
        // expired_at 是 DATETIME 列：必须用 datetime 字符串比较，
        // 不能与 time() 的 int 时间戳比较（类型强转导致过滤恒真/恒假）。
        $query->whereNull('expired_at')
              ->whereOr('expired_at', '>', date('Y-m-d H:i:s'));
    }

    /**
     * 解析角色集合的权限ID（含继承，仅返回启用状态的权限）
     *
     * 用于菜单过滤等需要权限ID的场景，避免直接操作中间表而绕过继承与状态检查。
     *
     * @param array $roleIds
     * @return array
     */
    public function resolveRolesPermissionIds(array $roleIds): array
    {
        $rawIds = $this->resolveRawPermissionIds($roleIds);

        if (empty($rawIds)) {
            return [];
        }

        return Permission::whereIn('id', $rawIds)
            ->where('status', 1)
            ->column('id');
    }

    /**
     * 解析角色集合的所有权限标识（含继承，JOIN 优化）
     *
     * 使用单次 JOIN 查询直接获取 ident，合并原来的两步查询。
     *
     * @param array $roleIds
     * @return array
     */
    public function resolveRolesPermissions(array $roleIds): array
    {
        $allRoles = $this->expandRoleIdsWithInheritance($roleIds);
        if (empty($allRoles)) {
            return [];
        }

        $rolePermissionTable = 'auth_role_permission';
        $permissionTable    = 'auth_permissions';

        // 单次 JOIN 查询：role_permission ← permissions，直接返回 ident
        $db = \think\facade\Db::name($rolePermissionTable);
        $results = $db->alias('rp')
            ->join($permissionTable . ' p', 'rp.permission_id = p.id')
            ->whereIn('rp.role_id', $allRoles)
            ->where('p.status', 1)
            ->column('p.ident');

        return array_values(array_unique($results));
    }

    /**
     * 从中间表解析角色集合的原始权限ID（含继承展开，不做状态过滤）
     *
     * @param array $roleIds
     * @return array
     */
    private function resolveRawPermissionIds(array $roleIds): array
    {
        $allRoles = $this->expandRoleIdsWithInheritance($roleIds);

        $permissionIds = [];
        $rolePermissionTable = 'auth_role_permission';
        $db = \think\facade\Db::name($rolePermissionTable);
        $records = $db->whereIn('role_id', $allRoles)->select()->toArray();
        foreach ($records as $record) {
            $permissionIds[] = $record['permission_id'];
        }
        return array_unique($permissionIds);
    }

    /**
     * 展开角色ID（含继承）
     *
     * @param array $roleIds
     * @return array
     */
    protected function expandRoleIdsWithInheritance(array $roleIds): array
    {
        if (!config('wise-auth.inheritance_enabled', true)) {
            return $roleIds;
        }

        $maxDepth = config('wise-auth.inheritance_max_depth', 10);
        // null 或 0 均表示无限制
        if ($maxDepth === null) {
            $maxDepth = 0;
        }
        $allRoles = $roleIds;
        $currentLevel = $roleIds;
        $depth = 0;

        while (!empty($currentLevel) && ($maxDepth === 0 || $depth < $maxDepth)) {
            $parentIds = Role::whereIn('id', $currentLevel)
                ->where('is_inherit', 1)
                ->where('parent_id', '>', 0)
                ->column('parent_id');

            $parentIds = array_unique(array_filter($parentIds));
            $newParents = array_diff($parentIds, $allRoles);

            if (empty($newParents)) {
                break;
            }

            $allRoles = array_merge($allRoles, $newParents);
            $currentLevel = $newParents;
            $depth++;
        }

        return array_unique($allRoles);
    }

    // =============================
    // 缓存管理
    // =============================

    /**
     * 清除指定用户的权限缓存（同时递增权限版本号）
     *
     * @param int|string $userId
     * @param string     $userType
     */
    public function clearUserCache($userId, ?string $userType = null): void
    {
        $userType = $this->resolveUserType($userType);
        $this->initCache();
        if (!$this->cache) {
            return;
        }

        $cacheKey = $this->getCacheKey("user_perms:{$userType}:{$userId}");
        $this->cache->delete($cacheKey);

        // 超管判定缓存必须一并失效：否则解除 super_admin 角色后，
        // isSuperAdmin() 仍命中旧缓存，用户在一整个 TTL 内继续拥有全部权限。
        $this->cache->delete($this->getCacheKey("super_admin:{$userType}:{$userId}"));

        // 递增权限版本号（用于会话失效检测）
        $this->incrementPermissionVersion($userId, $userType);
    }

    /**
     * 清除所有权限缓存
     */
    public function clearAllCache(): void
    {
        $this->initCache();
        if (!$this->cache) {
            return;
        }

        // 尝试 Tag 清除（best-effort）
        // 注意 1：本包所有权限缓存均以普通键写入、从未打过该 tag，且 TagSet::clear()
        //         在标签下无键时恒返回 true。这里绝不能置 $tagCleared = true，
        //         否则会跳过下面的按驱动前缀清理分支，导致 user_perms / super_admin
        //         等缓存永不失效（权限吊销不生效）。
        // 注意 2：必须用 $this->cache（包专属 store 驱动实例），而非 Cache 门面
        //         （框架默认 store），否则 tag 操作会打到另一个 store 上。
        $tagCleared = false;
        try {
            $this->cache->tag('wiseauth_permissions')->clear();
        } catch (\Throwable) {
            // Tag 驱动不支持，走 fallback
        }

        // fallback: 按驱动类型选择清除策略
        if (!$tagCleared) {
            $handler = $this->cache->handler();
            $cachePrefix = $this->getCacheKey('');

            // Redis / Predis: 使用 keys 扫描 + del 批量删除
            if (class_exists('Redis') && $handler instanceof \Redis) {
                try {
                    $keys = $handler->keys($cachePrefix . '*');
                    if (!empty($keys)) {
                        $handler->del($keys);
                    }
                } catch (\Throwable) {
                    // Redis keys/del 失败，静默忽略
                }
            } elseif ($handler !== null && method_exists($handler, 'keys') && method_exists($handler, 'del')) {
                // 类 Redis 驱动（如 Predis\Client），使用相同模式
                try {
                    $keys = $handler->keys($cachePrefix . '*');
                    if (!empty($keys)) {
                        $handler->del($keys);
                    }
                } catch (\Throwable) {
                    // 模式扫描失败，静默忽略
                }
            } elseif ($handler !== null && method_exists($handler, 'clear')) {
                // File / Memcache / Database 驱动：使用 clear 方法
                // 注意：clear 可能清除整个存储，适用于隔离的缓存 store
                try {
                    $handler->clear();
                } catch (\Throwable) {
                    // clear 失败，静默忽略
                }
            } else {
                // handler() 可能返回 null（如 file 驱动未覆写 handler()）：
                // 回退 Cache 级 clear，避免 method_exists(null, ...) 抛 TypeError 导致权限变更事件中断
                try { $this->cache->clear(); } catch (\Throwable) {}
            }
            // 对于不支持上述方法的驱动（如 Array / Wincache），
            // 依赖事件驱动的 clearUserCache 逐用户清除
        }

        // 路由匹配缓存必须显式清理：tag 清除覆盖不到未打 tag 的
        // `route_perms_map` 与 `route_match:*`（见 clearRouteMatchCache 说明）
        $this->clearRouteMatchCache();
    }

    /**
     * 清除路由匹配缓存（全量路由权限映射 + 单路由匹配结果）
     *
     * 背景：`route_perms_map` 与 `route_match:*` 均以普通键写入（未打 tag），
     * 因此 `Cache::tag('wiseauth_permissions')->clear()` **清除不到它们** —— 表现为
     * 「改了权限 route、或修复了匹配逻辑，却最长 1 小时不生效」。
     *
     * 实现：
     *  - `route_perms_map`：单键，直接删除；
     *  - `route_match:*`：键按路由动态生成、无法穷举 → **递增代际**使其整体失效
     *    （旧键不再被读取，随 TTL 自然过期）。File 等驱动不支持通配删除，故不逐键清理。
     *
     * @see routeMatchEpoch()
     */
    public function clearRouteMatchCache(): void
    {
        $this->initCache();
        if (!$this->cache) {
            return;
        }

        $this->cache->delete($this->getCacheKey('route_perms_map'));

        // 递增代际（永久键：避免其自身过期归零后与历史代际号撞键）
        $this->cache->set(
            $this->getCacheKey(self::ROUTE_MATCH_EPOCH_KEY),
            $this->routeMatchEpoch() + 1,
            0
        );
    }

    /**
     * 清除角色关联缓存（角色权限变更时调用）
     *
     * @param int $roleId
     */
    public function clearRoleCache(int $roleId): void
    {
        $this->initCache();
        if (!$this->cache) {
            return;
        }

        // 获取该角色的所有用户
        $userRoleTable = 'auth_user_role';
        $users = \think\facade\Db::name($userRoleTable)
            ->where('role_id', $roleId)
            ->select()
            ->toArray();

        if (empty($users)) {
            return;
        }

        // 构建所有缓存键，支持批量删除
        $keys = [];
        foreach ($users as $user) {
            $userType = $user['user_type'] ?? 'admin';
            $keys[] = $this->getCacheKey("user_perms:{$userType}:{$user['user_id']}");
        }

        // 批量删除（优先使用 Redis pipeline 或多键删除）
        $this->deleteCacheKeys($keys);
    }

    /**
     * 批量删除缓存键
     *
     * 根据底层驱动类型选择最优删除策略：
     *   Redis: 使用 del() 单次批量删除
     *   File/Memcache: 逐键调用 delete()
     *
     * @param array $keys 缓存键数组
     */
    protected function deleteCacheKeys(array $keys): void
    {
        if (empty($keys) || !$this->cache) {
            return;
        }

        $handler = $this->cache->handler();

        // Redis 支持单次批量删除
        if (class_exists('Redis') && $handler instanceof \Redis) {
            try {
                $redisKeys = array_map(function ($k) {
                    // Redis handler 可能需要原始键（不含 store prefix）
                    return $k;
                }, $keys);
                $handler->del($redisKeys);
                return;
            } catch (\Throwable) {
                // 批量删除失败，回退到逐键删除
            }
        }

        // 通用逐键删除
        foreach ($keys as $key) {
            $this->cache->delete($key);
        }
    }

    // =============================
    // RBAC2 约束检查（委托给 ConstraintEngine）
    // =============================

    /**
     * 获取约束引擎实例
     *
     * @return ConstraintEngine
     */
    protected function getConstraintEngine(): ConstraintEngine
    {
        return app(ConstraintEngine::class);
    }

    /**
     * 执行约束检查
     *
     * @param string $method    检查方法名
     * @param mixed  ...$args   参数
     * @return bool
     * @throws ConstraintViolationException
     */
    public function checkConstraint(string $method, ...$args): bool
    {
        return $this->getConstraintEngine()->checkConstraint($method, ...$args);
    }

    // =============================
    // 路由匹配权限
    // =============================

    /**
     * 路由匹配缓存代际（用于一次性失效全部 `route_match:*`）
     *
     * 为什么需要代际：`route_match:` 缓存键是**按路由动态生成**的，而 File 等
     * 缓存驱动不支持「按前缀通配删除」，无法逐键清理。改用代际号写入键名后，
     * 只需递增代际即可让上一代的全部匹配缓存立即失效（旧键随 TTL 自然过期）。
     *
     * 代际键以 **0（永久）** 写入，避免其自身过期后归零、与历史代际号撞键。
     *
     * @see clearRouteMatchCache()
     */
    protected function routeMatchEpoch(): int
    {
        $this->initCache();
        if (!$this->cache) {
            return 0;
        }

        return (int) $this->cache->get($this->getCacheKey(self::ROUTE_MATCH_EPOCH_KEY), 0);
    }

    /**
     * 根据路由路径匹配权限标识
     *
     * 两级缓存策略：
     *   1. 单次路由结果缓存（route_match:md5）—— 命中率最高，快速返回
     *   2. 全量路由权限映射缓存（route_perms_map）—— 包含所有活跃路由权限，
     *      缓存未命中时从映射中计算而非查数据库，避免每次全表扫描
     *
     * @param string $route  路由路径
     * @param string $method 请求方法
     * @return array 匹配的权限标识列表
     */
    public function matchRouteToPermissions(string $route, string $method = 'GET'): array
    {
        // 键内含「代际」：clearRouteMatchCache() 递增代际即可让上一代全部匹配缓存立即失效
        //（route_match 键按路由动态生成，File 等驱动不支持通配删除）
        $cacheKey = $this->getCacheKey('route_match:' . $this->routeMatchEpoch() . ':' . md5($route . $method));

        // L1: 单次结果的精确缓存
        $this->initCache();
        if ($this->cache) {
            $cached = $this->cache->get($cacheKey);
            if ($cached !== null) {
                return $cached;
            }
        }

        // L2: 加载全量路由权限映射（自身有缓存）
        $routePerms = $this->getRoutePermissionsMap();

        $matched = [];
        foreach ($routePerms as $item) {
            if ($this->routeMatch($item['route'], $route) && $this->methodMatch($item['method'], $method)) {
                $matched[] = $item['ident'];
            }
        }

        // L1 回写
        if ($this->cache) {
            $ttl = config('wise-auth.cache_ttl', 3600);
            $this->cache->set($cacheKey, $matched, $ttl);
        }

        return $matched;
    }

    /**
     * 获取全量活跃路由权限映射（含缓存）
     *
     * 返回格式：[['route' => ..., 'method' => ..., 'ident' => ...], ...]
     * 仅查询需要的列，减少内存占用。
     *
     * @return array
     */
    protected function getRoutePermissionsMap(): array
    {
        $mapKey = $this->getCacheKey('route_perms_map');

        $this->initCache();
        if ($this->cache) {
            $cached = $this->cache->get($mapKey);
            if ($cached !== null) {
                return $cached;
            }
        }

        $routePerms = Permission::where('status', 1)
            ->where('type', 'route')
            ->column('route,method,ident', 'id');

        // 转换为索引数组方便遍历
        $result = array_values($routePerms);

        // 缓存全量数据（TTL 与主缓存一致）
        if ($this->cache) {
            $ttl = config('wise-auth.cache_ttl', 3600);
            $this->cache->set($mapKey, $result, $ttl);
        }

        return $result;
    }

    /**
     * 路由归一：消除**前导斜杠**差异
     *
     * 背景：`auth_permissions.route` 存的是菜单 `path` 原样（**带**前导斜杠，
     * 如 `/plugin/foo/index`，见 `MenuPermissionBridge::transform()`），而部分
     * 调用方传入的 route **不带**前导斜杠（如 `PluginAdminAuth`、白名单配置）。
     * 历史实现为严格字符串比较，导致「同一路由、只差一个前导斜杠」被判为不匹配
     * —— 插件侧权限节点因此**恒不生效**（详见 docs/menu-permission-auto-derivation-plan.md §8）。
     *
     * 归一规则：**只去前导斜杠，保留尾斜杠**。
     * 保留尾斜杠是必需的：`/admin/*` 与 `/admin/` 必须仍能匹配（现有单测覆盖）。
     */
    protected function normalizeRoute(string $route): string
    {
        return ltrim($route, '/');
    }

    /**
     * 路由匹配（简单模式匹配）
     *
     * 两侧路由均先经 {@see normalizeRoute()} 归一，因此
     * `/admin/user/list` 与 `admin/user/list` 视为同一路由。
     *
     * @param string $pattern 权限定义的路由模式
     * @param string $route   实际请求路由
     * @return bool
     */
    public function routeMatch(string $pattern, string $route): bool
    {
        // 统一前导斜杠差异（两侧同时归一）
        $pattern = $this->normalizeRoute($pattern);
        $route   = $this->normalizeRoute($route);

        // 大小写归一：ThinkPHP 的路由解析本身不区分动作名大小写（/admin/admin/getList
        // 与 /admin/admin/getlist 分派到同一个方法），但权限 route 来自「菜单 path 原样」，
        // 与前端实际请求的大小写经常不一致（菜单存 getlist、JS 请求 getList）。
        // 严格区分大小写会让这类节点「加载页面 200、列表接口 403」，故匹配时统一折叠。
        $pattern = strtolower($pattern);
        $route   = strtolower($route);

        // 精确匹配
        if ($pattern === $route) {
            return true;
        }

        // 通配符匹配
        $pattern = preg_quote($pattern, '#');
        $pattern = str_replace('\*', '.*', $pattern);

        // 路径参数容忍：ThinkPHP 的 pathinfo 风格参数（如 /admin/menu/edit/id/2）
        // 在路由分派前不会被剥离，而权限节点只登记到动作（/admin/menu/edit），
        // 严格全等会让「编辑表单页」这类带 id 的链接一律 403。
        // 末尾允许成对的 k/v 段（id/2、name/wisecms …）；限定成对是为了避免
        // /admin/menu 这类控制器级节点把 /admin/menu/edit 也吞进来。
        $pattern .= '(?:/[^/]+/[^/]+)*';

        return (bool)preg_match('#^' . $pattern . '/?$#', $route);
    }

    /**
     * 请求方法匹配
     *
     * @param string $patternMethod 权限定义的方法
     * @param string $actualMethod  实际请求方法
     * @return bool
     */
    protected function methodMatch(string $patternMethod, string $actualMethod): bool
    {
        $patternMethod = strtoupper(trim($patternMethod));

        // `ALL` 是人工在权限管理里常见的写法，与 `*` / `ANY` 等价；
        // 历史实现只认前两者，导致填 ALL 的权限节点永远匹配失败。
        if ($patternMethod === '*' || $patternMethod === 'ANY' || $patternMethod === 'ALL') {
            return true;
        }

        $allowedMethods = array_map('trim', explode(',', $patternMethod));
        return in_array(strtoupper($actualMethod), $allowedMethods);
    }

    // =============================
    // 角色管理
    // =============================

    /**
     * 获取角色树
     *
     * @return array
     */
    public function getRoleTree(): array
    {
        $roles = Role::where('status', 1)
            ->order('sort', 'asc')
            ->order('id', 'asc')
            ->select()
            ->toArray();

        return $this->buildTree($roles);
    }

    /**
     * 获取所有启用角色（轻量列表，供角色选择器/下拉框使用）
     *
     * 统一封装，避免框架层直接操作 Role 模型。
     *
     * @param array $fields 需要查询的字段
     * @return array
     */
    public function getAllRoles(array $fields = []): array
    {
        if (empty($fields)) {
            $fields = ['id', 'parent_id', 'name', 'slug', 'is_inherit', 'sort', 'status'];
        }

        return Role::where('status', 1)
            ->field($fields)
            ->order('sort', 'asc')
            ->order('id', 'asc')
            ->select()
            ->toArray();
    }

    /**
     * 获取角色成员数
     *
     * @param int    $roleId   角色ID
     * @param string $userType 用户类型
     * @return int
     */
    public function getRoleUserCount(int $roleId, ?string $userType = null): int
    {
        return UserRole::where('role_id', $roleId)
            ->where('user_type', $this->resolveUserType($userType))
            ->count();
    }

    /**
     * 获取角色下的用户ID列表
     *
     * @param int    $roleId   角色ID
     * @param string $userType 用户类型
     * @return array
     */
    public function getUserIdsByRole(int $roleId, ?string $userType = null): array
    {
        return UserRole::where('role_id', $roleId)
            ->where('user_type', $this->resolveUserType($userType))
            ->column('user_id');
    }

    /**
     * 移除指定用户的所有角色关联（删除用户时清理中间表）
     *
     * @param array  $userIds  用户ID列表
     * @param string $userType 用户类型
     * @return int 删除的记录数
     */
    public function detachUsersFromRoles(array $userIds, ?string $userType = null): int
    {
        if (empty($userIds)) {
            return 0;
        }

        return UserRole::where('user_id', 'in', $userIds)
            ->where('user_type', $this->resolveUserType($userType))
            ->delete();
    }

    /**
     * 移除指定角色的所有用户关联（删除角色时清理中间表）
     *
     * @param int $roleId 角色ID
     * @return int 删除的记录数
     */
    public function detachRoleUsers(int $roleId): int
    {
        return UserRole::where('role_id', $roleId)->delete();
    }

    // =============================
    // 角色查询 / CRUD（框架层统一入口，避免直接操作 Role 模型）
    // =============================

    /**
     * 获取角色模型（按 ID）
     *
     * @param int $id
     * @return Role|null
     */
    public function getRoleById(int $id): ?Role
    {
        return Role::find($id) ?: null;
    }

    /**
     * 获取角色模型（不存在时返回空实例，供表单回显使用）
     *
     * @param int $id
     * @return Role
     */
    public function getRoleOrEmpty(int $id): Role
    {
        return Role::findOrEmpty($id);
    }

    /**
     * 按 slug（ident 别名）查找角色
     *
     * @param string $slug
     * @return Role|null
     */
    public function getRoleBySlug(string $slug): ?Role
    {
        return Role::where('slug', $slug)->find() ?: null;
    }

    /**
     * 获取启用角色模型（以 ID 为键），供需要调用角色领域方法的场景
     *
     * @param array $fields
     * @return array<int, Role>
     */
    public function getRoleModels(array $fields = []): array
    {
        if (empty($fields)) {
            $fields = ['id', 'parent_id', 'name', 'slug', 'is_inherit', 'sort', 'status'];
        }

        $roles = Role::where('status', 1)
            ->field($fields)
            ->order('sort', 'asc')
            ->order('id', 'asc')
            ->select();

        $map = [];
        foreach ($roles as $role) {
            $map[(int) $role->id] = $role;
        }

        return $map;
    }

    /**
     * 分页获取角色列表（含成员数 admin_count）
     *
     * @param int    $page
     * @param int    $limit
     * @param string $keyword
     * @return array{total:int, list:array, page:int, limit:int}
     */
    public function getRolePage(int $page, int $limit, string $keyword = ''): array
    {
        $query = Role::order('sort', 'asc')->order('id', 'desc');

        if ($keyword !== '') {
            $query->where('name|slug|description', 'like', "%{$keyword}%");
        }

        $countQuery = clone $query;
        $total = $countQuery->count();
        $list  = $query->page($page, $limit)->select()->toArray();

        foreach ($list as &$role) {
            $role['admin_count'] = $this->getRoleUserCount((int) $role['id']);
        }
        unset($role);

        return ['total' => $total, 'list' => $list, 'page' => $page, 'limit' => $limit];
    }

    /**
     * 子角色数量
     *
     * @param int $parentId
     * @return int
     */
    public function countChildren(int $parentId): int
    {
        return Role::where('parent_id', $parentId)->count();
    }

    /**
     * 获取子角色列表（数组）
     *
     * @param int   $parentId
     * @param array $fields
     * @return array
     */
    public function getChildren(int $parentId, array $fields = []): array
    {
        if (empty($fields)) {
            $fields = ['id', 'name', 'slug'];
        }

        return Role::where('parent_id', $parentId)
            ->where('status', 1)
            ->field($fields)
            ->select()
            ->toArray();
    }

    /**
     * 检测循环继承（代理 Role::hasCycle）
     *
     * @param int      $parentId
     * @param int|null $excludeId
     * @return bool
     */
    public function hasRoleCycle(int $parentId, ?int $excludeId = null): bool
    {
        return Role::hasCycle($parentId, $excludeId);
    }

    /**
     * 获取角色所有祖先 ID（代理 Role::getAncestorIds）
     *
     * @param int $roleId
     * @return array
     */
    public function getRoleAncestorIds(int $roleId): array
    {
        return Role::getAncestorIds($roleId);
    }

    /**
     * 创建角色（含权限同步与缓存清理）
     *
     * @param array $data          角色字段
     * @param array $permissionIds 初始权限ID列表
     * @return Role
     */
    public function createRole(array $data, array $permissionIds = []): Role
    {
        Db::startTrans();
        try {
            $role = Role::create($data);
            if (!empty($permissionIds)) {
                $role->syncPermissions($permissionIds);
            }
            Db::commit();
        } catch (\Throwable $e) {
            Db::rollback();
            throw $e;
        }

        $this->clearAllCache();

        // 触发角色变更事件（缓存联动 + 审计日志）。此前只在订阅端 listen、
        // 无任何发布点，导致 auth_audit_log 恒为空。
        \think\facade\Event::trigger(
            new \wise\auth\event\RoleChanged('create', (int) $role->id, $role->toArray())
        );

        return $role;
    }

    /**
     * 更新角色（含权限同步与缓存清理）
     *
     * @param Role  $role
     * @param array $data
     * @param array $permissionIds
     * @return Role
     */
    public function updateRole(Role $role, array $data, array $permissionIds): Role
    {
        Db::startTrans();
        try {
            $role->save($data);
            $role->syncPermissions($permissionIds);
            Db::commit();
        } catch (\Throwable $e) {
            Db::rollback();
            throw $e;
        }

        $this->clearRoleCache((int) $role->id);

        // 触发角色变更事件（缓存联动 + 审计日志）
        \think\facade\Event::trigger(
            new \wise\auth\event\RoleChanged('update', (int) $role->id, $role->toArray())
        );

        return $role;
    }

    /**
     * 删除角色（软删除 + 清理权限/用户关联 + 缓存清理）
     *
     * @param Role $role
     * @return bool
     */
    public function deleteRole(Role $role): bool
    {
        Db::startTrans();
        try {
            $role->delete();
            $role->syncPermissions([]);
            $this->detachRoleUsers((int) $role->id);
            Db::commit();
        } catch (\Throwable $e) {
            Db::rollback();
            throw $e;
        }

        $this->clearRoleCache((int) $role->id);

        // 触发角色变更事件（缓存联动 + 审计日志）
        \think\facade\Event::trigger(
            new \wise\auth\event\RoleChanged('delete', (int) $role->id, $role->toArray())
        );

        return true;
    }

    /**
     * 批量恢复软删除角色
     *
     * @param array $ids
     * @return int 恢复的记录数
     */
    public function restoreRoles(array $ids): int
    {
        $ids = array_values(array_filter(array_map('intval', $ids)));
        if (empty($ids)) {
            return 0;
        }

        $count = 0;
        foreach (Role::withTrashed()->whereIn('id', $ids)->select() as $role) {
            $role->restore();
            $count++;
        }

        if ($count > 0) {
            $this->clearAllCache();
        }

        return $count;
    }

    /**
     * 切换角色状态
     *
     * @param Role $role
     * @param int  $status
     * @return bool
     */
    public function toggleRoleStatus(Role $role, int $status): bool
    {
        $role->status = $status;
        $role->save();
        $this->clearRoleCache((int) $role->id);
        return true;
    }

    /**
     * 构建树形结构（一次遍历 O(n) 实现）
     *
     * @param array $items
     * @param int   $parentId
     * @return array
     */
    public function buildTree(array $items, int $parentId = 0): array
    {
        $tree = [];
        $refs = [];

        // 第一遍：建立 ID→引用 映射
        foreach ($items as &$item) {
            $item['children'] = [];
            $refs[$item['id']] = &$item;
        }
        unset($item);

        // 第二遍：将每个节点挂到其父节点下
        foreach ($refs as &$item) {
            $pid = $item['parent_id'] ?? 0;
            if ($pid == $parentId) {
                $tree[] = &$item;
            } elseif (isset($refs[$pid])) {
                $refs[$pid]['children'][] = &$item;
            }
        }

        // 清理空的 children 数组
        return $this->cleanEmptyChildren($tree);
    }

    /**
     * 递归清理树中空的 children 键
     *
     * @param array $nodes
     * @return array
     */
    private function cleanEmptyChildren(array $nodes): array
    {
        foreach ($nodes as &$node) {
            if (isset($node['children'])) {
                if (empty($node['children'])) {
                    unset($node['children']);
                } else {
                    $node['children'] = $this->cleanEmptyChildren($node['children']);
                }
            }
        }
        return $nodes;
    }
}
