<?php
/**
 * RBAC 权限验证与角色管理核心服务
 *
 * 负责权限检查、缓存管理、用户-角色-权限的关联查询。
 */
namespace wise\auth\service;

use think\facade\Cache;
use wise\auth\model\Role;
use wise\auth\model\Permission;
use wise\auth\model\UserRole;
use wise\auth\exception\ConstraintViolationException;
use wise\auth\trait\CacheKeyHelper;

class RbacManager
{
    use CacheKeyHelper;

    /**
     * 缓存实例
     *
     * @var \think\Cache
     */
    protected $cache;

    /**
     * 是否已初始化缓存驱动
     *
     * @var bool
     */
    protected $cacheInitialized = false;

    /**
     * 初始化缓存驱动
     */
    protected function initCache(): void
    {
        if ($this->cacheInitialized) {
            return;
        }

        if (config('wise-auth.cache_enabled', true)) {
            $store = config('wise-auth.cache_store');
            if ($store) {
                $this->cache = Cache::store($store);
            } else {
                $this->cache = Cache::store();
            }
        }

        $this->cacheInitialized = true;
    }

    // =============================
    // 权限检查
    // =============================

    /**
     * 检查用户是否拥有指定权限
     *
     * @param int|string $userId       用户ID
     * @param string     $userType     用户类型
     * @param string     $permission   权限标识
     * @return bool
     */
    public function check($userId, string $userType, string $permission): bool
    {
        // 超级管理员
        if ($this->isSuperAdmin($userId, $userType)) {
            return true;
        }

        $permissions = $this->getUserPermissions($userId, $userType);
        return in_array($permission, $permissions);
    }

    /**
     * 检查用户是否拥有指定权限中的任意一个（OR模式）
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
        return !empty(array_intersect($permissions, $userPerms));
    }

    /**
     * 检查用户是否拥有全部指定权限（AND模式）
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
        return empty(array_diff($permissions, $userPerms));
    }

    /**
     * 检查用户是否为超级管理员
     *
     * @param int|string $userId
     * @param string     $userType 用户类型，用于多态关联查询
     * @return bool
     */
    public function isSuperAdmin($userId, string $userType = 'admin'): bool
    {
        // 检查 super_admin_ids 配置（不受 user_type 影响，全局生效）
        $superAdminIds = config('wise-auth.super_admin_ids', []);
        if (in_array($userId, $superAdminIds)) {
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
            $userRoleTable = config('wise-auth.table_names.user_role', 'auth_user_role');
            $roleId = Role::where('slug', $superRole)->value('id');
            $result = false;
            if ($roleId) {
                $count = \think\facade\Db::name($userRoleTable)
                    ->where('user_id', $userId)
                    ->where('user_type', $userType)
                    ->where('role_id', $roleId)
                    ->where(function ($query) {
                        $query->whereNull('expired_at')
                              ->whereOr('expired_at', '>', time());
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
     * 实际解析用户权限
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
                $query->whereNull('expired_at')
                      ->whereOr('expired_at', '>', time());
            })
            ->column('role_id');

        if (empty($userRoles)) {
            return [];
        }

        // 递归获取所有角色权限（含继承）
        return $this->resolveRolesPermissions($userRoles);
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
     * 解析角色集合的所有权限标识（含继承）
     *
     * @param array $roleIds
     * @return array
     */
    public function resolveRolesPermissions(array $roleIds): array
    {
        $permissionIds = $this->resolveRolesPermissionIds($roleIds);

        if (empty($permissionIds)) {
            return [];
        }

        return Permission::whereIn('id', $permissionIds)
            ->column('ident');
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
        $rolePermissionTable = config('wise-auth.table_names.role_permission', 'auth_role_permission');
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
     * 清除指定用户的权限缓存
     *
     * @param int|string $userId
     * @param string     $userType
     */
    public function clearUserCache($userId, string $userType = 'admin'): void
    {
        $this->initCache();
        if (!$this->cache) {
            return;
        }

        $cacheKey = $this->getCacheKey("user_perms:{$userType}:{$userId}");
        $this->cache->delete($cacheKey);
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

        // 尝试 Tag 清除
        $tagCleared = false;
        try {
            Cache::tag('wiseauth_permissions')->clear();
            $tagCleared = true;
        } catch (\Throwable $e) {
            // Tag 驱动不支持，走 fallback
        }

        // fallback: 始终尝试遍历键删除，确保缓存被清除
        if (!$tagCleared) {
            $handler = $this->cache->handler();
            if (method_exists($handler, 'keys')) {
                $cachePrefix = $this->getCacheKey('');
                $keys = $handler->keys($cachePrefix . '*');
                if (!empty($keys)) {
                    $handler->del($keys);
                }
            }
        }
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

        // 获取该角色的所有用户并清除缓存
        $userRoleTable = config('wise-auth.table_names.user_role', 'auth_user_role');
        $users = \think\facade\Db::name($userRoleTable)
            ->where('role_id', $roleId)
            ->select()
            ->toArray();

        foreach ($users as $user) {
            $this->clearUserCache($user['user_id'], $user['user_type'] ?? 'admin');
        }
    }

    // =============================
    // RBAC2 约束检查
    // =============================

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
        // 检查自定义约束检查器
        $checker = config('wise-auth.constraint_checker');
        if ($checker) {
            if ($checker instanceof \Closure) {
                $event = $method;
                $context = ['args' => $args];
                return call_user_func($checker, $event, $context);
            }
            if (class_exists($checker)) {
                $instance = new $checker();
                if (method_exists($instance, $method)) {
                    return call_user_func_array([$instance, $method], $args);
                }
            }
        }

        // 内置约束规则
        return $this->checkBuiltinConstraints($method, ...$args);
    }

    /**
     * 内置约束规则检查
     *
     * @param string $method
     * @param mixed  ...$args
     * @return bool
     * @throws ConstraintViolationException
     */
    protected function checkBuiltinConstraints(string $method, ...$args): bool
    {
        $constraints = config('wise-auth.constraints', []);

        if (empty($constraints)) {
            return true;
        }

        switch ($method) {
            case 'beforeAssignRole':
                return $this->checkMutualExclusion($args[0], $args[1], $args[2], $constraints);

            case 'checkBeforeSaveRole':
                // 前置角色检查等
                return true;

            default:
                return true;
        }
    }

    /**
     * 检查互斥角色
     *
     * @param int|string $userId
     * @param string     $userType
     * @param int|string $newRoleId
     * @param array      $constraints
     * @return bool
     * @throws ConstraintViolationException
     */
    protected function checkMutualExclusion($userId, string $userType, $newRoleId, array $constraints): bool
    {
        if (empty($constraints['mutual_exclusion'])) {
            return true;
        }

        $newRole = Role::find($newRoleId);
        if (!$newRole) {
            return true;
        }

        $newRoleSlug = $newRole->slug;

        // 获取用户已有角色
        $existingRoles = UserRole::where('user_id', $userId)
            ->where('user_type', $userType)
            ->column('role_id');

        $existingSlugs = [];
        if (!empty($existingRoles)) {
            $existingSlugs = Role::whereIn('id', $existingRoles)->column('slug');
        }

        // 检查互斥关系
        foreach ($constraints['mutual_exclusion'] as $pair) {
            if (in_array($newRoleSlug, $pair)) {
                $conflict = array_diff($pair, [$newRoleSlug]);
                $intersection = array_intersect($conflict, $existingSlugs);
                if (!empty($intersection)) {
                    throw new ConstraintViolationException(
                        "角色 '{$newRoleSlug}' 与已有角色 '" . implode("', '", $intersection) . "' 互斥，不能同时分配",
                        'mutual_exclusion'
                    );
                }
            }
        }

        return true;
    }

    // =============================
    // 路由匹配权限
    // =============================

    /**
     * 根据路由路径匹配权限标识
     *
     * @param string $route  路由路径
     * @param string $method 请求方法
     * @return array 匹配的权限标识列表
     */
    public function matchRouteToPermissions(string $route, string $method = 'GET'): array
    {
        $cacheKey = $this->getCacheKey("route_match:" . md5($route . $method));

        $this->initCache();
        if ($this->cache) {
            $cached = $this->cache->get($cacheKey);
            if ($cached !== null) {
                return $cached;
            }
        }

        $permissions = Permission::where('status', 1)
            ->where('type', 'route')
            ->select();

        $matched = [];
        foreach ($permissions as $perm) {
            if ($this->routeMatch($perm->route, $route) && $this->methodMatch($perm->method, $method)) {
                $matched[] = $perm->ident;
            }
        }

        if ($this->cache) {
            $this->cache->set($cacheKey, $matched, 3600);
        }

        return $matched;
    }

    /**
     * 路由匹配（简单模式匹配）
     *
     * @param string $pattern 权限定义的路由模式
     * @param string $route   实际请求路由
     * @return bool
     */
    public function routeMatch(string $pattern, string $route): bool
    {
        // 精确匹配
        if ($pattern === $route) {
            return true;
        }

        // 通配符匹配
        $pattern = preg_quote($pattern, '#');
        $pattern = str_replace('\*', '.*', $pattern);
        return (bool)preg_match('#^' . $pattern . '$#', $route);
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
        if ($patternMethod === '*' || $patternMethod === 'ANY') {
            return true;
        }

        $allowedMethods = array_map('trim', explode(',', strtoupper($patternMethod)));
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
