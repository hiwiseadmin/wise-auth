<?php
/**
 * 用户角色关联 Trait
 *
 * 使用此 Trait 的模型将获得完整的 RBAC 权限判断能力。
 * 支持多态关联，适用于不同用户类型（admin, member 等）。
 *
 * 使用方式：
 * ```php
 * class Admin extends Model
 * {
 *     use \wise\auth\traits\HasRoles;
 * }
 * ```
 */
namespace wise\auth\traits;

use think\facade\Event;
use wise\auth\model\Role;
use wise\auth\service\RbacManager;

trait HasRoles
{
    /**
     * 获取当前模型的 user_type 标识
     * 子类可覆盖此方法以返回自定义类型。
     *
     * 权威口径：配置 wise-auth.user_models 的 key（如 'admin'、'member'）。
     * 这与 auth_user_role.user_type 字段的实际存储值一致（由 morphMap 保证：
     * MorphToMany 写入时会把模型 FQCN 经 morphMap 转成配置 key）。
     *
     * @return string
     */
    public function getAuthUserType(): string
    {
        $class = get_class($this);

        // 优先从配置 user_models 反查：FQCN => key
        $userModels = (array) config('wise-auth.user_models', []);
        foreach ($userModels as $type => $modelClass) {
            if (is_string($modelClass) && ltrim($modelClass, '\\') === ltrim($class, '\\')) {
                return (string) $type;
            }
        }

        // 回退：类名小写短名（与旧行为保持一致）
        $parts = explode('\\', $class);
        return strtolower((string) array_pop($parts));
    }

    /**
     * 需要在模型中自定义用户唯一标识
     */
    // public function getTotpLabel(): string
    // {
        // return $this->username;
    // }
    
    /**
     * 获取用户唯一标识
     *
     * @return int|string
     */
    public function getAuthIdentifier(): int|string
    {
        return $this->getKey();
    }

    // =============================
    // 关联
    // =============================

    /**
     * 角色关联（多对多，多态）
     *
     * @return \think\model\relation\MorphToMany
     */
    public function roles()
    {
        $pivotTable = 'auth_user_role';
        return $this->morphToMany(
            Role::class,
            $pivotTable,
            'user',
            'role_id'
        );
    }

    // =============================
    // 角色操作
    // =============================

    /**
     * 获取所有角色
     *
     * @return \think\Collection
     */
    public function getRoles()
    {
        return $this->roles()->select();
    }

    /**
     * 检查是否拥有指定角色
     *
     * @param string|array $roles      角色 slug 或 slug 数组
     * @param bool         $requireAll 是否必须全部拥有
     * @return bool
     */
    public function hasRole(string|array $roles, bool $requireAll = false): bool
    {
        if (is_string($roles)) {
            $roles = [$roles];
        }

        $userRoles = $this->roles()->column('slug');

        if (empty($userRoles)) {
            return false;
        }

        if ($requireAll) {
            return empty(array_diff($roles, $userRoles));
        }

        return !empty(array_intersect($roles, $userRoles));
    }

    /**
     * 将角色 slug 或 ID 统一转换为数字 ID 数组
     *
     * @param array $roleIds 角色 slug 或 ID 的混合数组
     * @return array 角色数字 ID 数组
     */
    private function resolveRoleIds(array $roleIds): array
    {
        $numericIds = [];
        $slugs = [];

        // 分离数字 ID 和 slug
        foreach ($roleIds as $id) {
            if (is_numeric($id)) {
                $numericIds[] = (int)$id;
            } else {
                $slugs[] = $id;
            }
        }

        // 批量查询 slug → ID 映射（避免 N+1）
        $slugIds = [];
        if (!empty($slugs)) {
            $roles = Role::whereIn('slug', $slugs)->column('id', 'slug');
            $slugIds = array_values($roles);
        }

        return array_merge($numericIds, $slugIds);
    }

    /**
     * 分配角色
     *
     * @param int|string|array $roleIds   角色ID或slug，支持数组
     * @param int|null         $expiredAt 过期时间戳（null 表示永不过期）
     * @return bool
     */
    public function assignRole($roleIds, ?int $expiredAt = null): bool
    {
        $roleIds = is_array($roleIds) ? $roleIds : [$roleIds];
        $ids = $this->resolveRoleIds($roleIds);
        $userId = $this->getAuthIdentifier();
        $userType = $this->getAuthUserType();

        if (empty($ids)) {
            return false;
        }

        // 约束检查
        $manager = app(RbacManager::class);
        foreach ($ids as $roleId) {
            if (!$manager->checkConstraint('beforeAssignRole', $userId, $userType, $roleId)) {
                return false;
            }
        }

        // 触发分配前事件
        Event::trigger('RbacRoleAssigning', [
            'user_id'   => $userId,
            'user_type' => $userType,
            'role_ids'  => $ids,
            'expired_at' => $expiredAt,
        ]);

        // 构建 pivot 数据（含过期时间）
        // 注意：当前 MorphToMany::attach 不支持按 id 分组的 pivot 结构，
        // 第二参数必须是扁平的字段属性数组，否则整数键会被当作字段名传给 setAttr 而报错。
        // 另：auth_user_role.expired_at 是 DATETIME 列，必须写 datetime 字符串，
        // 直接写 int 时间戳会触发 Incorrect datetime value（严格模式）或被转成非法日期。
        $pivotData = [];
        if ($expiredAt !== null) {
            $pivotData['expired_at'] = date('Y-m-d H:i:s', $expiredAt);
        }

        $this->roles()->attach($ids, $pivotData);

        // 触发分配后事件
        Event::trigger('RbacRoleAssigned', [
            'user_id'   => $userId,
            'user_type' => $userType,
            'role_ids'  => $ids,
            'expired_at' => $expiredAt,
        ]);

        // 清除缓存
        $manager->clearUserCache($userId, $userType);

        return true;
    }

    /**
     * 移除角色
     *
     * @param int|string|array $roleIds
     * @return bool
     */
    public function removeRole($roleIds): bool
    {
        $roleIds = is_array($roleIds) ? $roleIds : [$roleIds];
        $ids = $this->resolveRoleIds($roleIds);
        $userId = $this->getAuthIdentifier();
        $userType = $this->getAuthUserType();

        // 触发移除前事件
        Event::trigger('RbacRoleRemoving', [
            'user_id'   => $userId,
            'user_type' => $userType,
            'role_ids'  => $ids,
        ]);

        $this->roles()->detach($ids);

        // 触发移除后事件
        Event::trigger('RbacRoleRemoved', [
            'user_id'   => $userId,
            'user_type' => $userType,
            'role_ids'  => $ids,
        ]);

        $manager = app(RbacManager::class);
        $manager->clearUserCache($userId, $userType);

        return true;
    }

    /**
     * 同步角色（先移除后分配）
     *
     * @param array    $roleIds   角色ID或slug数组
     * @param int|null $expiredAt 统一过期时间戳（null 表示永不过期），
     *                           注意：syncRoles 对所有角色使用相同的过期时间
     * @return bool
     */
    public function syncRoles(array $roleIds, ?int $expiredAt = null): bool
    {
        $this->roles()->detach();

        if (!empty($roleIds)) {
            $ids = $this->resolveRoleIds($roleIds);
            // 构建 pivot 数据（含过期时间）
            // 注意：当前 MorphToMany::attach 不支持按 id 分组的 pivot 结构，
            // 第二参数必须是扁平的字段属性数组，否则整数键会被当作字段名传给 setAttr 而报错。
            // 另：auth_user_role.expired_at 是 DATETIME 列，须写 datetime 字符串。
            $pivotData = [];
            if ($expiredAt !== null) {
                $pivotData['expired_at'] = date('Y-m-d H:i:s', $expiredAt);
            }
            $this->roles()->attach($ids, $pivotData);
        }
        $userId = $this->getAuthIdentifier();
        $userType = $this->getAuthUserType();
        
        $manager = app(RbacManager::class);
        $manager->clearUserCache($userId, $userType);
        
        Event::trigger('RbacRoleSynced', [
            'user_id'   => $userId,
            'user_type' => $userType,
            'role_ids'  => $roleIds,
            'expired_at' => $expiredAt,
        ]);

        return true;
    }

    // =============================
    // 权限检查
    // =============================

    /**
     * 检查是否拥有指定权限（单个）
     *
     * @param string $permission 权限标识
     * @return bool
     */
    public function can(string $permission): bool
    {
        return $this->hasPermission($permission);
    }

    /**
     * 检查是否拥有指定权限
     *
     * @param string|array $permissions 权限标识或标识数组
     * @param bool         $requireAll 是否必须全部拥有
     * @return bool
     */
    public function hasPermission(string|array $permissions, bool $requireAll = false): bool
    {
        // 超级管理员直接通过
        if ($this->isSuperAdmin()) {
            return true;
        }

        if (is_string($permissions)) {
            $permissions = [$permissions];
        }

        // 空权限数组：无权限要求，视为通过
        if (empty($permissions)) {
            return true;
        }

        $userPermissions = $this->getAllPermissions();

        if ($requireAll) {
            return empty(array_diff($permissions, $userPermissions));
        }

        return !empty(array_intersect($permissions, $userPermissions));
    }

    /**
     * 获取用户所有权限标识
     *
     * @return array
     */
    public function getAllPermissions(): array
    {
        // 超级管理员返回特殊标记
        if ($this->isSuperAdmin()) {
            return ['*'];
        }

        $manager = app(RbacManager::class);
        return $manager->getUserPermissions($this->getAuthIdentifier(), $this->getAuthUserType());
    }

    /**
     * 是否为超级管理员
     *
     * 委托给 RbacManager，统一从 PHP 配置文件直接读取 super_admin_ids，
     * 绕过可变的 config() 系统，防止运行时篡改。
     *
     * @return bool
     */
    public function isSuperAdmin(): bool
    {
        /** @var RbacManager $manager */
        $manager = app(RbacManager::class);
        return $manager->isSuperAdmin($this->getAuthIdentifier(), $this->getAuthUserType());
    }

    // =============================
    // 权限缓存清除
    // =============================

    /**
     * 强制刷新用户权限缓存（实现 UserContract）
     *
     * @return array
     */
    public function refreshPermissions(): array
    {
        $manager = app(RbacManager::class);
        $userId   = $this->getAuthIdentifier();
        $userType = $this->getAuthUserType();
        $manager->clearUserCache($userId, $userType);
        return $manager->getUserPermissions($userId, $userType);
    }

    /**
     * 清除用户权限缓存（实现 UserContract）
     */
    public function forgetPermissions(): void
    {
        $manager = app(RbacManager::class);
        $manager->clearUserCache($this->getAuthIdentifier(), $this->getAuthUserType());
    }

    /**
     * 模型事件：保存/删除后自动清除权限缓存
     *
     * 注意：角色分配/移除/同步操作已在对应方法中显式清除缓存，
     * 此处 saved 事件仅处理新建模型的场景（如分配默认角色后需要刷新）。
     * deleted 事件需要清除，防止已删除用户的缓存残留。
     */
    public static function bootHasRoles(): void
    {
        // static::saved(function ($model) {
        //     // 仅新建时清除缓存（更新操作由 assignRole/removeRole/syncRoles 显式处理）
        //     if ($model->wasRecentlyCreated && method_exists($model, 'getAuthIdentifier') && method_exists($model, 'getAuthUserType')) {
        //         $manager = app(RbacManager::class);
        //         $manager->clearUserCache(
        //             $model->getAuthIdentifier(),
        //             $model->getAuthUserType()
        //         );
        //     }
        // });

        // static::deleted(function ($model) {
        //     if (method_exists($model, 'getAuthIdentifier') && method_exists($model, 'getAuthUserType')) {
        //         $manager = app(RbacManager::class);
        //         $manager->clearUserCache(
        //             $model->getAuthIdentifier(),
        //             $model->getAuthUserType()
        //         );
        //     }
        // });
        // 缓存清除已由 assignRole/removeRole/syncRoles 显式处理，
        // 若需模型事件级别的自动清除，可在此处注册 saved/deleted 事件监听。
    }
}
