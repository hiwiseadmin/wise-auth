<?php
/**
 * Rbac 门面类
 *
 * 提供静态调用方式访问 RbacManager 服务。
 *
 * 使用示例：
 * ```php
 * use wise\auth\facade\Rbac;
 *
 * Rbac::check($userId, 'admin', 'admin.user.list');
 * Rbac::hasRole($userId, 'admin', 'editor');
 * Rbac::assignRole($userId, 'admin', $roleId);
 * Rbac::clearCache();
 * ```
 */
namespace wise\auth\facade;

use think\Facade;

/**
 * @method static bool check(int|string $userId, string $userType, string $permission) 检查权限
 * @method static bool checkAny(int|string $userId, string $userType, array $permissions) OR模式检查
 * @method static bool checkAll(int|string $userId, string $userType, array $permissions) AND模式检查
 * @method static bool isSuperAdmin(int|string $userId, string $userType = 'admin') 是否超管
 * @method static array getUserPermissions(int|string $userId, string $userType) 获取用户权限
 * @method static array resolveRolesPermissionIds(array $roleIds) 解析角色权限ID（含继承，已过滤禁用权限）
 * @method static array resolveRolesPermissions(array $roleIds) 解析角色权限标识
 * @method static array matchRouteToPermissions(string $route, string $method) 路由匹配权限
 * @method static void clearUserCache(int|string $userId, string $userType) 清除用户缓存
 * @method static void clearAllCache() 清除全部缓存
 * @method static void clearRoleCache(int $roleId) 清除角色缓存
 * @method static bool checkConstraint(string $method, ...$args) 约束检查
 * @method static array getRoleTree() 获取角色树
 */
class Rbac extends Facade
{
    /**
     * 获取 Facade 对应的服务类
     *
     * @return string
     */
    protected static function getFacadeClass(): string
    {
        return \wise\auth\service\RbacManager::class;
    }
}
