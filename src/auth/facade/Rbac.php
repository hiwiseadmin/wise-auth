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
 * @method static string getDefaultUserType() 获取默认 user_type（配置 user_models 第一个 key）
 * @method static bool isSuperAdmin(int|string $userId, ?string $userType = null) 是否超管
 * @method static array getUserPermissions(int|string $userId, string $userType) 获取用户权限
 * @method static array resolveRolesPermissionIds(array $roleIds) 解析角色权限ID（含继承，已过滤禁用权限）
 * @method static array resolveRolesPermissions(array $roleIds) 解析角色权限标识
 * @method static array matchRouteToPermissions(string $route, string $method) 路由匹配权限
 * @method static void clearUserCache(int|string $userId, ?string $userType = null) 清除用户缓存
 * @method static void clearAllCache() 清除全部缓存
 * @method static void clearRoleCache(int $roleId) 清除角色缓存
 * @method static bool checkConstraint(string $method, ...$args) 约束检查
 * @method static array getRoleTree() 获取角色树
 * @method static array getAllRoles(array $fields = []) 获取所有启用角色（轻量列表）
 * @method static int getRoleUserCount(int $roleId, ?string $userType = null) 获取角色成员数
 * @method static array getUserIdsByRole(int $roleId, ?string $userType = null) 获取角色下的用户ID列表
 * @method static int detachUsersFromRoles(array $userIds, ?string $userType = null) 移除用户的所有角色关联
 * @method static int detachRoleUsers(int $roleId) 移除角色的所有用户关联
 * @method static \wise\auth\model\Role|null getRoleById(int $id) 获取角色模型
 * @method static \wise\auth\model\Role getRoleOrEmpty(int $id) 获取角色模型（空实例）
 * @method static \wise\auth\model\Role|null getRoleBySlug(string $slug) 按 slug 查找角色
 * @method static array getRoleModels(array $fields = []) 获取启用角色模型（以ID为键）
 * @method static array getRolePage(int $page, int $limit, string $keyword = '') 分页获取角色列表
 * @method static int countChildren(int $parentId) 子角色数量
 * @method static array getChildren(int $parentId, array $fields = []) 子角色列表
 * @method static bool hasRoleCycle(int $parentId, ?int $excludeId = null) 检测循环继承
 * @method static array getRoleAncestorIds(int $roleId) 获取祖先角色ID
 * @method static \wise\auth\model\Role createRole(array $data, array $permissionIds = []) 创建角色
 * @method static \wise\auth\model\Role updateRole(\wise\auth\model\Role $role, array $data, array $permissionIds) 更新角色
 * @method static bool deleteRole(\wise\auth\model\Role $role) 删除角色
 * @method static int restoreRoles(array $ids) 批量恢复角色
 * @method static bool toggleRoleStatus(\wise\auth\model\Role $role, int $status) 切换角色状态
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
