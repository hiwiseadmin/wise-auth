<?php
/**
 * 权限管理门面
 *
 * 提供静态调用方式访问 PermissionService。
 *
 * 使用示例：
 * ```php
 * use wise\auth\facade\Perm;
 *
 * $permId = Perm::registerPermission([...]);
 * Perm::deletePermission('admin.user.list', 'menu');
 * ```
 */
namespace wise\auth\facade;

use think\Facade;

/**
 * @method static int    registerPermission(array $data) 注册/更新权限，返回权限ID
 * @method static bool   deletePermission(string $ident, string $type = '') 软删除权限
 * @method static \wise\auth\model\Permission|null findByIdent(string $ident, string $type = '') 按标识查找权限
 */
class Perm extends Facade
{
    protected static function getFacadeClass(): string
    {
        return \wise\auth\service\PermissionService::class;
    }
}
