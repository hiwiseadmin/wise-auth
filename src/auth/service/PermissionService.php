<?php
/**
 * 权限注册与管理服务
 *
 * 作为 wise-auth 包对外暴露的权限 CRUD 统一入口。
 * 框架层（如 Menu 模型）通过此服务注册/更新权限，无需直接操作 Permission 模型，
 * 实现框架与包的解耦。
 *
 * 使用示例：
 * ```php
 * use wise\auth\facade\Perm;
 *
 * // 注册/更新一条权限
 * $permId = Perm::registerPermission([
 *     'ident'       => 'admin.user.list',
 *     'name'        => '用户列表',
 *     'type'        => 'menu',
 *     'parent_id'   => 0,
 *     'route'       => '/admin/user/list',
 *     'method'      => 'GET',
 *     'plugin'      => 'system',
 *     'description' => '查看用户列表',
 * ]);
 * ```
 */
namespace wise\auth\service;

use wise\auth\model\Permission;

class PermissionService
{
    /**
     * 注册/更新单条权限（按 ident + type 幂等）
     *
     * 策略：
     *   - 同 ident + type 已存在（含软删除）→ 恢复并更新字段
     *   - 不存在 → 新建
     *   - 保存后自动计算 tree path 和 level
     *   - 清除相关缓存
     *
     * @param array $data {
     *     @var string $ident       权限标识（必填）
     *     @var string $name        权限名称
     *     @var string $type        权限类型: menu|route|api|custom
     *     @var int    $parent_id   父权限ID（默认 0）
     *     @var string $route       路由路径
     *     @var string $method      HTTP方法（默认 GET）
     *     @var string $plugin      插件标识
     *     @var string $description 描述
     *     @var int    $status      状态（默认 1 启用）
     *     @var int    $sort        排序
     * }
     * @return int 权限ID
     */
    public function registerPermission(array $data): int
    {
        $ident  = $data['ident'] ?? '';
        $type   = $data['type'] ?? 'custom';

        if (empty($ident)) {
            throw new \InvalidArgumentException('Permission ident is required');
        }

        $permission = Permission::withTrashed()
            ->where('ident', $ident)
            ->where('type', $type)
            ->find();

        $isNew = !$permission;

        $fields = $this->buildFields($data);

        if ($permission && !empty($data['preserve_method'])) {
            unset($fields['method']);
        }

        if ($permission) {
            if ($permission->delete_time) {
                $permission->restore();
            }
            foreach ($fields as $key => $value) {
                $permission->setAttr($key, $value);
            }
            $permission->save();
        } else {
            $permission = new Permission();
            foreach ($fields as $key => $value) {
                $permission->setAttr($key, $value);
            }
            $permission->save();
        }

        $permission->updatePath();

        $this->clearPermissionCache();

        \think\facade\Event::trigger(
            new \wise\auth\event\PermissionChanged(
                $isNew ? 'create' : 'update',
                (int) $permission->id,
                $permission->toArray()
            )
        );

        return (int) $permission->id;
    }

    /**
     * 按 ident 删除权限（软删除）
     *
     * @param string $ident 权限标识
     * @param string $type  权限类型（可选，为空则匹配所有类型）
     * @return bool
     */
    public function deletePermission(string $ident, string $type = ''): bool
    {
        $query = Permission::where('ident', $ident);
        if ($type !== '') {
            $query->where('type', $type);
        }

        $permission = $query->find();
        if (!$permission) {
            return false;
        }

        $permission->delete();
        $this->clearPermissionCache();

        \think\facade\Event::trigger(
            new \wise\auth\event\PermissionChanged('delete', (int) $permission->id, $permission->toArray())
        );

        return true;
    }

    /**
     * 按 ident + type 查找权限
     *
     * @param string $ident
     * @param string $type
     * @return Permission|null
     */
    public function findByIdent(string $ident, string $type = ''): ?Permission
    {
        $query = Permission::where('ident', $ident);
        if ($type !== '') {
            $query->where('type', $type);
        }
        return $query->find() ?: null;
    }

    /**
     * 获取所有启用权限（数组）
     *
     * @param array  $fields  需要查询的字段
     * @param string $keyword 关键字过滤（匹配 name/ident/route）
     * @return array
     */
    public function getActiveList(array $fields = [], string $keyword = ''): array
    {
        if (empty($fields)) {
            $fields = ['id', 'parent_id', 'ident', 'name', 'type', 'route', 'method', 'plugin', 'level', 'sort', 'status'];
        }

        $query = Permission::where('status', 1)
            ->field($fields)
            ->order('sort', 'asc')
            ->order('id', 'asc');

        if ($keyword !== '') {
            $query->where('name|ident|route', 'like', "%{$keyword}%");
        }

        return $query->select()->toArray();
    }

    /**
     * 获取所有启用权限 ID
     *
     * @return array
     */
    public function getActiveIds(): array
    {
        return Permission::where('status', 1)->column('id');
    }

    /**
     * 从输入数据构建标准化的权限字段
     *
     * @param array $data
     * @return array
     */
    protected function buildFields(array $data): array
    {
        return [
            'ident'       => $data['ident'],
            'name'        => $data['name'] ?? '',
            'type'        => $data['type'] ?? 'custom',
            'parent_id'   => (int)($data['parent_id'] ?? 0),
            'route'       => $data['route'] ?? '',
            'method'      => $data['method'] ?? 'GET',
            'plugin'      => $data['plugin'] ?? '',
            'description' => $data['description'] ?? '',
            'status'      => (int)($data['status'] ?? 1),
            'sort'        => (int)($data['sort'] ?? 0),
        ];
    }

    /**
     * 清除权限相关缓存
     */
    protected function clearPermissionCache(): void
    {
        try {
            app(PermissionRegistrar::class)->clearPermissionsCache();
        } catch (\Throwable) {
        }
    }
}
