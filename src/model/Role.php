<?php
/**
 * 角色模型
 *
 * 支持 RBAC1 角色继承（父子角色树形结构）。
 */
namespace wise\auth\model;

use think\Model;
use think\model\concern\SoftDelete;

class Role extends Model
{
    use SoftDelete;

    /**
     * 默认时间戳字段
     *
     * @var bool
     */
    protected $autoWriteTimestamp = true;

    /**
     * 创建时间字段
     *
     * @var string
     */
    protected $createTime = 'create_time';

    /**
     * 更新时间字段
     *
     * @var string
     */
    protected $updateTime = 'update_time';

    /**
     * 软删除字段
     *
     * @var string
     */
    protected $deleteTime = 'delete_time';

    /**
     * 追加到序列化的属性
     *
     * @var array
     */
    protected $append = ['ident'];

    /**
     * 类型转换
     *
     * @var array
     */
    protected $type = [
        'is_inherit'  => 'integer',
        'status'      => 'integer',
        'level'       => 'integer',
        'sort'        => 'integer',
        'max_members' => 'integer',
        'mutex'       => 'json',
    ];

    /**
     * 只读字段
     *
     * @var array
     */
    protected $readonly = ['create_time'];

    /**
     * 表名（不含前缀，框架自动添加）
     *
     * @var string
     */
    protected $name = 'auth_roles';

    /**
     * 模型初始化
     */
    protected static function init(): void
    {
    }

    /**
     * 写入前事件：RBAC2 约束检查
     *
     * ThinkPHP 6 模型事件机制：trigger('BeforeWrite') 自动查找并调用当前类的
     * onBeforeWrite 静态方法。返回 false 可阻止写入。
     *
     * @param Role $role 当前模型实例
     * @return bool
     */
    public static function onBeforeWrite(Role $role): bool
    {
        if (config('wise-auth.constraints', []) !== []) {
            $engine = app(\wise\auth\service\ConstraintEngine::class);
            $roleData = [
                'parent_id'  => $role->parent_id,
                'level'      => $role->level,
                'slug'       => $role->slug,
            ];
            $engine->checkBuiltinConstraints('checkBeforeSaveRole', $roleData);
        }

        return true;
    }

    /**
     * ident 别名访问器（映射到 slug 字段，向后兼容旧代码）
     *
     * @param mixed $value
     * @param array $data
     * @return string
     */
    public function getIdentAttr($value, $data): string
    {
        return $data['slug'] ?? '';
    }

    /**
     * 属性写入拦截：ident 是 slug 的别名（虚拟字段，表中不存在 ident 列）
     *
     * 历史实现用 `setIdentAttr($value, &$data)`，但 think-orm 调用修改器时第二参是
     * `array_merge(...)` 的临时数组，按引用传递会抛
     * `Only variables should be passed by reference`，导致角色新增/编辑保存失败
     * （异常被控制器 catch 后只返回一句英文提示）。
     *
     * 改为在 setAttr 入口直接改名：ident → slug，既避免虚拟字段进 SQL，
     * 也保留 `$role->ident` 读取别名（见 getIdentAttr + $append）。
     *
     * @param string $name
     * @param mixed  $value
     * @param array  $data
     * @return void
     */
    public function setAttr(string $name, $value, array $data = []): void
    {
        if ($name === 'ident') {
            $name = 'slug';
        }

        parent::setAttr($name, $value, $data);
    }

    // =============================
    // 关联
    // =============================

    /**
     * 关联权限（多对多）
     *
     * @return \think\model\relation\BelongsToMany
     */
    public function permissions()
    {
        $pivotTable = 'auth_role_permission';
        return $this->belongsToMany(
            Permission::class,
            $pivotTable,
            'permission_id',
            'role_id'
        );
    }

    /**
     * 关联用户（多对多，多态）
     *
     * @return \think\model\relation\MorphToMany
     */
    public function users()
    {
        $pivotTable = 'auth_user_role';
        // 反向多态必须用 morphByMany：morphToMany 会把 pivot.user_type 写成
        // 当前模型（Role）的类名，查询恒为空、attach 还会污染 user_type。
        return $this->morphByMany(
            config('wise-auth.default_user_model'),
            $pivotTable,
            'user',
            'role_id'
        );
    }

    /**
     * 父角色
     *
     * @return \think\model\relation\BelongsTo
     */
    public function parent()
    {
        return $this->belongsTo(static::class, 'parent_id');
    }

    /**
     * 子角色
     *
     * @return \think\model\relation\HasMany
     */
    public function children()
    {
        return $this->hasMany(static::class, 'parent_id');
    }

    // =============================
    // 方法
    // =============================

    /**
     * 检查角色是否拥有指定权限（含继承，防循环引用）
     *
     * @param string $permission 权限标识
     * @param array  $visited    已访问角色ID列表（内部防循环参数）
     * @return bool
     */
    public function hasPermission(string $permission, array &$visited = []): bool
    {
        // 循环引用防护
        if (in_array($this->id, $visited, true)) {
            return false;
        }
        $visited[] = $this->id;

        // 直接权限
        $direct = $this->permissions()->where('ident', $permission)->find();
        if ($direct) {
            return true;
        }

        // 继承权限（从父角色）
        if ($this->is_inherit && $this->parent_id && $this->parent_id !== $this->id) {
            $parent = $this->parent()->find();
            if ($parent) {
                return $parent->hasPermission($permission, $visited);
            }
        }

        return false;
    }

    /**
     * 获取角色所有权限（含继承，防循环引用）
     *
     * @param array $visited 已访问角色ID列表（内部防循环参数）
     * @return array
     */
    public function getAllPermissions(array &$visited = []): array
    {
        // 循环引用防护
        if (in_array($this->id, $visited, true)) {
            return [];
        }
        $visited[] = $this->id;

        $permissionIds = [];

        // 自己的权限
        $own = $this->permissions()->column('id');
        $permissionIds = array_merge($permissionIds, $own);

        // 继承父角色权限
        if ($this->is_inherit && $this->parent_id && $this->parent_id !== $this->id) {
            $parent = $this->parent()->find();
            if ($parent) {
                $parentPerms = $parent->getAllPermissions($visited);
                $permissionIds = array_merge($permissionIds, $parentPerms);
            }
        }

        return array_unique($permissionIds);
    }

    /**
     * 赋予权限（含 RBAC2 约束检查）
     *
     * @param int|string|array $permissionIds 权限ID或权限ID数组
     * @return bool
     */
    public function grantPermission($permissionIds): bool
    {
        $ids = is_array($permissionIds) ? $permissionIds : [$permissionIds];

        // 约束检查（checkBeforeGrantPermission）
        $engine = app(\wise\auth\service\ConstraintEngine::class);
        $engine->checkBuiltinConstraints('checkBeforeGrantPermission', $this->id, $ids);

        $this->permissions()->attach($ids);
        return true;
    }

    /**
     * 撤销权限
     *
     * @param int|string|array $permissionIds 权限ID或权限ID数组
     * @return bool
     */
    public function revokePermission($permissionIds): bool
    {
        $ids = is_array($permissionIds) ? $permissionIds : [$permissionIds];
        $this->permissions()->detach($ids);
        return true;
    }

    /**
     * 同步权限
     *
     * @param array $permissionIds
     * @return bool
     */
    public function syncPermissions(array $permissionIds): bool
    {
        $ids = $this->withAncestorPermissionIds($permissionIds);

        $this->permissions()->detach();
        if (!empty($ids)) {
            $this->permissions()->attach($ids);
        }
        return true;
    }

    /**
     * 补全权限的祖先节点
     *
     * 权限树中「页面」节点是「按钮/动作」节点的父节点（如
     * /admin/admin/index 是 /admin/admin/getlist 的父节点）。只勾选子节点而不勾父节点时：
     *   - 侧边栏仍会显示该页面（MenuPermissionBridge 会自动补父级菜单）；
     *   - 但直接访问页面路由时 RbacMiddleware 按路由精确匹配 → 匹配到页面节点 → 角色未持有 → 403。
     * 因此保存角色权限时向上补全祖先节点，保证「能看到菜单 = 能打开页面」。
     *
     * 只补父节点本身，不会带出兄弟节点，权限范围仍然最小。
     *
     * @param array $permissionIds
     * @return array
     */
    protected function withAncestorPermissionIds(array $permissionIds): array
    {
        $collected = array_values(array_unique(array_filter(array_map('intval', $permissionIds))));
        if ($collected === []) {
            return [];
        }

        $current = $collected;
        // 权限树层级有限（现有最深 4 级），加个上限防御脏数据成环
        for ($depth = 0; $depth < 10 && $current !== []; $depth++) {
            $parentIds = Permission::whereIn('id', $current)
                ->where('parent_id', '>', 0)
                ->column('parent_id');

            $parentIds = array_values(array_unique(array_filter(array_map('intval', (array) $parentIds))));
            $newIds    = array_values(array_diff($parentIds, $collected));

            if ($newIds === []) {
                break;
            }

            $collected = array_merge($collected, $newIds);
            $current   = $newIds;
        }

        sort($collected);

        return $collected;
    }

    /**
     * 检测循环继承
     *
     * @param int $parentId 父角色ID
     * @return bool 返回 true 表示存在循环
     */
    public static function hasCycle(int $parentId, ?int $excludeId = null): bool
    {
        $visited = [];
        return static::_detectCycle($parentId, $visited, $excludeId);
    }

    /**
     * 递归检测循环
     *
     * @param int   $roleId
     * @param array $visited
     * @param int|null $excludeId
     * @return bool
     */
    private static function _detectCycle(int $roleId, array &$visited, ?int $excludeId = null): bool
    {
        if (in_array($roleId, $visited)) {
            return true;
        }
        $visited[] = $roleId;

        $role = static::find($roleId);
        if (!$role || !$role->parent_id) {
            return false;
        }

        if ($excludeId && $role->parent_id === $excludeId) {
            return false;
        }

        return static::_detectCycle($role->parent_id, $visited, $excludeId);
    }

    /**
     * 获取所有祖先角色ID
     *
     * 优先通过 path 字段解析（避免 N+1 查询），
     * path 为空时 fallback 到逐级查询。
     *
     * @param int $roleId
     * @return array
     */
    public static function getAncestorIds(int $roleId): array
    {
        $role = static::find($roleId);
        if (!$role) {
            return [];
        }

        // 优先使用 path 字段解析（格式如 "0-1-3-5"）
        if (!empty($role->path)) {
            $pathIds = explode('-', trim($role->path, '-'));
            // 单次遍历：过滤空值并排除自身
            $pathIds = array_values(array_filter($pathIds, function ($id) use ($roleId) {
                return $id !== '' && (int)$id !== $roleId;
            }));
            return array_map('intval', $pathIds);
        }

        // fallback: 逐级查询父角色
        // visited 防环：历史数据已可能存在循环引用（cycle_check_enabled 未接入保存流程），
        // 无守卫时此处会死循环。
        $ancestors = [];
        $visited = [(int) $roleId];
        $currentRole = $role;
        while ($currentRole && $currentRole->parent_id) {
            $parentId = (int) $currentRole->parent_id;
            if (in_array($parentId, $visited, true)) {
                break;
            }
            $visited[] = $parentId;
            $ancestors[] = $parentId;
            $currentRole = static::find($parentId);
        }
        return $ancestors;
    }
}
