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
     * 类型转换
     *
     * @var array
     */
    protected $type = [
        'is_inherit' => 'integer',
        'status'     => 'integer',
        'level'      => 'integer',
        'sort'       => 'integer',
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

    public function __construct($data = [])
    {
        parent::__construct($data);
        $this->setName(config('wise-auth.table_names.roles', $this->name));
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
        $pivotTable = config('wise-auth.table_names.role_permission', 'auth_role_permission');
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
        $pivotTable = config('wise-auth.table_names.user_role', 'auth_user_role');
        return $this->morphToMany(
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
     * 检查角色是否拥有指定权限
     *
     * @param string $permission 权限标识
     * @return bool
     */
    public function hasPermission(string $permission): bool
    {
        // 直接权限
        $direct = $this->permissions()->where('ident', $permission)->find();
        if ($direct) {
            return true;
        }

        // 继承权限（从父角色）
        if ($this->is_inherit && $this->parent_id) {
            $parent = $this->parent()->find();
            if ($parent) {
                return $parent->hasPermission($permission);
            }
        }

        return false;
    }

    /**
     * 获取角色所有权限（含继承）
     *
     * @return array
     */
    public function getAllPermissions(): array
    {
        $permissionIds = [];

        // 自己的权限
        $own = $this->permissions()->column('id');
        $permissionIds = array_merge($permissionIds, $own);

        // 继承父角色权限
        if ($this->is_inherit && $this->parent_id) {
            $parent = $this->parent()->find();
            if ($parent) {
                $parentPerms = $parent->getAllPermissions();
                $permissionIds = array_merge($permissionIds, $parentPerms);
            }
        }

        return array_unique($permissionIds);
    }

    /**
     * 赋予权限
     *
     * @param int|string|array $permissionIds 权限ID或权限ID数组
     * @return bool
     */
    public function grantPermission($permissionIds): bool
    {
        $ids = is_array($permissionIds) ? $permissionIds : [$permissionIds];
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
        $this->permissions()->detach();
        if (!empty($permissionIds)) {
            $this->permissions()->attach($permissionIds);
        }
        return true;
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
            $pathIds = array_filter(explode('-', trim($role->path, '-')));
            // 排除角色自身
            $pathIds = array_filter($pathIds, function ($id) use ($roleId) {
                return (int)$id !== $roleId;
            });
            return array_map('intval', array_values($pathIds));
        }

        // fallback: 逐级查询父角色
        $ancestors = [];
        $currentRole = $role;
        while ($currentRole && $currentRole->parent_id) {
            $ancestors[] = $currentRole->parent_id;
            $currentRole = static::find($currentRole->parent_id);
        }
        return $ancestors;
    }
}
