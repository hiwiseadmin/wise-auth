<?php
/**
 * 权限模型
 *
 * 权限可细分为"权限规则"，存储路由、请求方法、条件等。
 */
namespace wise\auth\model;

use think\Model;
use think\model\concern\SoftDelete;

class Permission extends Model
{
    use SoftDelete;

    /**
     * 自动时间戳
     *
     * @var bool
     */
    protected $autoWriteTimestamp = true;

    /** @var string */
    protected $createTime = 'create_time';

    /** @var string */
    protected $updateTime = 'update_time';

    /** @var string */
    protected $deleteTime = 'delete_time';

    /**
     * 类型转换
     *
     * @var array
     */
    protected $type = [
        'status'      => 'integer',
        'level'       => 'integer',
        'sort'        => 'integer',
        'conditions'  => 'json',
    ];

    /**
     * JSON 字段
     *
     * @var array
     */
    protected $json = ['conditions'];

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
    protected $name = 'auth_permissions';


    /**
     * 关联角色（多对多）
     *
     * @return \think\model\relation\BelongsToMany
     */
    public function roles()
    {
        $pivotTable = 'auth_role_permission';
        return $this->belongsToMany(
            Role::class,
            $pivotTable,
            'role_id',
            'permission_id'
        );
    }

    /**
     * 父权限
     *
     * @return \think\model\relation\BelongsTo
     */
    public function parent()
    {
        return $this->belongsTo(static::class, 'parent_id');
    }

    /**
     * 子权限
     *
     * @return \think\model\relation\HasMany
     */
    public function children()
    {
        return $this->hasMany(static::class, 'parent_id');
    }


    /**
     * 更新树形路径与层级
     *
     * 保存记录后调用，根据 parent_id 计算 path（格式如 0-1-3）与 level。
     * 该方法主要用于菜单驱动的权限创建/同步场景。
     *
     * @return void
     */
    public function updatePath(): void
    {
        if (empty($this->id)) {
            return;
        }

        if ($this->parent_id > 0) {
            $parent = static::find($this->parent_id);
            if ($parent && !empty($parent->path)) {
                $this->path  = rtrim($parent->path, '-') . '-' . $this->id;
                $this->level = (int)$parent->level + 1;
            } else {
                $this->path  = '0-' . $this->id;
                $this->level = 1;
            }
        } else {
            $this->path  = '0-' . $this->id;
            $this->level = 0;
        }

        static::where('id', $this->id)->update([
            'path'  => $this->path,
            'level' => $this->level,
        ]);
    }

    /**
     * 获取所有祖先权限ID
     *
     * 优先通过 path 字段解析（避免 N+1 查询），
     * path 为空时 fallback 到逐级查询。
     *
     * @param int $permissionId
     * @return array
     */
    public static function getAncestorIds(int $permissionId): array
    {
        $perm = static::find($permissionId);
        if (!$perm) {
            return [];
        }

        if (!empty($perm->path)) {
            $pathIds = explode('-', trim($perm->path, '-'));
            $pathIds = array_values(array_filter($pathIds, function ($id) use ($permissionId) {
                return $id !== '' && (int)$id !== $permissionId;
            }));
            return array_map('intval', $pathIds);
        }

        $ancestors = [];
        $current = $perm;
        while ($current && $current->parent_id) {
            $ancestors[] = $current->parent_id;
            $current = static::find($current->parent_id);
        }
        return $ancestors;
    }


    /**
     * 从配置文件批量创建/更新权限（幂等）
     *
     * @param array $permissions 权限定义数组
     * @return int 创建的记录数
     */
    public static function loadFromConfig(array $permissions): int
    {
        $count = 0;
        foreach ($permissions as $item) {
            $exists = static::withTrashed()->where('ident', $item['ident'])->find();
            $data = [
                'ident'       => $item['ident'],
                'name'        => $item['name'] ?? '',
                'type'        => $item['type'] ?? 'custom',
                'route'       => $item['route'] ?? '',
                'method'      => $item['method'] ?? '*',
                'description' => $item['description'] ?? '',
                'status'      => $item['status'] ?? 1,
                'sort'        => $item['sort'] ?? 0,
                'conditions'  => $item['conditions'] ?? [],
            ];

            if (!empty($item['parent'])) {
                $parent = static::where('ident', $item['parent'])->find();
                if ($parent) {
                    $data['parent_id'] = $parent->id;
                }
            }

            if ($exists) {
                if ($exists->delete_time) {
                    $exists->restore();
                }
                $exists->save($data);
            } else {
                static::create($data);
                $count++;
            }
        }
        return $count;
    }

}
