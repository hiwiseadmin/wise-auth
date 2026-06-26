<?php
/**
 * 用户-角色中间表模型（多态关联）
 *
 * user_type + user_id 共同标识一个用户实例。
 */
namespace wise\auth\model;

use think\Model;

class UserRole extends Model
{
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

    /**
     * 表名（不含前缀，框架自动添加）
     *
     * @var string
     */
    protected $name = 'auth_user_role';

    public function __construct($data = [])
    {
        parent::__construct($data);
        $this->setName(config('wise-auth.table_names.user_role', $this->name));
    }

    /**
     * 关联角色
     *
     * @return \think\model\relation\BelongsTo
     */
    public function role()
    {
        return $this->belongsTo(Role::class);
    }
}
