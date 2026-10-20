<?php
/**
 * 角色变更事件
 *
 * 在角色创建、更新、删除时触发。
 */
namespace wise\auth\event;

class RoleChanged
{
    /**
     * @var string 操作类型：create/update/delete
     */
    public string $action;

    /**
     * @var int 角色ID
     */
    public int $roleId;

    /**
     * @var array 角色数据（变更后）
     */
    public array $data;

    /**
     * @param string $action
     * @param int    $roleId
     * @param array  $data
     */
    public function __construct(string $action, int $roleId, array $data = [])
    {
        $this->action = $action;
        $this->roleId = $roleId;
        $this->data   = $data;
    }
}
