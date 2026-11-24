<?php
/**
 * 权限变更事件
 *
 * 在权限创建、更新、删除时触发。
 */
namespace wise\auth\event;

class PermissionChanged
{
    /**
     * @var string 操作类型：create/update/delete
     */
    public string $action;

    /**
     * @var int 权限ID
     */
    public int $permissionId;

    /**
     * @var array 权限数据（变更后）
     */
    public array $data;

    /**
     * @param string $action
     * @param int    $permissionId
     * @param array  $data
     */
    public function __construct(string $action, int $permissionId, array $data = [])
    {
        $this->action       = $action;
        $this->permissionId = $permissionId;
        $this->data         = $data;
    }
}
