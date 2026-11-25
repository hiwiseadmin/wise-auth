<?php

declare(strict_types=1);

namespace wise\auth\attribute;

use Attribute;

/**
 * 权限声明 Attribute
 *
 * 用于在控制器类/方法上声明权限节点，由 PermissionRegistrar 扫描后落库。
 * 与 wise-operation-log 的 #[OperationLog] 保持同一套声明风格。
 *
 * 类级用法：只提供默认值（ident 不参与继承），减少方法级重复
 *   #[AuthPermission(type: 'route', parent: 'admin.user')]
 *   class Users extends BaseController {}
 *
 * 方法级用法：必须提供 ident，一条 Attribute 对应一条权限
 *   #[AuthPermission(ident: 'admin.user.list', name: '管理员列表', route: '/admin/users/index')]
 *   public function index() {}
 *
 * 同一方法可重复声明（如列表 + 导出）：
 *   #[AuthPermission(ident: 'admin.user.list', name: '管理员列表', route: '/admin/users/index')]
 *   #[AuthPermission(ident: 'admin.user.export', name: '导出用户', route: '/admin/users/export')]
 *
 * 未显式声明的字段保持 null，交由 Permission::loadFromConfig() 使用框架默认值，
 * 这样类级默认值不会被方法级的“空默认值”覆盖。
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD | Attribute::IS_REPEATABLE)]
class AuthPermission
{
    /**
     * @param string|null $ident       权限唯一标识（方法级必填）
     * @param string|null $name        权限名称
     * @param string|null $type        权限类型：route/api/custom
     * @param string|null $route       对应路由（type=route 时生效）
     * @param string|null $method      HTTP 方法：GET/POST/PUT/DELETE/*
     * @param string|null $description 权限说明
     * @param string|null $parent      父权限 ident
     * @param int|null    $sort        排序
     * @param int|null    $status      状态：1 启用 / 0 禁用
     * @param array|null  $conditions  附加条件
     */
    public function __construct(
        public ?string $ident = null,
        public ?string $name = null,
        public ?string $type = null,
        public ?string $route = null,
        public ?string $method = null,
        public ?string $description = null,
        public ?string $parent = null,
        public ?int $sort = null,
        public ?int $status = null,
        public ?array $conditions = null
    ) {}

    /**
     * 转成 Permission::loadFromConfig() 可消费的数组
     *
     * 仅保留显式声明的字段，未声明字段由 loadFromConfig() 填默认值。
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return array_filter(
            [
                'ident'       => $this->ident,
                'name'        => $this->name,
                'type'        => $this->type,
                'route'       => $this->route,
                'method'      => $this->method,
                'description' => $this->description,
                'parent'      => $this->parent,
                'sort'        => $this->sort,
                'status'      => $this->status,
                'conditions'  => $this->conditions,
            ],
            static fn ($value): bool => $value !== null
        );
    }
}
