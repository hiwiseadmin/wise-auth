<?php

declare(strict_types=1);

namespace wise\auth\tests\fixtures;

use wise\auth\attribute\AuthPermission;

/**
 * Attribute 扫描测试夹具
 *
 * 类级声明提供默认值（type/parent），方法级声明生成权限节点，
 * 同一方法可重复声明多条权限。
 */
#[AuthPermission(type: 'route', parent: 'admin.user')]
class AuthPermissionController
{
    #[AuthPermission(ident: 'admin.user.list', name: '管理员列表', route: '/admin/users/index')]
    public function index(): void
    {
    }

    #[AuthPermission(ident: 'admin.user.create', name: '新增管理员', route: '/admin/users/create', method: 'POST')]
    #[AuthPermission(ident: 'admin.user.export', name: '导出管理员', route: '/admin/users/export')]
    public function save(): void
    {
    }

    #[AuthPermission(name: '缺少 ident 的声明')]
    public function missingIdent(): void
    {
    }

    public function plain(): void
    {
    }
}
