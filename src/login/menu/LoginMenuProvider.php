<?php
declare(strict_types=1);

namespace wise\login\menu;

use wise\support\contracts\MenuItemProvider;

/**
 * wise-login-security 后台菜单声明（ExtPoints::MENU_ITEM）
 *
 * 「安全管理」菜单组整体归属于本包：容器以 anchor='console' **自持**，
 * 因此卸载 / prune 时连同目录一并清理（卸载无痕）。
 *
 * 菜单不硬编码 INSERT，而是在此声明；由宿主侧
 * app\admin\service\MenuItemSync 扫描扩展点幂等落地（含菜单派生权限联动）。
 * 升级时以本文件为真相刷新：改这里再执行 `php think menu:sync` 即可。
 *
 * 派生的权限标识（供 RBAC 中间件与角色授权使用）：
 *   admin.login_security_attempt.* / admin.login_security_device.* /
 *   admin.login_security_event.*   / admin.auth_ip_lists.* /
 *   admin.login_security_totp.*
 */
class LoginMenuProvider implements MenuItemProvider
{
    public function ident(): string
    {
        return 'auth.login';
    }

    public function containers(): array
    {
        return [
            [
                'key'    => 'security',
                'name'   => '安全管理',
                'icon'   => 'bi bi-shield-check',
                'anchor' => 'console',
                'sort'   => 600,
            ],
        ];
    }

    public function items(): array
    {
        return [
            [
                'name'   => '登录尝试记录',
                'icon'   => 'bi bi-shield-exclamation',
                'path'   => '/admin/auth/login/attempt/index',
                'sort'   => 0,
                'type'   => 'menu',
                'status' => 1,
                'child'  => [
                    ['name' => '失败列表',     'path' => '/admin/auth/login/attempt/getList',      'type' => 'button'],
                    ['name' => '手动解锁',     'path' => '/admin/auth/login/attempt/unlock',       'type' => 'button'],
                    ['name' => '清理过期记录', 'path' => '/admin/auth/login/attempt/clearExpired', 'type' => 'button'],
                ],
            ],
            [
                'name'   => '安全设备管理',
                'icon'   => 'bi bi-phone',
                'path'   => '/admin/auth/login/device/index',
                'sort'   => 0,
                'type'   => 'menu',
                'status' => 1,
                'child'  => [
                    ['name' => '设备列表',   'path' => '/admin/auth/login/device/getList', 'type' => 'button'],
                    ['name' => '设备预览',   'path' => '/admin/auth/login/device/preview', 'type' => 'button'],
                    ['name' => '信任设备',   'path' => '/admin/auth/login/device/trust',   'type' => 'button'],
                    ['name' => '取消信任',   'path' => '/admin/auth/login/device/untrust', 'type' => 'button'],
                    ['name' => '撤销设备',   'path' => '/admin/auth/login/device/revoke',  'type' => 'button'],
                    ['name' => '重命名设备', 'path' => '/admin/auth/login/device/rename',  'type' => 'button'],
                ],
            ],
            [
                'name'   => '安全事件日志',
                'icon'   => 'bi bi-journal-code',
                'path'   => '/admin/auth/login/event/index',
                'sort'   => 0,
                'type'   => 'menu',
                'status' => 1,
                'child'  => [
                    ['name' => '事件列表', 'path' => '/admin/auth/login/event/getList',  'type' => 'button'],
                    ['name' => '事件预览', 'path' => '/admin/auth/login/event/preview',  'type' => 'button'],
                    ['name' => '清理日志', 'path' => '/admin/auth/login/event/clearLog', 'type' => 'button'],
                ],
            ],
            [
                'name'   => 'IP 黑白名单',
                'icon'   => 'bi bi-globe',
                'path'   => '/admin/auth/login/ip-list/index',
                'sort'   => 0,
                'type'   => 'menu',
                'status' => 1,
                'child'  => [
                    ['name' => 'IP列表',     'path' => '/admin/auth/login/ip-list/getList', 'type' => 'button'],
                    ['name' => '新增IP',     'path' => '/admin/auth/login/ip-list/add',     'type' => 'button'],
                    ['name' => '编辑IP',     'path' => '/admin/auth/login/ip-list/edit',    'type' => 'button'],
                    ['name' => '删除IP',     'path' => '/admin/auth/login/ip-list/delete',  'type' => 'button'],
                    ['name' => '切换IP状态', 'path' => '/admin/auth/login/ip-list/status',  'type' => 'button'],
                ],
            ],
            [
                'name'   => 'TOTP 配置',
                'icon'   => 'bi bi-shield-lock',
                'path'   => '/admin/auth/login/totp/index',
                'sort'   => 0,
                'type'   => 'menu',
                'status' => 1,
                'child'  => [
                    ['name' => '配置列表', 'path' => '/admin/auth/login/totp/getList',      'type' => 'button'],
                    ['name' => '强制关闭', 'path' => '/admin/auth/login/totp/forceDisable', 'type' => 'button'],
                    ['name' => '重置密钥', 'path' => '/admin/auth/login/totp/resetSecret',  'type' => 'button'],
                    ['name' => '删除配置', 'path' => '/admin/auth/login/totp/delete',       'type' => 'button'],
                    ['name' => '恢复配置', 'path' => '/admin/auth/login/totp/restore',       'type' => 'button'],
                ],
            ],
        ];
    }
}
