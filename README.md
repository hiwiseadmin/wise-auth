# wiseadmin/wise-auth

> 为 ThinkPHP 6 设计的通用 RBAC 权限管理包，支持多应用、多用户类型、角色继承（RBAC1）与职责分离约束（RBAC2 扩展）。

[![PHP Version](https://img.shields.io/badge/php-%3E%3D8.1-blue)](https://www.php.net/)
[![ThinkPHP](https://img.shields.io/badge/thinkphp-%5E6.0%20%7C%7C%20%5E8.0-green)](https://www.thinkphp.cn/)
[![License](https://img.shields.io/badge/license-Apache%202.0-brightgreen)](LICENSE)
[![Packagist](https://img.shields.io/badge/packagist-wiseadmin%2Fwise--auth-orange)](https://packagist.org/packages/wiseadmin/wise-auth)

---

## 目录

- [核心特性](#核心特性)
- [环境要求](#环境要求)
- [安装](#安装)
- [快速开始](#快速开始)
- [核心概念](#核心概念)
- [配置说明](#配置说明)
- [使用指南](#使用指南)
  - [用户模型接入](#用户模型接入)
  - [权限检查](#权限检查)
  - [角色管理](#角色管理)
  - [中间件集成](#中间件集成)
  - [超级管理员](#超级管理员)
  - [角色继承（RBAC1）](#角色继承rbac1)
  - [约束检查（RBAC2）](#约束检查rbac2)
  - [数据权限](#数据权限)
- [权限来源](#权限来源)
- [事件系统](#事件系统)
- [命令行工具](#命令行工具)
- [数据库表结构](#数据库表结构)
- [目录结构](#目录结构)
- [最佳实践](#最佳实践)
- [License](#license)

---

## 核心特性

- **标准 RBAC** — 用户 → 角色 → 权限 三层模型，清晰直观
- **多应用支持** — 通过多态关联支持 admin、member 等多种用户类型
- **角色继承（RBAC1）** — 父子角色树，子角色自动继承父角色权限，支持无限层级与循环检测
- **职责分离约束（RBAC2 扩展）** — 互斥角色、基数限制、前置角色三种内置约束规则
- **超级管理员机制** — 支持超级角色 slug 与超级用户 ID 列表两种方式
- **多来源权限加载** — 数据库 / 配置文件 / 控制器 Attribute（`#[AuthPermission]`）三种权限定义方式
- **缓存优化** — 用户权限缓存，支持 Redis / 文件缓存，TTL 可配
- **路由自动匹配** — 中间件自动将路由映射到权限标识，支持黑白名单策略
- **事件驱动** — 角色/权限变更时自动清除缓存，支持业务侧自定义监听
- **灵活的错误处理** — 未授权时可选择抛出异常、重定向、JSON 响应或自定义处理器

---

## 环境要求

| 依赖 | 版本 |
|------|-----|
| PHP | >= 8.1 |
| ThinkPHP | >= 6.0 |

---

## 安装

### 1. 通过 Composer 安装

```bash
composer require wiseadmin/wise-auth
```

### 2. 初始化

发布配置文件并导入权限：

```bash
php think vendor:publish   # 发布配置文件 wise-auth.php 到项目 config/ 目录
php think wise:auth:import # 从 config/attribute 加载并注册权限数据
```

### 3. 执行数据库迁移

```bash
php think migrate:run
```

将创建以下 4 张数据表：

| 表名（默认） | 说明 |
|-------------|------|
| `auth_roles` | 角色表 |
| `auth_permissions` | 权限规则表 |
| `auth_role_permission` | 角色-权限中间表 |
| `auth_user_role` | 用户-角色多态关联表 |

---

## 快速开始

### 第一步：给你的用户模型加上权限能力

```php
<?php
namespace app\admin\model;

use think\Model;
use wise\auth\traits\HasRoles;
use wise\auth\contract\UserContract;

class Admin extends Model implements UserContract
{
    use HasRoles;
}
```

### 第二步：配置超级管理员（可选）

在 `config/wise-auth.php` 中：

```php
'super_admin_ids' => [1],
```

### 第三步：在路由中使用中间件

```php
// route/admin.php
Route::group('admin', function () {
    Route::get('dashboard', 'admin.Index/index');
    Route::get('users', 'admin.Admins/index');
})->middleware(\wise\auth\middleware\RbacMiddleware::class);
```

### 第四步：在控制器中检查权限

```php
<?php
namespace app\admin\controller;

use app\common\controller\BaseController;
use wise\auth\facade\Rbac;

class UserController extends BaseController
{
    public function delete($id)
    {
        $adminId = session('admin_id');

        if (!Rbac::check($adminId, 'admin', 'admin.user.delete')) {
            return json(['code' => 403, 'msg' => '没有删除权限']);
        }

        // 执行删除逻辑...
    }
}
```

---

## 核心概念

```
┌──────────┐      ┌───────────┐      ┌──────────────┐
│   用户    │ ───→ │   角色     │ ───→ │     权限      │
│ (Admin)  │ 多对多 │  (Role)   │ 多对多 │ (Permission) │
└──────────┘      └───────────┘      └──────────────┘
                        │
                        │ 继承 (parent_id)
                        ▼
                  ┌───────────┐
                  │   父角色    │
                  └───────────┘
```

- **用户（User）**：使用 `HasRoles` Trait 的模型实例，通过 `user_type` + `user_id` 多态关联到角色
- **角色（Role）**：权限的集合，用 `slug` 唯一标识，支持父子继承
- **权限（Permission）**：最小的授权单位，用 `ident` 唯一标识（如 `admin.user.list`），可关联路由、请求方法等

---

## 配置说明

完整配置文件位于 `config/wise-auth.php`，以下是所有配置项的详细说明：

### 用户模型

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `default_user_model` | string | `\app\admin\model\Admin::class` | 默认用户模型（FQCN），需 use HasRoles |
| `user_models` | array | `[]` | 多用户类型映射，key 为 guard/user_type，value 为模型类 |

```php
'user_models' => [
    'admin'  => \app\admin\model\Admin::class,
    'member' => \app\api\model\Member::class,
],
```

### 数据表

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `auth_roles` | - | - | 角色表名（固定） |
| `auth_permissions` | - | - | 权限表名（固定） |
| `auth_role_permission` | - | - | 角色-权限中间表名（固定） |
| `auth_user_role` | - | - | 用户-角色中间表名（固定） |

### 超级管理员

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `super_role` | string\|null | `super_admin` | 超级管理员角色 slug，设为 null 禁用 |
| `super_admin_ids` | array | `[]` | 超级管理员用户 ID 列表 |

### 缓存

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `cache_enabled` | bool | `true` | 是否启用权限缓存 |
| `cache_store` | string\|null | `wise_auth` | 缓存 store 名。默认由包自动注册专属 store `wise_auth`（只合并框架 `cache.stores`）；可填宿主已有 store（如 `redis`）；null 复用框架默认 store |
| `cache_store_config` | array\|null | `null` | 专属 store 的驱动参数，null 时按宿主默认 store 推导（File → 独立目录 `wise_auth/`；其它驱动 → 加 `wise_auth_` 前缀） |
| `cache_ttl` | int\|null | `3600` | 缓存过期时间（秒），null 为永久 |
| `cache_prefix` | string | `wiseauth:` | 缓存键前缀 |

### 权限来源

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `permission_sources` | array | `['database']` | 权限来源：database / attribute / config |
| `attribute_dirs` | array | `[]` | `#[AuthPermission]` 扫描目录 |
| `permissions` | array | `[]` | 配置文件驱动的权限列表 |

### 中间件策略

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `default_mode` | string | `whitelist` | 默认检查模式：whitelist / blacklist |
| `whitelist_routes` | array | `[...]` | 白名单路由（无需鉴权） |
| `blacklist_routes` | array | `[]` | 黑名单路由（必须鉴权） |
| `middleware_check_type` | string | `or` | 默认权限检查类型：and / or |
| `middleware_auth_check` | bool | `true` | 中间件是否检查登录状态 |
| `user_resolver` | Closure\|null | `null` | 自定义用户解析器 |

### 未授权处理

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `unauthorized_action` | string | `json` | exception / redirect / json / custom |
| `unauthorized_redirect` | string | `/admin/login` | 重定向地址（redirect 模式） |
| `unauthorized_handler` | Closure\|null | `null` | 自定义处理器（custom 模式） |

### 角色继承

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `inheritance_enabled` | bool | `true` | 是否启用角色继承 |
| `inheritance_max_depth` | int\|null | `10` | 最大继承深度，null/0 为无限制 |
| `cycle_check_enabled` | bool | `true` | 是否检测循环继承 |

### RBAC2 约束

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `constraint_checker` | string\|Closure\|null | `null` | 自定义约束检查器 |
| `constraints` | array | `[]` | 内置约束规则（详见 RBAC2 章节） |

### 数据权限

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `data_policy` | Closure\|null | `null` | 数据权限策略（行级过滤） |

---

## 使用指南

### 用户模型接入

```php
<?php
namespace app\admin\model;

use think\Model;
use wise\auth\traits\HasRoles;

class Admin extends Model
{
    use HasRoles;

    // 可选：覆盖默认的 user_type（默认取类名小写）
    public function getAuthUserType(): string
    {
        return 'admin';
    }
}
```

`HasRoles` Trait 提供以下方法：

| 方法 | 说明 |
|------|------|
| `getRoles()` | 获取所有角色 |
| `hasRole($roles, $requireAll)` | 检查是否拥有指定角色（slug/ID） |
| `assignRole($roleIds)` | 分配角色（支持 slug 或 ID） |
| `removeRole($roleIds)` | 移除角色 |
| `syncRoles($roleIds)` | 同步角色（先清空再分配） |
| `can($permission)` | 检查单个权限 |
| `hasPermission($permissions, $requireAll)` | 检查权限（支持 OR/AND 模式） |
| `getAllPermissions()` | 获取用户所有权限标识 |
| `isSuperAdmin()` | 判断是否为超级管理员 |

`HasRoles` 还会自动注册 `saved` 和 `deleted` 模型事件，在用户信息变更时自动清除权限缓存。

---

### 权限检查

#### 方式一：通过 Trait 实例方法

```php
$admin = Admin::find(1);

// 单个权限
if ($admin->can('admin.user.edit')) {
    // ...
}

// OR 检查（任一满足即可）
if ($admin->hasPermission(['admin.user.edit', 'admin.user.delete'])) {
    // ...
}

// AND 检查（全部满足才行）
if ($admin->hasPermission(['admin.user.edit', 'admin.user.delete'], true)) {
    // ...
}
```

#### 方式二：通过门面（静态调用）

```php
use wise\auth\facade\Rbac;

// 单个权限检查
Rbac::check($userId, 'admin', 'admin.user.list');

// OR 检查
Rbac::checkAny($userId, 'admin', ['admin.user.edit', 'admin.user.delete']);

// AND 检查
Rbac::checkAll($userId, 'admin', ['admin.user.edit', 'admin.user.delete']);

// 超管判断
Rbac::isSuperAdmin($userId, 'admin');

// 获取用户所有权限
$permissions = Rbac::getUserPermissions($userId, 'admin');

// 路由匹配权限
$permissions = Rbac::matchRouteToPermissions('/admin/admins/index', 'GET');
```

#### 方式三：模板中使用

```html
<!-- 按钮权限控制 -->
{if $admin->can('admin.user.delete')}
    <button class="btn btn-danger btn-delete">删除</button>
{/if}

<!-- 角色检查 -->
{if $admin->hasRole('editor')}
    <div class="editor-panel">编辑器面板</div>
{/if}
```

---

### 角色管理

#### 创建角色

```php
use wise\auth\model\Role;

$role = Role::create([
    'name'        => '编辑员',
    'slug'        => 'editor',
    'description' => '内容编辑角色',
    'parent_id'   => 0,       // 父角色 ID，0 表示顶级
    'is_inherit'  => 1,       // 是否继承父角色权限
    'sort'        => 10,
    'status'      => 1,
]);
```

#### 赋予权限

```php
$role = Role::find(1);

// 赋予单个权限
$role->grantPermission(1);

// 赋予多个权限
$role->grantPermission([1, 2, 3]);

// 撤销权限
$role->revokePermission(2);

// 同步权限（先清空再设置）
$role->syncPermissions([1, 3, 5]);
```

#### 获取角色树

```php
use wise\auth\facade\Rbac;

$roleTree = Rbac::getRoleTree();
```

返回格式示例：

```php
[
    [
        'id'       => 1,
        'name'     => '超级管理员',
        'slug'     => 'super_admin',
        'parent_id' => 0,
        'children' => [
            [
                'id'       => 2,
                'name'     => '管理员',
                'slug'     => 'admin',
                'parent_id' => 1,
                'children' => [...],
            ],
        ],
    ],
]
```

#### 检测循环继承

```php
use wise\auth\model\Role;

// 在保存前检查
if (config('wise-auth.cycle_check_enabled', true)) {
    if (Role::hasCycle($newParentId, $currentRoleId)) {
        throw new \Exception('检测到角色循环继承！');
    }
}
```

---

### 中间件集成

#### 基础用法

在路由定义中注册中间件：

```php
// route/admin.php
Route::group('admin', function () {
    Route::get('dashboard', 'admin.Index/index');
    Route::resource('users', 'admin.Admins');
    Route::resource('roles', 'admin.Roles');
})->middleware(\wise\auth\middleware\RbacMiddleware::class);
```

中间件会自动：
1. 从 Session（`admin_id`）或自定义解析器获取当前用户
2. 超级管理员直接放行
3. 检查当前路由是否在白名单中（白名单命中则跳过鉴权）
4. 将当前路由匹配到权限标识（如 `/admin/admins/index` → `admin.admins.index`）
5. 执行 `checkAny`（OR 模式）或 `checkAll`（AND 模式）
6. 根据 `unauthorized_action` 配置处理未授权情况

#### 按路由指定权限

```php
// 手动指定需要的权限（使用完整类名）
Route::get('dangerous', 'admin.Tools/clean')
    ->middleware(\wise\auth\middleware\RbacMiddleware::class . ':admin.tools.clean');
```

#### 中间件注册

在 `app/middleware.php` 中注册中间件别名（TP8 仅支持静态配置）：

```php
return [
    // 中间件别名
    'alias' => [
        'wise.auth' => \wise\auth\middleware\RbacMiddleware::class,
    ],
    // 全局中间件（可选）
    // 'global' => [],
];
```

#### 自定义用户解析器

当用户信息不在 Session 时（如使用 JWT）：

```php
'user_resolver' => function () {
    $token = request()->header('Authorization');
    if ($token) {
        // JWT 解析，获取用户 ID
        $userId = JwtService::parse($token)->uid;
        return \app\admin\model\Admin::find($userId);
    }
    return null;
},
```

#### 黑白名单策略

**白名单模式**（默认）：未匹配路由默认需要鉴权，白名单内路由可跳过。

```php
'default_mode'      => 'whitelist',
'whitelist_routes'  => [
    '/admin/login',
    '/admin/logout',
    '/admin/auth/*',   // 支持通配符
    '/api/public/*',
],
```

**黑名单模式**：未匹配路由默认允许访问，黑名单内路由必须鉴权。

```php
'default_mode'      => 'blacklist',
'blacklist_routes'  => [
    '/admin/finance/*',
],
```

#### 未授权处理

四种模式可选：

```php
// 抛出异常（适合框架级处理）
'unauthorized_action' => 'exception',

// 重定向（适合传统 Web 应用）
'unauthorized_action' => 'redirect',
'unauthorized_redirect' => '/admin/login',

// 返回 JSON（适合 API 接口，默认）
'unauthorized_action' => 'json',
// 响应格式：{"code":403,"msg":"Permission denied: ...","data":[],"timestamp":...}

// 自定义处理
'unauthorized_action' => 'custom',
'unauthorized_handler' => function (\think\Request $request) {
    return json(['code' => 403, 'msg' => '您没有访问权限'])->code(403);
},
```

---

### 超级管理员

支持两种超管判断方式：

#### 方式一：用户 ID 列表

```php
'super_admin_ids' => [1, 2],
```

全局生效，不受 `user_type` 影响。通常与项目 `config('app.super_admin_ids')` 保持一致。

#### 方式二：超级角色 slug

```php
'super_role' => 'super_admin',
```

拥有 `super_admin` 角色的用户自动拥有全部权限。此方式受 `user_type` 多态关联约束。

```php
// 在业务中使用
$admin = Admin::find(1);
if ($admin->isSuperAdmin()) {
    // 超管逻辑
}
```

---

### 角色继承（RBAC1）

通过 `parent_id` 字段建立角色父子关系，子角色自动继承父角色的所有权限。

```
  super_admin (全部权限)
       │
       ▼
     admin (管理权限)
       │
  ┌────┴────┐
  ▼         ▼
editor    operator
```

```php
// editor 自动继承 admin 的权限
$editor = Role::create([
    'name'      => '编辑员',
    'slug'      => 'editor',
    'parent_id' => $adminRoleId,   // 父角色 ID
    'is_inherit' => 1,             // 开启继承
]);
```

- 支持多层级继承（受 `inheritance_max_depth` 限制）
- 自动检测循环引用（`cycle_check_enabled` 开启时）
- 继承链通过 `path` 字段快速查询（如 `0-1-3-7`）
- 角色权限变更时自动清除所有受影响用户的缓存

---

### 约束检查（RBAC2）

内置三种约束规则，在 `config/wise-auth.php` 中配置：

#### 互斥角色（mutual_exclusion）

某些角色不能同时分配给同一个用户：

```php
'constraints' => [
    'mutual_exclusion' => [
        ['admin', 'auditor'],     // admin 和 auditor 互斥
        ['finance', 'cashier'],   // finance 和 cashier 互斥
    ],
],
```

#### 基数限制（cardinality）

限制某个角色的最大用户数：

```php
'constraints' => [
    'cardinality' => [
        'super_admin' => 3,       // super_admin 最多 3 人
        'finance'     => 5,       // finance 最多 5 人
    ],
],
```

#### 前置角色（prerequisite）

分配某角色前必须先拥有另一角色：

```php
'constraints' => [
    'prerequisite' => [
        'super_admin' => ['admin'],   // 分配 super_admin 前必须先有 admin
    ],
],
```

#### 自定义约束检查器

```php
// config/wise-auth.php
'constraint_checker' => \app\common\auth\CustomConstraintChecker::class,
```

需实现 `\wise\auth\contract\ConstraintCheckerInterface` 接口：

```php
<?php
namespace app\common\auth;

use wise\auth\contract\ConstraintCheckerInterface;

class CustomConstraintChecker implements ConstraintCheckerInterface
{
    public function checkBeforeAssignRole($userId, string $userType, $roleId, array $context = []): bool
    {
        // 自定义逻辑：例如检查用户部门是否匹配
        return true;
    }

    public function checkBeforeGrantPermission($roleId, $permissionId, array $context = []): bool
    {
        return true;
    }

    public function checkBeforeSaveRole(array $data, $roleId = null): bool
    {
        return true;
    }
}
```

---

### 数据权限

通过 `data_policy` 配置行级数据过滤策略：

```php
'data_policy' => function (string $permission, $user, array $context = []): \Closure {
    // 返回一个闭包用于修改查询条件
    return function ($query) use ($user) {
        // 例如：只看自己部门的数据
        $query->where('dept_id', $user->dept_id);
    };
},
```

`auth_user_role` 表的 `data_scope` 字段支持为特定用户-角色关联附加数据范围（如部门 ID 列表）。

---

## 权限来源

WiseAuth 支持三种权限定义来源，可在 `permission_sources` 中组合使用：

### 数据库（database）

通过后台管理界面动态增删权限，数据持久化在 `auth_permissions` 表中。

### 配置文件（config）

在 `wise-auth.php` 的 `permissions` 节点定义：

```php
'permission_sources' => ['database', 'config'],
'permissions' => [
    [
        'ident'       => 'admin.dashboard',
        'name'        => '仪表盘',
        'type'        => 'route',
        'route'       => '/admin/index/index',
        'method'      => '*',
        'description' => '查看后台仪表盘',
    ],
    [
        'ident'       => 'admin.user.list',
        'name'        => '管理员列表',
        'type'        => 'route',
        'route'       => '/admin/admins/index',
        'method'      => 'GET',
    ],
    [
        'ident'  => 'admin.user.delete',
        'name'   => '删除管理员',
        'type'   => 'custom',
        'parent' => 'admin.user.list',  // 父权限 ident
    ],
],
```

### Attribute（attribute）

在控制器类/方法上使用 `#[AuthPermission]` 声明权限（PHP 8 Attribute，与 wise-operation-log 的 `#[OperationLog]` 同一风格）：

```php
use wise\auth\attribute\AuthPermission;

class Admins
{
    #[AuthPermission(ident: 'admin.user.list', name: '管理员列表', type: 'route', route: '/admin/admins/index', method: 'GET')]
    public function index()
    {
        // ...
    }

    #[AuthPermission(ident: 'admin.user.delete', name: '删除管理员', type: 'custom')]
    public function delete($id)
    {
        // ...
    }
}
```

类级声明只提供默认值（`ident` 不参与继承），可把公共字段提到类上；同一方法可重复声明多条权限：

```php
#[AuthPermission(type: 'route', parent: 'admin.user')]
class Admins extends BaseController
{
    #[AuthPermission(ident: 'admin.user.list', name: '管理员列表', route: '/admin/admins/index')]
    public function index() {}

    #[AuthPermission(ident: 'admin.user.export', name: '导出管理员', route: '/admin/admins/export')]
    #[AuthPermission(ident: 'admin.user.export_all', name: '导出全部', route: '/admin/admins/export_all')]
    public function export() {}
}
```

字段与 `permissions` 配置一致：`ident`、`name`、`type`、`route`、`method`、`description`、`parent`、`sort`、`status`、`conditions`；未声明的字段由框架填默认值，方法级声明会覆盖类级默认值。

扫描目录配置：

```php
'permission_sources' => ['database', 'attribute'],
'attribute_dirs'     => [
    app_path('admin/controller'),
    app_path('api/controller'),
],
```

> 扫描时通过反射读取 Attribute，因此目标目录应是**宿主 app 控制器**（composer PSR-4 自动加载，CLI 下同样可加载）。插件在 CLI 下不注册 `plugin\*` 命名空间，插件权限不走这条链路：用 `manifest.json` 的 `menus`（控制器 docblock `@menu`）与 `permissions` 声明，配合 `plugin:menu-migrate` / `menu:permission-sync` 落库。`class_exists` 失败只可能是类名写错或父类缺失，跳过该文件不阻断整轮同步。

通过命令手动导入：

```bash
php think wise:auth:import --from=attribute --dir=app/admin/controller
```

---

## 事件系统

WiseAuth 通过 ThinkPHP 事件系统提供了丰富的事件钩子：

| 事件名 | 触发时机 | 携带数据 |
|--------|----------|----------|
| `RoleChanged` | 角色创建/更新/删除 | `action`, `roleId`, `data` |
| `PermissionChanged` | 权限创建/更新/删除 | `action`, `permissionId`, `data` |
| `RbacRoleAssigning` | 角色分配前 | `user_id`, `user_type`, `role_ids` |
| `RbacRoleAssigned` | 角色分配后 | `user_id`, `user_type`, `role_ids` |
| `RbacRoleRemoving` | 角色移除前 | `user_id`, `user_type`, `role_ids` |
| `RbacRoleRemoved` | 角色移除后 | `user_id`, `user_type`, `role_ids` |
| `RbacRoleSynced` | 角色同步后 | `user_id`, `user_type`, `role_ids` |

### 触发事件

```php
use think\facade\Event;
use wise\auth\event\RoleChanged;

// 在角色修改后触发
Event::trigger(new RoleChanged('update', $role->id, $role->toArray()));
```

### 监听事件

```php
// app/event.php
return [
    'listen' => [
        'RbacRoleAssigned' => [
            \app\admin\listener\OperationLog::class,
        ],
    ],
];
```

或在 `app/event.php` 中订阅：

```php
'subscribe' => [
    \app\admin\subscribe\UserAuthListener::class,
],
```

---

## 命令行工具

### wise:auth:import

从不同来源批量导入权限。

```bash
# 从配置文件导入
php think wise:auth:import --from=config

# 从控制器 Attribute 导入
php think wise:auth:import --from=attribute --dir=app/admin/controller

# 从 JSON 文件导入
php think wise:auth:import --from=json --file=permissions.json
```

JSON 文件格式：

```json
[
    {
        "ident": "admin.report.view",
        "name": "查看报表",
        "type": "route",
        "route": "/admin/report/index",
        "method": "*"
    }
]
```

### wise:auth:clear

清除权限缓存。

```bash
# 清除所有缓存
php think wise:auth:clear

# 清除指定用户缓存
php think wise:auth:clear --user=1 --type=admin
```

---

## 数据库表结构

### auth_roles（角色表）

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | int, PK | 主键 |
| `name` | varchar(50) | 角色名称 |
| `slug` | varchar(50), UNIQUE | 角色唯一标识 |
| `description` | varchar(255) | 描述 |
| `parent_id` | int, DEFAULT 0 | 父角色 ID（RBAC1 继承） |
| `path` | varchar(500) | 树形路径（如 `0-1-3`） |
| `level` | int | 层级深度 |
| `is_inherit` | tinyint, DEFAULT 1 | 是否继承父角色权限 |
| `sort` | int | 排序 |
| `status` | tinyint, DEFAULT 1 | 状态（1:启用 0:禁用） |
| `extend` | json | 扩展属性 |
| `create_time` | dateTime | 创建时间戳 |
| `update_time` | dateTime, nullable | 更新时间戳 |
| `delete_time` | dateTime, nullable | 软删除 |

### auth_permissions（权限表）

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | int, PK | 主键 |
| `ident` | varchar(100), UNIQUE | 权限标识（如 `admin.user.list`） |
| `name` | varchar(100) | 权限名称 |
| `description` | varchar(255) | 描述 |
| `type` | varchar(20), DEFAULT 'route' | 类型：route/api/custom/menu |
| `route` | varchar(200) | 路由路径（支持通配符 `*`） |
| `method` | varchar(20), DEFAULT '*' | 请求方法（GET/POST/PUT/DELETE/*） |
| `parent_id` | int, DEFAULT 0 | 父权限 ID |
| `path` | varchar(500) | 树形路径 |
| `level` | int | 层级深度 |
| `plugin` | varchar(50) | 所属插件标识 |
| `source` | varchar(20), DEFAULT 'database' | 来源：database/config/attribute |
| `conditions` | text, nullable | 权限条件（JSON） |
| `sort` | int | 排序 |
| `status` | tinyint, DEFAULT 1 | 状态 |
| `extend` | json | 扩展属性 |
| `create_time` | dateTime | 创建时间戳 |
| `update_time` | dateTime, nullable | 更新时间戳 |
| `delete_time` | dateTime, nullable | 软删除 |

### auth_role_permission（角色-权限中间表）

| 字段 | 类型 | 说明 |
|------|------|------|
| `role_id` | int | 角色 ID（联合主键） |
| `permission_id` | int | 权限 ID（联合主键） |

### auth_user_role（用户-角色多态关联表）

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | int, PK | 主键 |
| `user_type` | varchar(50), DEFAULT 'admin' | 用户类型 |
| `user_id` | int | 用户 ID |
| `role_id` | int | 角色 ID |
| `data_scope` | json, nullable | 数据权限范围 |
| `expired_at` | dateTime, nullable | 角色过期时间戳 |
| `create_time` | dateTime | 创建时间戳 |
| `update_time` | dateTime, nullable | 更新时间戳 |

**唯一索引**：`(user_id, role_id)`

---

## 目录结构

```
wise-auth/
├── composer.json                         # Composer 包定义
├── config/
│   └── wise-auth.php                        # 主配置文件
├── database/
│   └── migrations/
│       ├── 20240101000001_...roles.php   # 角色表迁移
│       ├── 20240101000002_...permissions.php  # 权限表迁移
│       ├── 20240101000003_...role_permission.php  # 角色-权限中间表迁移
│       └── 20240101000004_...user_role.php  # 用户-角色中间表迁移
└── src/
    ├── Service.php                       # ThinkPHP 服务提供者
    ├── facade/
    │   └── Rbac.php                      # RBAC 静态门面
    ├── contract/
    │   ├── UserContract.php              # 用户模型契约接口
    │   └── ConstraintCheckerInterface.php # 约束检查器接口
    ├── model/
    │   ├── Role.php                      # 角色模型
    │   ├── Permission.php                # 权限模型
    │   └── UserRole.php                  # 用户-角色多态模型
    ├── service/
    │   ├── RbacManager.php               # 核心权限验证服务
    │   └── PermissionRegistrar.php       # 权限注册与缓存管理
    ├── middleware/
    │   └── RbacMiddleware.php            # 路由中间件
    ├── trait/
    │   ├── HasRoles.php                  # 用户角色关联 Trait
    │   └── CacheKeyHelper.php            # 缓存键辅助 Trait
    ├── event/
    │   ├── RoleChanged.php               # 角色变更事件
    │   └── PermissionChanged.php         # 权限变更事件
    ├── subscribe/
    │   └── AuthEventSubscriber.php       # 事件订阅者
    ├── exception/
    │   ├── UnauthorizedException.php     # 未授权异常
    │   └── ConstraintViolationException.php  # 约束违反异常
    └── command/
        ├── ClearCache.php                # wise:auth:clear 清理缓存命令
        └── ImportPermissions.php         # wise:auth:import 导入权限命令
```

---

## 最佳实践

### 1. 权限标识命名规范

推荐使用点分格式，体现层级关系：

```
模块.控制器.操作
admin.user.list
admin.user.create
admin.user.edit
admin.user.delete
admin.role.list
admin.config.site
```

### 2. 缓存策略建议

- **开发环境**：关闭缓存（`cache_enabled => false`），便于调试权限变更
- **生产环境**：保留默认的专属 store `wise_auth`（需要 Redis 时通过 `cache_store_config` 指定驱动参数），推荐 TTL 1 小时
- **权限变更后**：触发 `RoleChanged` / `PermissionChanged` 事件，自动清除缓存

### 3. 路由通配符使用

权限的 `route` 字段支持 `*` 通配符：

```
/admin/user/*        → 匹配 /admin/user 下所有路由
/admin/*/index       → 匹配 /admin 下任意模块的 index
/api/public/*        → 匹配 /api/public 下所有路由
```

### 4. 防范循环继承

```php
// 始终在保存角色前检查
if (Role::hasCycle($request->parent_id, $roleId)) {
    return $this->error('不允许的角色继承关系，检测到循环引用');
}
```

### 5. 用户模型事件

`HasRoles` Trait 的 `bootHasRoles` 方法会在模型 `saved`/`deleted` 时自动清除缓存。如果需要在用户模型中定义自己的 `boot` 方法，务必调用 `parent::boot()` 或手动 `static::bootHasRoles()`。

### 6. 多用户类型场景

```php
// 配置多种用户类型
'user_models' => [
    'admin'  => \app\admin\model\Admin::class,
    'member' => \app\api\model\Member::class,
],

// 使用时指定 user_type
Rbac::check($adminId, 'admin', 'admin.dashboard');
Rbac::check($memberId, 'member', 'member.profile.edit');
```

### 7. 与 WiseAdmin 框架集成

在 WiseAdmin 中，wise-auth 已作为核心依赖预装。默认用户模型指向 `\app\admin\model\Admin::class`，超管 ID 通常通过 `config('app.super_admin_ids')` 配置。

---

## 依赖关系

- **运行时依赖**：仅 `php >= 8.1`（零外部运行时依赖，可独立使用）
- **可选集成**：`wise-support`（配合 `AuthManager` 统一认证）、`wise-jwt`（JWT 用户解析器）

## 许可证

Apache-2.0 License. 详见 [LICENSE](LICENSE) 文件。
