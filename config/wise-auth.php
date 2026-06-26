<?php
/**
 * WiseAuth RBAC 权限管理配置文件
 *
 * 可通过 config('wise-auth.xxx') 读取所有配置项。
 * 发布后自动复制到项目 config/ 目录，业务可按需覆盖。
 */
return [
    // -----------------------------------------------------------------------
    // 用户模型配置
    // -----------------------------------------------------------------------

    /**
     * 默认用户模型类（FQCN）
     * 该模型需要 use \wise\auth\trait\HasRoles
     */
    'default_user_model' => \app\admin\model\Admin::class,

    /**
     * 多用户类型映射
     * key: guard/user_type 标识符
     * value: 用户模型类 (FQCN)
     *
     * 示例：
     *   'admin'  => \app\admin\model\Admin::class,
     *   'member' => \app\api\model\Member::class,
     */
    'user_models' => [
        // 'admin'  => \app\admin\model\Admin::class,
        // 'member' => \app\api\model\Member::class,
    ],

    // -----------------------------------------------------------------------
    // 数据表配置
    // -----------------------------------------------------------------------

    /**
     * 数据表名（不含前缀）
     * 如果你需要自定义表名，可在此修改。
     */
    'table_names' => [
        'roles'                 => 'auth_roles',
        'permissions'           => 'auth_permissions',
        'role_permission'       => 'auth_role_permission',
        'user_role'             => 'auth_user_role',
    ],

    // -----------------------------------------------------------------------
    // 超级管理员配置
    // -----------------------------------------------------------------------

    /**
     * 超级管理员角色标识（slug）
     * 拥有此角色的用户将绕过所有权限检查。
     * 设为 null 则禁用超级管理员概念，严格按 RBAC 判定。
     */
    'super_role' => 'super_admin',

    /**
     * 超级管理员用户 ID 列表
     * 这些 ID 的用户直接拥有全部权限，无需分配角色。
     * 通常与项目的 config('app.super_admin_ids') 保持一致。
     */
    'super_admin_ids' => [],

    // -----------------------------------------------------------------------
    // 缓存配置
    // -----------------------------------------------------------------------

    /**
     * 是否启用权限缓存
     */
    'cache_enabled' => true,

    /**
     * 缓存驱动
     * 默认使用框架 cache() 全局驱动，可指定具体 store（如 'redis'）
     */
    'cache_store' => null,

    /**
     * 缓存过期时间（秒）
     * null 表示永久有效（直到手动清除）
     */
    'cache_ttl' => 3600,

    /**
     * 缓存键前缀
     * 用于防止多应用实例之间的缓存键冲突
     */
    'cache_prefix' => 'wsauth:',

    // -----------------------------------------------------------------------
    // 权限加载与注册
    // -----------------------------------------------------------------------

    /**
     * 权限来源方式
     *
     * 支持多种来源组合：
     *   - 'database'  : 从数据库动态加载（默认）
     *   - 'annotation' : 从控制器注解/注释自动发现
     *   - 'config'     : 从本配置文件 'permissions' 节点加载
     *
     * 可同时启用多个来源，按数组顺序加载，后加载的会合并覆盖。
     */
    'permission_sources' => ['database'],
    
    // -----------------------------------------------------------------------
    // 权限注解
    // -----------------------------------------------------------------------

    /**
     * 注解扫描目录
     * 当 'annotation' 在 permission_sources 中时，扫描这些目录的控制器。
     */
    'annotation_dirs' => [
        // app_path('admin/controller'),
    ],

    /**
     * 注解标签名
     * 控制器方法注释中使用的权限声明标签。
     */
    'annotation_tag' => '@permission',

    /**
     * 配置文件驱动的权限列表（当 'config' 在 permission_sources 中时生效）
     * 每个权限包含：ident（标识）, name（名称）, type（类型: route/api/custom）,
     *   route（路由路径）, method（请求方法: GET/POST/PUT/DELETE/*）,
     *   description（描述）, parent（父权限标识，可选）
     *
     * 示例：
     * [
     *     ['ident' => 'admin.dashboard', 'name' => '仪表盘', 'type' => 'route', 'route' => '/admin/index/index', 'method' => '*'],
     *     ['ident' => 'admin.user.list',  'name' => '管理员列表', 'type' => 'route', 'route' => '/admin/admins/index', 'method' => '*'],
     * ]
     */
    'permissions' => [],

    // -----------------------------------------------------------------------
    // 权限检查策略
    // -----------------------------------------------------------------------

    /**
     * 默认检查模式
     *   - 'whitelist' : 白名单模式，未匹配路由默认拒绝（推荐）
     *   - 'blacklist' : 黑名单模式，未匹配路由默认允许
     */
    'default_mode' => 'whitelist',

    /**
     * 白名单路由（无需鉴权即可访问）
     * 支持路由 pattern，如 '/admin/login', '/admin/auth/*'
     */
    'whitelist_routes' => [
        '/admin/login',
        '/admin/logout',
        '/admin/auth/*',
    ],

    /**
     * 黑名单路由（必须鉴权，即使用户已登录）
     * 仅在 default_mode 为 'blacklist' 时生效
     */
    'blacklist_routes' => [],

    // -----------------------------------------------------------------------
    // 未授权处理
    // -----------------------------------------------------------------------

    /**
     * 未授权时的处理行为
     *
     * 支持三种配置方式：
     *
     * 1. 字符串模式（向后兼容，所有请求统一处理）：
     *    'exception' | 'redirect' | 'json' | 'custom'
     *
     * 2. 'auto' 模式（推荐，根据请求类型自动判断）：
     *    AJAX/API 请求（X-Requested-With: XMLHttpRequest 或 Accept: application/json）
     *    → 返回 JSON 错误响应
     *    普通浏览器请求 → 重定向到 unauthorized_redirect
     *
     * 3. 数组模式（按请求类型分别配置）：
     *    [
     *        'default' => 'json',    // 默认处理（必须，当无法判断请求类型时使用）
     *        'ajax'    => 'json',    // AJAX/XHR/API 请求
     *        'web'     => 'redirect', // 普通网页请求（浏览器地址栏访问）
     *    ]
     */
    'unauthorized_action' => 'auto',

    /**
     * 重定向 URL（当 unauthorized_action = 'redirect' 时生效）
     */
    'unauthorized_redirect' => '/admin/login',

    /**
     * 自定义未授权处理器（当 unauthorized_action = 'custom' 时生效）
     * 可设为闭包或实现了 __invoke($request) 的类名
     * function(\think\Request $request): \think\Response
     */
    'unauthorized_handler' => null,

    // -----------------------------------------------------------------------
    // 未登录处理（Authentication — 用户未认证）
    // -----------------------------------------------------------------------
    // 与"未授权处理"用法完全一致，但仅对"未登录"场景生效。
    // 各配置项设为 null 时自动回退到对应的 unauthorized_* 配置（向后兼容）。

    /**
     * 未登录时的处理行为
     *
     * 格式与 unauthorized_action 一致：
     *   1. 字符串：'exception' | 'redirect' | 'json' | 'custom'
     *   2. 'auto'：自动判断请求类型（AJAX→json，浏览器→redirect）
     *   3. 数组：['default' => 'json', 'ajax' => 'json', 'web' => 'redirect']
     *
     * 设为 null 时回退到 unauthorized_action（向后兼容）。
     */
    'not_logged_in_action' => null,

    /**
     * 未登录时重定向 URL（当 action 为 'redirect' 时生效）
     * 设为 null 时回退到 unauthorized_redirect（向后兼容）。
     */
    'not_logged_in_redirect' => null,

    /**
     * 未登录时 JSON 响应的 HTTP 状态码（默认 401）
     */
    'not_logged_in_code' => 401,

    /**
     * 未登录时的自定义处理器（当 action 为 'custom' 时生效）
     * 签名：function(\think\Request $request, string $type): \think\Response
     * 设为 null 时回退到 unauthorized_handler（向后兼容）。
     */
    'not_logged_in_handler' => null,

    // -----------------------------------------------------------------------
    // 无权限处理（Authorization — 用户已认证但无权限）
    // -----------------------------------------------------------------------
    // 与"未授权处理"用法完全一致，但仅对"无权限"场景（路由无匹配 / 权限检查失败）生效。
    // 各配置项设为 null 时自动回退到对应的 unauthorized_* 配置（向后兼容）。

    /**
     * 无权限时的处理行为
     *
     * 格式同上。
     * 设为 null 时回退到 unauthorized_action（向后兼容）。
     *
     * 推荐配置：
     *   - 网页后台：'redirect'，配合 forbidden_redirect 跳转到独立提示页
     *   - API 服务：'json'，返回 403 JSON 错误
     */
    'forbidden_action' => null,

    /**
     * 无权限时重定向 URL（当 action 为 'redirect' 时生效）
     * 设为 null 时回退到 unauthorized_redirect（向后兼容）。
     *
     * 推荐设为 '/admin/403' 或 '/admin/no-permission'，
     * 该路由由 Service 自动加入 whitelist_routes 防止拦截死循环。
     */
    'forbidden_redirect' => null,

    /**
     * 无权限时 JSON 响应的 HTTP 状态码（默认 403）
     */
    'forbidden_code' => 403,

    /**
     * 无权限时的自定义处理器（当 action 为 'custom' 时生效）
     * 签名：function(\think\Request $request, string $type): \think\Response
     * 设为 null 时回退到 unauthorized_handler（向后兼容）。
     */
    'forbidden_handler' => null,

    // -----------------------------------------------------------------------
    // 角色继承
    // -----------------------------------------------------------------------

    /**
     * 是否启用角色继承（RBAC1）
     * 启用后，父角色自动拥有子角色的所有权限。
     */
    'inheritance_enabled' => true,

    /**
     * 角色继承最大深度
     * null 或 0 表示无限制；设为正整数限制继承层级。
     */
    'inheritance_max_depth' => 10,

    /**
     * 是否检测循环继承
     * 启用后，在保存角色父子关系时会自动检测并阻止循环引用。
     */
    'cycle_check_enabled' => true,

    // -----------------------------------------------------------------------
    // RBAC2 约束扩展
    // -----------------------------------------------------------------------

    /**
     * RBAC2 约束检查器
     *
     * 可设为：
     *   - null : 不启用约束检查
     *   - FQCN : 实现了 \wise\auth\contract\ConstraintCheckerInterface 的类
     *   - \Closure : function(string $event, array $context): bool
     *
     * 约束检查器会在角色分配/权限赋予等操作前后被调用。
     */
    'constraint_checker' => null,

    /**
     * 内置约束规则配置（轻量级 RBAC2）
     *
     * 支持：
     *   - 'mutual_exclusion' : 互斥角色（定义哪些角色不能同时分配给同一用户）
     *   - 'cardinality'      : 角色基数限制（限制某个角色最多分配多少用户）
     *   - 'prerequisite'     : 前置角色（分配某角色前必须先拥有另一角色）
     *
     * 示例：
     * 'constraints' => [
     *     'mutual_exclusion' => [
     *         ['admin', 'editor'],     // admin 和 editor 不能同时分配
     *         ['finance', 'auditor'],  // finance 和 auditor 不能同时分配
     *     ],
     *     'cardinality' => [
     *         'super_admin' => 3,      // super_admin 最多3人
     *     ],
     *     'prerequisite' => [
     *         'super_admin' => ['admin'],  // 分配 super_admin 前必须先有 admin
     *     ],
     * ],
     */
    'constraints' => [],

    // -----------------------------------------------------------------------
    // 中间件配置
    // -----------------------------------------------------------------------

    /**
     * 默认权限检查类型
     *   - 'and' : 用户必须拥有所有指定的权限
     *   - 'or'  : 用户拥有任意一个指定权限即通过
     */
    'middleware_check_type' => 'or',

    /**
     * 中间件登录检查
     * 设为 true 时，中间件会先检查用户是否已登录
     */
    'middleware_auth_check' => true,

    /**
     * 获取当前登录用户 ID 的回调
     * 闭包签名：function(): ?int
     * 若为 null，中间件使用默认逻辑获取。
     *
     * 示例：function() { return session('admin_id'); }
     */
    'user_resolver' => null,

    // -----------------------------------------------------------------------
    // 数据权限（行级权限）
    // -----------------------------------------------------------------------

    /**
     * 数据权限策略
     * 设为闭包或实现了 __invoke 的类名，用于行级数据过滤。
     *
     * 签名：function(string $permission, $user, array $context = []): \Closure
     * 返回闭包用于修改查询条件。
     */
    'data_policy' => null
];
