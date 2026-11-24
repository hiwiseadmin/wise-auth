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
     * 该模型需要 use \wise\auth\traits\HasRoles
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
     * 
     * 设为空数组 [] 则不通过用户 ID 识别超级管理员，仅通过 super_role 判定。
     * 若 super_role 也为 null，则全部用户严格按 RBAC 规则校验。
     *
     * 为安全考虑，建议使用硬编码的 ID 列表，避免依赖系统配置文件。
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
     * 缓存驱动（store 名）
     *
     * 默认使用本包专属 store「wise_auth」：由 AuthServiceProvider 在 register()
     * 阶段只向框架 cache.stores 合并注册（不改动框架 config/cache.php，也不改
     * runtime 配置缓存文件），使 clearAllCache() 在不支持「按前缀删除」的驱动
     * （File/Memcache 等）下退化为 $handler->clear() 时，仅清空本包缓存目录，
     * 不会误删业务缓存。
     *
     * 取值说明：
     *   - 'wise_auth'（默认）：自动注册的包专属 store，驱动参数见 cache_store_config
     *   - 宿主已定义的其它 store 名（如 'redis'）：直接复用，不做隔离
     *   - null：复用框架默认 store（放弃隔离，需自行承担误清风险）
     */
    'cache_store' => 'wise_auth',

    /**
     * 包专属 store 的驱动参数（可选，仅 cache_store = 'wise_auth' 时生效）
     *
     * 为 null 时自动依据宿主 cache.default 指向的 store 推导：
     *   - File 驱动：path 改写为 <原 path>/wise_auth/ 独立目录
     *   - 其它驱动：prefix 追加 wise_auth_ 前缀（实现同库隔离）
     *
     * 需要独立后端时在此显式声明完整驱动参数，例如：
     * [
     *     'type'   => 'redis',
     *     'host'   => '127.0.0.1',
     *     'port'   => 6379,
     *     'select' => 1,
     *     'prefix' => 'wise_auth_',
     * ]
     */
    'cache_store_config' => null,

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

    /**
     * 权限操作审计日志
     *
     * 启用后自动记录所有角色/权限变更操作到 auth_audit_log 表。
     * 日志包含操作类型、实体信息、操作者ID、IP 地址等。
     *
     * 默认 true（审计日志开启）。
     */
    'audit_enabled' => true,
    // -----------------------------------------------------------------------

    /**
     * 权限来源方式
     *
     * 支持多种来源组合：
     *   - 'database'  : 从数据库动态加载（默认）
     *   - 'attribute' : 扫描控制器上的 #[AuthPermission] Attribute 自动发现
     *   - 'config'    : 从本配置文件 'permissions' 节点加载
     *
     * 可同时启用多个来源，按数组顺序加载，后加载的会合并覆盖。
     */
    'permission_sources' => ['database'],
    
    // -----------------------------------------------------------------------
    // 权限 Attribute
    // -----------------------------------------------------------------------

    /**
     * Attribute 扫描目录
     * 当 'attribute' 在 permission_sources 中时，扫描这些目录的控制器，
     * 读取类/方法上的 #[AuthPermission] 声明并落库。
     *
     * 指向宿主 app 目录（composer PSR-4 自动加载，CLI 下可反射）；
     * 插件权限不走本链路（CLI 不加载 plugin\* 命名空间），由 manifest.json 的
     * menus / permissions 声明落库。
     */
    'attribute_dirs' => [
        // app_path('admin/controller'),
    ],

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
    'whitelist_routes' => [],

    /**
     * 登录即可访问的路由（只跳过权限节点匹配，**仍需登录**）
     *
     * 用于后台首页、个人资料、消息中心等「框架外壳」入口：它们没有对应的业务
     * 菜单，因此不会有菜单派生的权限节点。在 default_mode=whitelist 下若不豁免，
     * 所有非超管登录后会被首页直接重定向到 403。
     *
     * 与 whitelist_routes 的区别：白名单完全跳过登录校验（匿名可访问），
     * 本项在登录校验之后生效，未登录仍会跳登录页。
     */
    'authenticated_routes' => [],

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
     * 注意：互斥角色（mutual_exclusion）与角色基数限制（cardinality）
     * 已改为角色表字段驱动，分别对应 auth_roles.mutex 与 auth_roles.max_members，
     * 请直接在角色管理中维护，无需在此配置。
     *
     * 支持：
     *   - 'prerequisite'     : 前置角色（分配某角色前必须先拥有另一角色）
     *   - 'max_role_depth'   : 角色最大层级深度（限制嵌套层级数）
     *   - 'max_children'     : 父角色最大子节点数（限制某角色下最多创建多少子角色）
     *
     * 示例：
     * 'constraints' => [
     *     'prerequisite' => [
     *         'super_admin' => ['admin'],  // 分配 super_admin 前必须先有 admin
     *     ],
     *     'max_role_depth' => 5,       // 角色最多5层继承
     *     'max_children' => 10,        // 每个父角色最多10个子角色
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

    /**
     * 是否信任请求中的 auth_user_id 属性
     *
     * 当上游中间件（如 JWT 鉴权中间件）已将用户 ID 注入到
     * $request->auth_user_id 时，启用此选项允许 RbacMiddleware
     * 直接使用该值而无需通过 session 或数据库再次查询。
     *
     * 安全要求：上游中间件必须同时设置 $request->_rbac_trusted = true
     * 作为信任标记，防止请求伪造 auth_user_id。
     *
     * 默认 false（不接受请求中的 auth_user_id，必须通过 session 或 user_resolver 获取）。
     */
    'middleware_trust_auth_user_id' => false,

    /**
     * 是否启用权限版本检查（角色变更后强制重新登录）
     *
     * 启用后，当用户角色被修改/移除时，中间件会检测 session 中保存的
     * 权限版本号与缓存中的当前版本号是否一致，不一致时清除权限缓存并
     * 要求重新登录。
     *
     * 默认 true（开启角色变更后的会话保护）。
     */
    'middleware_permission_version_check' => true,

    // -----------------------------------------------------------------------
    // 数据权限（行级权限）
    // -----------------------------------------------------------------------

    /**
     * 数据权限策略
     * 设为闭包或实现了 __invoke 的类名，用于行级数据过滤。
     *
     * 实际签名（见 DataScope::apply()）：
     *   function($query, $user, string $permission, string $userField): mixed
     * 直接接收并返回查询对象；旧文档写的
     * function(string $permission, $user, array $context = []): \Closure
     * 与实现不符，按旧文档实现会拿到错位参数且返回值不被消费。
     */
    'data_policy' => null,

    // =======================================================================
    // 登录安全（原 wiseadmin/wise-login-security，2026-11-08 并入本包）
    //
    // 对应命名空间 `wise\login\*`；配置已内联于下方 `login` 段。
    // 宿主覆盖方式：config('wise-auth.login.captcha.enabled') 等。
    // =======================================================================
    'login' =>  [
    // ========================================================================
    // ⚠️ 当前版本【尚未实现】的配置项（预留，改动不会生效）：
    //   - guard_pipeline / result_pipeline   —— 管道顺序由中间件代码决定
    //   - two_factor.required_roles          —— 按角色强制 2FA
    //   - device_management.auto_register    —— 设备登记由 login_result.actions.device_record 控制
    //   - events.retention_days              —— 事件自动清理无调度入口
    //   - events.types                       —— 事件类型过滤未实现
    //   - middleware.login_guard.check_two_factor / record_device
    //                                        —— 2FA 由 TwoFactorMiddleware 负责，设备记录由 result_pipeline 负责
    // 需要启用时请先确认对应能力已实现，避免"改了配置但无任何效果"。
    // ========================================================================

    // ============ 验证码 ============
    'captcha' => [
        // 全局验证码开关（false = 前端不渲染验证码区域、后端不校验验证码）
        'enabled' => true,
        // 驱动：gd（GD 库图片验证码）| geetest（行为验证码，配置由用户实现 BehaviorCaptchaDriver）
        'driver'      => 'gd',

        // 验证码字符长度
        'length'      => 4,

        // 字符集：digits 数字 / letters 字母 / mix 数字字母混合
        'charset'     => 'mix',

        // 验证码有效期（秒）
        'expire'      => 300,

        // 图片宽度（px）
        'width'       => 130,

        // 图片高度（px）
        'height'      => 50,

        // 字体大小（使用 TrueType 字体时实际生效；无 TrueType 字体时自动限制为 1-5）
        'font_size'   => 20,

        // TrueType 字体文件路径（可选，不设则自动检测系统常见字体。如 Arial、DejaVuSans 等）
        'font_path'   => '',

        // 干扰点数量
        'noise_dots'  => 80,

        // 干扰线数量
        'noise_lines' => 3,

        // 文字扭曲（0-1）
        'distortion'  => 0.3,

        // 缓存前缀
        'cache_prefix' => 'wise_login:captcha:',

        // CAPTCHA 生成频率限制（防止资源耗尽攻击）
        'rate_limit' => [
            // 是否启用频率限制
            'enabled'              => true,

            // 单 IP 每分钟最大生成次数
            'max_per_ip_minute'    => 30,

            // 每会话每分钟最大生成次数（无 IP 降级）
            'max_per_session_minute' => 10,

            // 全局每分钟最大生成次数（兜底，0=不限制）
            'max_global_per_minute' => 500,

            // 限流计数存储驱动：redis（推荐，原子）| 其它已注册缓存驱动
            // 留空 = 跟随应用默认缓存（cache.default）；redis 不可用时自动降级并记日志
            'store'                => 'redis',

            // 频率限制缓存前缀
            'cache_prefix'         => 'wise_login:captcha_rate:',
        ],

        // 第三方行为验证码（geetest 等）的配置占位
        'geetest'     => [
            'id'         => '',
            'key'        => '',
            'api_server' => 'https://gcaptcha4.geetest.com/validate',
        ],

        // P1-#1：腾讯云验证码配置
        'tencent'     => [
            'app_id'     => '',
            'secret_key' => '',
            'api_server' => 'https://ssl.captcha.qq.com/ticket/verify',
        ],

        // P1-#1：hCaptcha 国际验证码配置
        'hcaptcha'    => [
            'site_key'   => '',
            'secret_key' => '',
            'api_server' => 'https://api.hcaptcha.com/siteverify',
        ],
    ],

    // ============ 登录失败次数限制 ============
    'failed_attempts' => [
        // 最大失败次数
        'max_attempts'    => 5,

        // 锁定时长（分钟），0 表示不自动解锁（需管理员手动解锁）
        'lockout_minutes' => 15,

        // 计数器存储：cache（缓存）| redis（Redis）| database（数据库）
        'store'           => 'cache',

        // 统计维度：ip（按 IP）| username（按用户名）| ip_username（按 IP+用户名组合）
        'scope'           => 'ip_username',

        // 缓存前缀
        'cache_prefix'    => 'wise_login:failed:',

        // 当 store = cache 时使用的缓存驱动；留空 = 跟随应用默认缓存（cache.default）
        //
        // 显式配置的作用：避免与宿主 cache.default 形成隐式联动。
        // 注意：这里**必须与 set/expire 使用同一连接**，否则 isLocked() 读不到
        // lock() 写入的标记，锁定会静默失效；留空时本包会自动对齐 cache.default。
        'cache_store'     => '',

        // 失败计数衰减窗口（分钟），窗口外的失败计数自动重置
        'decay_minutes'   => 60,

        // 渐进式锁定时长（P0-#5）
        // 启用后 lockout_minutes 作为首次锁定基础值，后续锁定逐级递增
        'progressive_lockout' => [
            // 是否启用渐进式锁定
            'enabled'              => false,

            // 锁定级别（分钟），索引0=第1次锁定，依次递进
            'levels'               => [1, 5, 15, 30, 60, 1440],

            // 成功登录后是否重置锁定级别
            'reset_after_success'   => true,

            // 锁定历史保留天数（超过后自动归零重新计算）
            'history_ttl_days'     => 7,
        ],
    ],

    // ============ IP 黑白名单 ============
    'ip_list' => [
        // 工作模式（显式控制，避免隐式行为）：
        //   'blacklist' - 仅检查黑名单，白名单不生效（默认，安全）
        //   'whitelist' - 仅检查白名单，只允许列表中的 IP 访问
        //   'both'      - 白名单优先：白名单 IP 直接放行，其余走黑名单检查
        'mode' => 'blacklist',

        // 白名单（mode=whitelist 或 mode=both 时生效）
        'whitelist' => [
            '127.0.0.1',
            '::1',
        ],

        // 黑名单（mode=blacklist 或 mode=both 时生效）
        'blacklist' => [],

        // 列表提供器：config（从本配置）| database（从数据库动态加载，P1-#10 已实现）
        'provider'           => 'config',

        // database 提供器缓存时间（秒，P1-#10）
        'provider_cache_ttl' => 300,

        // 是否在反向代理环境下信任 X-Forwarded-For。
        // 注意：仅当 REMOTE_ADDR 命中下方 trusted_proxies 时才真正采信代理头；
        // 未配置 trusted_proxies 时该开关不会生效（fail-closed），
        // 否则客户端可伪造 X-Forwarded-For 绕过 IP 黑名单与失败锁定。
        'trust_proxy_header' => true,

        // 已识别代理服务器 IP（CIDR 格式）。
        // 反向代理/网关部署时必须填写，例如本机 Nginx：['127.0.0.1/32', '::1/128']；
        // 留空表示"没有可信代理"，将忽略 X-Forwarded-For 并直接使用 REMOTE_ADDR。
        'trusted_proxies'    => [],
    ],

    // ============ 双因素认证（TOTP）============
    'two_factor' => [
        // 全局开关
        'enabled'  => true,

        // SMS/Email 2FA 发送失败专用日志通道
        // 包会自动注册此通道（File 驱动，路径 runtime/log/wise_login/），
        // 如需自定义通道（如 Redis），在 config/log.php 的 channels 中定义同名通道即可覆盖。
        'log_channel' => 'wise_login',

        // 默认多态用户类型（HasTotp Trait 和 TotpConfig 表使用）
        'user_type_default' => 'admin',

        // 发行者（显示在 Google Authenticator 中）
        'issuer'   => 'WiseAdmin',

        // 码位数（通常为 6）
        'digits'   => 6,

        // 时间步长（秒，RFC 6238 默认 30）
        'period'   => 30,

        // HMAC 算法：sha1 | sha256 | sha512
        'algorithm' => 'sha1',

        // 密钥长度（字节，Base32 编码后约为 1.6 倍）
        'secret_length' => 20,

        // 备份码数量
        'backup_codes_count' => 10,

        // 是否跳过已信任设备的 TOTP
        'skip_for_trusted_device' => true,

        // 强制要求 2FA 的角色 ID 列表（空 = 所有已启用 2FA 的用户都需验证）
        'required_roles' => [],

        // 备份码速率限制（P0-#16）
        // 防止备份码被暴力破解，内置冷却机制
        'backup_codes_rate_limit' => [
            // 是否启用
            'enabled'            => true,

            // 时间窗口内最大尝试验证次数
            'max_attempts'       => 3,

            // 时间窗口（分钟）
            'window_minutes'     => 5,

            // 触发限制后的冷却时间（分钟）
            'cooldown_minutes'   => 30,

            // 缓存前缀
            'cache_prefix'       => 'wise_login:backup_rate:',
        ],

        // P1-#14：邮件双因素认证
        'email' => [
            'enabled'         => true,   // 需安装 wise-notification + SMTP 配置
            'code_ttl'        => 300,    // 验证码有效期（秒）
            'code_length'     => 6,      // 验证码位数
            'max_attempts'    => 3,      // 最大尝试次数
            'resend_cooldown' => 60,     // 重发冷却（秒）
            'cache_prefix'    => 'wise_login:2fa_email:',
        ],

        // P1-#14：SMS 双因素认证
        'sms'  => [
            'enabled'         => false,  // 需安装 wise-notification + 短信 SDK 后启用
            'code_ttl'        => 300,
            'code_length'     => 6,
            'max_attempts'    => 3,
            'resend_cooldown' => 60,
            'template_code'   => 'verify_code',
            'cache_prefix'    => 'wise_login:2fa_sms:',
        ],

        // P2-#17：恢复码配置
        'recovery' => [
            'count'       => 8,   // 恢复码数量
            'code_length' => 16,  // 恢复码长度（16位 = 4×4格式）
        ],
    ],

    // ============ 设备管理 ============
    'device_management' => [
        // 设备信任有效期（天）
        'trust_duration_days' => 30,

        // 已信任设备是否跳过 TOTP
        'skip_totp_for_trusted_device' => true,

        // 设备指纹盐值（增强安全性，请修改为随机字符串）
        'fingerprint_salt'    => env('WISE_LOGIN_FINGERPRINT_SALT', 'change-me-to-random-string'),

        // User-Agent / IP 解析顺序
        'trust_proxy_header'  => true,

        // 是否在登录时自动注册新设备
        'auto_register'       => true,

        // 是否在新设备登录时记录安全事件（可由监听器发邮件）
        'notify_new_device'        => true,

        // P2-#18："记住此设备"功能
        'remember_device_enabled'  => true,                // 启用用户可选的"记住此设备"
        'remember_cookie_name'     => 'ws_remember_2fa',   // Cookie 名称
    ],

    // ============ P2-#21：登录异常检测 ============
    'anomaly_detection' => [
        // 是否启用
        'enabled' => true,

        // 缓存前缀
        'cache_prefix' => 'wise_login:anomaly:',

        // 规则1：异地登录检测
        'geo_anomaly' => [
            'enabled'           => true,
            'window_minutes'    => 60,   // 检测窗口（分钟）
            'ip_count_threshold' => 2,   // 不同 IP 数量触发阈值
        ],

        // 规则2：新设备+新IP 检测
        'new_device' => [
            'enabled'       => true,
            'lookback_days' => 7,       // 历史回溯天数
        ],

        // 规则3：异常时段检测
        'time_anomaly' => [
            'enabled'    => true,
            'start_hour' => 1,          // 异常时段起始（0-23）
            'end_hour'   => 5,          // 异常时段结束（0-23）
        ],

        // 规则4：频率异常检测
        'frequency_anomaly' => [
            'enabled'         => true,
            'window_minutes'  => 10,    // 检测窗口（分钟）
            'login_threshold' => 5,     // 登录次数阈值
        ],
    ],

    // ============ 中间件配置 ============
    'middleware' => [
        // 统一登录守卫中间件
        'login_guard' => [
            // 验证码启用开关
            'enabled' => true,

            // 失败达到此次数后强制要求验证码
            'require_captcha_after_failures' => 2,

            // 是否在守卫中检查 IP 黑白名单
            'check_ip_list' => true,

            // 是否在守卫中检查失败锁定
            'check_lock' => true,

            // 是否在守卫中检查 TOTP
            'check_two_factor' => true,

            // 是否在守卫中记录设备
            'record_device' => true,

            // 同源校验（登录端点来源校验，独立于全局 CSRF 与包内 CsrfToken）
            //
            // 适用前提：本包只管 Web 端登录，登录页由框架渲染，是访问系统的第一步，
            // 不存在 App / 小程序 / 服务端直调的登录入口。
            //
            // 只拒绝「证据明确为外部来源」的请求：Sec-Fetch-Site: cross-site、
            // same-site（可配）、以及来源 host 不在 allowed_hosts。证据缺失时
            // 不拦截，由包内 CsrfTokenMiddleware 兜底防 CSRF。
            //
            // 放在守卫链最前面：伪造来源直接 403，不再消耗 IP/锁定/验证码开销。
            'origin_check' => [
                // 总开关（关闭后登录端点将无任何来源校验，不建议）
                'enabled' => true,

                // 允许的来源 host（不含协议，可含端口；端口会被忽略）
                // 留空 = 取当前请求 Host，兼容默认部署。
                // 生产建议显式配置，避免 Host 头被代理改写时失效。
                // 例：['admin.example.com']
                'allowed_hosts' => [],

                // 是否信任 `Sec-Fetch-Site: same-origin` 作为来源证据（默认 true）
                //
                // 该头由浏览器网络栈写入，页面 JS 无法设置（`Sec-` 前缀是 Fetch
                // 规范中的禁止头），证据强度等同于「Origin 命中 allowed_hosts」。
                // 开启后，隐私扩展/企业代理剥掉 Referer、WebView 不带 Origin、
                // sandbox 文档 `Origin: null` 等误报不再被拦截。
                // 关闭 = 退回「必须带 Origin 或 Referer」，会误伤上述正常浏览器。
                'trust_fetch_metadata' => true,

                // 完全取不到来源证据（Origin / Referer / Sec-Fetch-Site 全空）时是否拒绝
                //
                // 默认 false：三者同时为空在现实中很常见（企业代理、抓包工具、
                // 隐私扩展剥头；WebView / 部分国产内核 / 旧浏览器对同源 POST
                // 既不写 Origin 也不写 Sec-Fetch-Site），属于误报来源，直接 403
                // 会把合法用户挡在登录门外。
                //
                // 登录 CSRF 的主防线是包内 CsrfTokenMiddleware（跨站构造的请求
                // 拿不到 Session 令牌，必然在令牌层被拒），来源层只负责拒绝
                // 「已声明为外部来源」的请求（cross-site / 跨源 host）。
                //
                // 置 true = 严格模式：连非浏览器客户端也拒绝。仅在确定登录端点
                // 100% 由浏览器页面提交、且不接受任何无来源请求时开启。
                'require_source' => false,

                // 是否把 `Sec-Fetch-Site: same-site` 也视为不可信并拒绝
                // 登录页恒为同源提交（same-origin），出现 same-site 说明来源是
                // 兄弟子域；子域常由其他系统/用户托管，默认不接受。
                'reject_same_site' => true,
            ],
        ],

        // 独立 IP 守卫中间件
        'ip_guard' => [
            'enabled' => true,
        ],

        // 独立 TOTP 中间件
        'two_factor' => [
            'enabled' => true,
        ],
    ],

    // ============ V2: Pipeline 管道配置（⚠️ 预留，当前版本尚未读取）============
    // 实际守卫顺序由 LoginGuardMiddleware::resolveGuardActions() 决定
    // （IP → 锁定 → 验证码 + 插件注册项）；改动下列顺序不会生效。
    'guard_pipeline' => [
        // 默认守卫顺序：IP → 锁定 → 验证码
        'default' => [
            \wise\login\action\IpGuardAction::class,
            \wise\login\action\LockCheckAction::class,
            \wise\login\action\CaptchaCheckAction::class,
        ],
        // 精简模式：仅 IP + 锁定（如内部系统无需验证码）
        'simple' => [
            \wise\login\action\IpGuardAction::class,
            \wise\login\action\LockCheckAction::class,
        ],
    ],

    // 登录结果管道（后置处理，按顺序执行；⚠️ 预留，当前版本尚未读取）
    // 实际顺序由 LoginResultMiddleware::resolveResultActions() 决定。
    'result_pipeline' => [
        'default' => [
            \wise\login\action\FailureRecordAction::class,
            \wise\login\action\SuccessRecordAction::class,
            \wise\login\action\DeviceRecordAction::class,
            \wise\login\action\AnomalyDetectAction::class,
        ],
    ],

    // ============ 路由配置（兼容旧版，新代码请使用 web 节）============
    'route' => [
        // 是否自动注册验证码 HTTP 路由（Service::register() 中 loadRoutesFrom）
        'auto_register' => true,

        // 路由前缀（自动注册时使用）
        'prefix' => 'wise/captcha',
    ],

    // ============ Web 路由（配置驱动，由 RouteRegistrar 读取）============
    'web' => [
        // 总开关：false 时本包不注册任何 HTTP 路由
        'enable' => true,
        // 默认路由前缀（分组级 prefix 可覆盖）；未设置时回退读取 route.prefix
        'prefix' => '',
        // 全局默认中间件（所有分组生效）
        'middleware' => [],
        // 分组配置：key 对应 RouteRegistrar::define() 中的 group('key', ...)
        'groups' => [
            'captcha' => [
                'enable'     => true,
                'middleware' => [],
            ],
            // 后台「安全管理」页面（/admin/login_security_*）：投递到 admin 应用，
            // 以相对前缀 '' 落地，鉴权由 admin 应用级 RBAC 中间件统一负责。
            'admin_security' => [
                'enable'     => true,
                'prefix'     => 'admin',
                'middleware' => [],
            ],
        ],
    ],

    // ============ 登录结果自动记录（LoginResultMiddleware）============
    'login_result' => [
        // 中间件开关
        'enabled' => true,

        // 响应字段映射
        'response' => [
            // 表示成功/失败的字段名
            'status_field'  => 'code',

            // 成功的值（与 status_field 对比）
            'success_value' => 0,

            // 成功时获取用户 ID 的方式：
            //   字符串模式：dot notation 字段路径，直接从响应体提取
            //   callable 模式：[ClassName::class, 'method']，回调接收 ($body, $request): ?int
            //     避免在响应中直接暴露真实 ID，可从 token 等中间值解析
            'user_id_field' => 'data.user_id',
        ],

        // 请求中用户名的字段名
        'username_input' => 'username',

        // 自动记录动作开关
        'actions' => [
            // 失败 → Lock::recordFailure()
            'failure_lock'   => true,

            // 失败 → Logger::log(LOGIN_FAILURE)
            'failure_event'  => true,

            // P2-#7：锁定触发 → Logger::log(ACCOUNT_LOCKED) + 邮件通知
            'lock_notify'    => true,

            // 成功 → Lock::clear()
            'success_clear'  => true,

            // 成功 → Logger::log(LOGIN_SUCCESS)
            'success_event'  => true,

            // 成功 → DeviceManager::record()
            'device_record'  => true,

            // 成功 → 标记 TOTP 已验证（跳过 2FA 中间件）
            'totp_verified'  => true,

            // P2-#21：成功 → 登录异常检测
            'anomaly_detect' => true,
        ],
    ],

    // ============ 站点标识 ============
    //
    // 用于安全通知邮件（新设备登录 / 账号锁定）中区分"是哪个系统"。
    // 留空 = 自动取当前请求的 Host（多系统部署时最准确，收件人一眼能对上）。
    // 队列 / CLI 场景没有请求上下文，如需在邮件里显示域名请在此显式配置。
    // 例：'admin.example.com'
    'site_domain' => '',

    // ============ 安全事件记录 ============
    'events' => [
        // 是否记录到数据库
        'log_to_database' => true,

        // 是否同时输出到日志
        'log_to_file'     => true,

        // 日志通道
        'log_channel'     => null,

        // 保留天数（0 = 永久），自动清理通过 think-login-security:init 后的清理命令
        'retention_days'  => 90,

        // 事件类型（可由监听器监听）
        'types' => [
            'login_failure',
            'login_success',
            'account_locked',
            'account_unlocked',
            'ip_blacklisted',
            'captcha_failed',
            'totp_verified',
            'totp_failed',
            'device_trusted',
            'device_new',
            'device_revoked',
        ],

        // 邮件通知按用户反查邮箱所需的用户模型（不配置则无法发送任何通知邮件）
        // 例如：\app\admin\model\Admin::class
        'user_model'     => null,

        // 用户名对应字段（事件只带 username 时按此字段反查用户）
        'username_field' => 'username',

        // P1-#25：新设备登录邮件提醒（NewDeviceMailListener）
        'new_device_email' => [
            'enabled'      => true,
            'email_field'  => 'email',
            'subject'      => '新设备登录提醒 - {app_name}',
            'app_name'     => '',
        ],

        // P2-#7：账户锁定邮件通知（LockedAccountMailListener）
        'lock_notify' => [
            'enabled'      => true,
            'email_field'  => 'email',
            'subject'      => '账户安全提醒 - {app_name}',
            'app_name'     => '',
        ],
    ],

    // ============ CSRF 防护（P0-#29）============
    //
    // 【本包独立配置，不受 config/csrf.php 影响】
    // 本包 CSRF 是「登录安全子系统」自带的防护层，与全局 CSRF 是两层
    // 互相独立的机制（令牌来源、存储位置、保护范围均不同）。
    // 详见 src/config/wise-login-security.php 同名段落的职责划分说明。
    'csrf' => [
        // 是否启用本包的 CSRF 校验
        'enabled'     => true,

        // CSRF Token 的 Header 名称
        'header_name' => 'X-CSRF-Token',

        // CSRF Token 的 Body 字段名称
        'field_name'  => '_csrf_token',

        // 排除的路径（支持通配符 *）
        // 例如：['api/callback/*', 'webhook/*']
        'except'      => [],
    ],

    // ================================================================
    // 验证码服务断路器（Circuit Breaker）
    // ================================================================
    'circuit' => [
        // 断路器状态存储驱动：留空 = 跟随应用默认缓存（cache.default）；
        // 驱动不可用时自动降级到默认缓存，避免验证码校验整体 500
        'store'             => 'redis',
        'failure_threshold' => 3,
        'timeout'           => 30,
        'key_prefix'        => 'wise_login:cb',
    ],
],
];
