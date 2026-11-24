<?php
/**
 * RBAC 路由中间件
 *
 * 自动校验当前用户的访问权限。
 * 支持 OR/AND 权限检查模式，可通过参数配置。
 *
 * 使用方式：
 * ```php
 * // 在路由定义或中间件配置中注册
 * 'admin' => [\wise\auth\middleware\RbacMiddleware::class]
 *
 * // 或使用别名（需在 app/middleware.php 中注册别名）
 * 'rbac:admin.user.list'
 * ```
 */
namespace wise\auth\middleware;

use think\Request;
use think\Response;
use think\facade\Session;
use wise\auth\contract\UserContract;
use wise\auth\service\RbacManager;
use wise\auth\exception\UnauthorizedException;
use wise\support\context\RequestContext;

class RbacMiddleware
{
    /**
     * 中间件入口
     *
     * @param Request  $request
     * @param \Closure $next
     * @param array    $params 额外参数
     *                         - 'checkType': 'and'|'or'
     *                         - 'permissions': 权限标识或标识数组
     *                         - 'loginCheck': true|false
     * @return Response
     * @throws UnauthorizedException
     */
    public function handle(Request $request, \Closure $next, ...$params): Response
    {
        $checkType = config('wise-auth.middleware_check_type', 'or');
        $requiredPermissions = null;

        if (!empty($params)) {
            $requiredPermissions = $params;
        }

        $manager = app(RbacManager::class);
        
        if ($this->shouldBypassAuth($request, $manager)) {
            return $next($request);
        }

        $user = $this->resolveUser($request);

        if (config('wise-auth.middleware_auth_check', true)) {
            if (!$user) {
                return $this->handleUnauthorized($request, 'Please login first', '', 'login');
            }
        }

        if (!$user) {
            return $next($request);
        }

        $userId = $user->getAuthIdentifier();
        $userType = $user->getAuthUserType();

        if (config('wise-auth.middleware_permission_version_check', true)) {
            $sessionVersion = Session::get('_rbac_perm_version') ?? RequestContext::get('_rbac_perm_version');
            $currentVersion = $manager->getUserPermissionVersion($userId, $userType);
            if ($sessionVersion !== null && $currentVersion > 0 && (int)$sessionVersion !== $currentVersion) {
                Session::delete('_rbac_perm_version');
                $manager->clearUserCache($userId, $userType);
                return $this->handleUnauthorized($request, 'Your roles have been updated. Please login again.', '', 'login');
            }
            if ($currentVersion > 0 && (int) $sessionVersion !== $currentVersion) {
                Session::set('_rbac_perm_version', $currentVersion);
            }
        }

        if ($manager->isSuperAdmin($userId, $userType)) {
            return $next($request);
        }

        if ($this->shouldSkipPermissionCheck($request, $manager)) {
            return $next($request);
        }

        if (empty($requiredPermissions)) {
            $route = $this->getDispatchedRoute($request);
            $method = $request->method();
            $requiredPermissions = $manager->matchRouteToPermissions($route, $method);

            if (empty($requiredPermissions)) {
                if (config('wise-auth.default_mode', 'whitelist') === 'whitelist') {
                    return $this->handleUnauthorized($request, "Permission not defined for route: {$route}", $route, 'forbidden');
                } else {
                    return $next($request);
                }
            }
        }

        $passed = false;
        if ($checkType === 'and') {
            $passed = $manager->checkAll($userId, $userType, $requiredPermissions);
        } else {
            $passed = $manager->checkAny($userId, $userType, $requiredPermissions);
        }

        if (!$passed) {
            $permissionStr = is_array($requiredPermissions) ? implode(',', $requiredPermissions) : $requiredPermissions;
            return $this->handleUnauthorized($request, "Permission denied: {$permissionStr}", $permissionStr, 'forbidden');
        }

        return $next($request);
    }

    /**
     * 解析当前用户
     *
     * 用户来源优先级：
     *   1. 自定义 user_resolver 闭包
     *   2. Session（admin_id）
     *   3. 被信任中间件注入的 auth_user_id（需配置 middleware_trust_auth_user_id = true）
     *
     * 安全说明：auth_user_id 来自 $request->auth_user_id 动态属性，
     * 仅当配置 middleware_trust_auth_user_id 为 true 且请求已被上游鉴权中间件
     * （如 JWT 中间件）标记为可信时，才接受该来源。默认为 false，防止伪造。
     *
     * @param Request $request
     * @return UserContract|null
     */
    protected function resolveUser(Request $request): ?UserContract
    {
        $resolver = config('wise-auth.user_resolver');
        if ($resolver instanceof \Closure) {
            $user = $resolver();
            $this->ensureUserContract($user, 'User resolver');
            return $user;
        }

        $userId = function_exists('auth_id') ? auth_id('admin') : null;
        if (!$userId) {
            $userId = session('admin_id');
        }

        if (!$userId && config('wise-auth.middleware_trust_auth_user_id', false)) {
            $trusted = (bool) ($request->_rbac_trusted ?? false);
            if ($trusted) {
                $userId = $request->auth_user_id ?? null;
            }
        }

        if (!$userId) {
            return null;
        }

        $modelClass = config('wise-auth.default_user_model');
        if (!$modelClass || !class_exists($modelClass)) {
            return null;
        }

        $user = $modelClass::find($userId);

        if ($user) {
            $this->ensureUserContract($user, $modelClass);
        }

        return $user;
    }

    /**
     * 确保用户对象实现了 UserContract 接口
     *
     * @param object|null $user
     * @param string      $source 用户来源描述（用于错误消息）
     * @return void
     * @throws \RuntimeException
     */
    private function ensureUserContract(?object $user, string $source): void
    {
        if ($user !== null && !$user instanceof UserContract) {
            throw new \RuntimeException(
                sprintf(
                    '%s returned object [%s] which does not implement %s',
                    $source,
                    get_class($user),
                    UserContract::class
                )
            );
        }
    }

    /**
     * 检查当前路由是否应绕过权限认证
     *
     * 白名单路由命中时返回 true（跳过认证），
     * 黑名单路由命中时返回 false（必须认证），
     * 均未命中时返回 false（默认需要认证）。
     *
     * 匹配规则：优先使用分派路由（app/controller/action），同时兼容原始 URL 匹配。
     *
     * @param Request      $request
     * @param RbacManager  $manager
     * @return bool
     */
    protected function shouldBypassAuth(Request $request, RbacManager $manager): bool
    {
        $whitelist = config('wise-auth.whitelist_routes', []);
        $dispatchedRoute = $this->getDispatchedRoute($request);
        $baseUrl = $request->baseUrl();

        foreach ($whitelist as $pattern) {
            if ($manager->routeMatch($pattern, $dispatchedRoute) || $manager->routeMatch($pattern, $baseUrl)) {
                return true;
            }
        }
        
        $blacklist = config('wise-auth.blacklist_routes', []);
        foreach ($blacklist as $pattern) {
            if ($manager->routeMatch($pattern, $dispatchedRoute) || $manager->routeMatch($pattern, $baseUrl)) {
                return false;
            }
        }

        return false;
    }

    /**
     * 检查当前路由是否「登录即可访问」（跳过权限节点匹配）
     *
     * 用于后台首页、主题切换、个人偏好等「每个已登录管理员都必须能用」的
     * 框架级入口：它们不属于任何业务菜单，也就不会有菜单派生的权限节点；
     * 若走 default_mode=whitelist 的「未匹配即拒绝」分支，所有非超管会在
     * 登录后被首页直接踢到 403。
     *
     * 与 whitelist_routes 的区别：本项**不跳过登录校验**（调用点在登录校验之后），
     * 只跳过权限匹配，因此未登录请求仍会被重定向到登录页。
     *
     * 匹配规则同白名单：先匹配分派路由，再匹配原始 URL。
     *
     * @param Request      $request
     * @param RbacManager  $manager
     * @return bool
     */
    protected function shouldSkipPermissionCheck(Request $request, RbacManager $manager): bool
    {
        $routes = (array) config('wise-auth.authenticated_routes', []);
        if (empty($routes)) {
            return false;
        }

        $dispatchedRoute = $this->getDispatchedRoute($request);
        $baseUrl         = $request->baseUrl();

        foreach ($routes as $pattern) {
            if ($manager->routeMatch($pattern, $dispatchedRoute) || $manager->routeMatch($pattern, $baseUrl)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 处理未授权（统一入口，按场景类型分发）
     *
     * @param Request $request
     * @param string  $message    错误消息
     * @param string  $permission 相关权限标识
     * @param string  $type       场景类型：'login' 未登录 | 'forbidden' 无权限
     * @return Response
     * @throws UnauthorizedException
     */
    protected function handleUnauthorized(Request $request, string $message, string $permission = '', string $type = 'forbidden'): Response
    {
        $action = $this->resolveUnauthorizedAction($request, $type);

        switch ($action) {
            case 'exception':
                throw new UnauthorizedException($message, $permission);

            case 'redirect':
                $redirectUrl = $this->getRedirectUrl($type);
                if ($redirectUrl) {
                    return redirect($redirectUrl);
                }
                return $this->jsonUnauthorized("Redirect URL not configured for '{$type}' scenario", $type);

            case 'json':
                return $this->jsonUnauthorized($message, $type);

            case 'custom':
                $handler = $this->getCustomHandler($type);
                if ($handler instanceof \Closure) {
                    return $handler($request, $type);
                }
                if (is_string($handler) && class_exists($handler)) {
                    $instance = app()->make($handler);
                    if (is_callable($instance)) {
                        return $instance($request, $type);
                    }
                }
                return $this->jsonUnauthorized($message, $type);

            default:
                return $this->jsonUnauthorized($message, $type);
        }
    }

    /**
     * 获取指定场景的重定向 URL
     *
     * 优先使用场景专属配置，未设置时回退到通用 unauthorized_redirect。
     *
     * @param string $type 场景类型：'login' | 'forbidden'
     * @return string
     */
    protected function getRedirectUrl(string $type): string
    {
        if ($type === 'login') {
            return config('wise-auth.not_logged_in_redirect')
                ?? config('wise-auth.unauthorized_redirect', '');
        }
        return config('wise-auth.forbidden_redirect')
            ?? config('wise-auth.unauthorized_redirect', '');
    }

    /**
     * 获取指定场景的自定义处理器
     *
     * 优先使用场景专属处理器，未设置时回退到通用 unauthorized_handler。
     *
     * @param string $type 场景类型：'login' | 'forbidden'
     * @return \Closure|string|null
     */
    protected function getCustomHandler(string $type)
    {
        if ($type === 'login') {
            return config('wise-auth.not_logged_in_handler')
                ?? config('wise-auth.unauthorized_handler');
        }
        return config('wise-auth.forbidden_handler')
            ?? config('wise-auth.unauthorized_handler');
    }

    /**
     * 解析未授权处理动作（支持按场景类型配置）
     *
     * 配置读取优先级：
     *   1. 场景专属配置（not_logged_in_action / forbidden_action）
     *   2. 通用配置（unauthorized_action）——向后兼容
     *
     * 支持三种配置格式：
     *   1. 字符串（向后兼容）：'json' | 'redirect' | 'exception' | 'custom'
     *   2. 'auto'：自动判断请求类型，AJAX→json，普通请求→redirect
     *   3. 数组：按请求类型分别指定
     *      [
     *          'default' => 'json',    // 默认（必须）
     *          'ajax'    => 'json',    // AJAX/XHR/API 请求
     *          'web'     => 'redirect', // 普通网页请求
     *      ]
     *
     * @param Request $request
     * @param string  $type    场景类型：'login' | 'forbidden'
     * @return string 'json' | 'redirect' | 'exception' | 'custom'
     */
    protected function resolveUnauthorizedAction(Request $request, string $type = 'forbidden'): string
    {
        $actionConfigKey = ($type === 'login')
            ? 'wise-auth.not_logged_in_action'
            : 'wise-auth.forbidden_action';

        $action = config($actionConfigKey);

        if ($action === null) {
            $action = config('wise-auth.unauthorized_action', 'auto');
        }

        if (is_string($action)) {
            if ($action === 'auto') {
                return $this->isAjaxRequest($request) ? 'json' : 'redirect';
            }
            return $action;
        }

        if (is_array($action)) {
            if ($this->isAjaxRequest($request) && isset($action['ajax'])) {
                return $action['ajax'];
            }
            if (!$this->isAjaxRequest($request) && isset($action['web'])) {
                return $action['web'];
            }
            return $action['default'] ?? 'json';
        }

        return 'json';
    }

    /**
     * 判断是否为 AJAX/API 请求
     *
     * 综合检测：X-Requested-With 头（jQuery/RequireJS）或 Accept: application/json（fetch/axios）。
     *
     * @param Request $request
     * @return bool
     */
    protected function isAjaxRequest(Request $request): bool
    {
        if ($request->isAjax()) {
            return true;
        }

        if ($request->isJson()) {
            return true;
        }

        return false;
    }

    /**
     * 返回统一 JSON 未授权响应
     *
     * 根据场景类型返回不同的 HTTP 状态码：
     *   - 'login' → 401（Unauthorized，未认证）
     *   - 'forbidden' → 403（Forbidden，已认证但无权限）
     *
     * @param string $message 错误消息
     * @param string $type    场景类型：'login' | 'forbidden'
     * @return Response
     */
    private function jsonUnauthorized(string $message, string $type = 'forbidden'): Response
    {
        $code = ($type === 'login')
            ? config('wise-auth.not_logged_in_code', 401)
            : config('wise-auth.forbidden_code', 403);

        return json([
            'code'      => $code,
            'msg'       => $message,
            'data'      => [],
            'timestamp' => time(),
        ])->code($code);
    }

    /**
     * 获取分派路由（/{app}/{controller}/{action} 或 /{app}/{url-path} 格式）
     *
     * ThinkPHP 多应用模式下，URL 如 /admin 实际分派到 admin/Index/index。
     * 此方法返回分派后的真实路由，用于白名单匹配和权限查找。
     *
     * ⚠ 执行时机（历史上踩过的坑）：
     * controller / action 是**路由分派阶段**才写入 Request 的
     * （见 think\route\dispatch\Controller::parseDispatch() 的 setController/setAction）。
     * 而本中间件常驻**应用级**流水线（app/{app}/middleware.php），应用级流水线在
     * 路由分派**之前**执行 —— 此时两者都是空字符串，拼接结果是 '/admin//'，
     * 权限永远匹配不上：白名单模式下非超管被全量 403，权限节点形同虚设
     * （表现为「超管全放行、其它角色一律无权限」）。
     * 故 controller/action 缺失时回退到「应用名 + URL 路径」，与菜单派生的
     * 权限 route（存的就是菜单 path，如 /admin/member/level/index）同构。
     *
     * 格式：/{app}/{controller}/{action}（controller/action 已知时，全部小写）
     *      /{app}/{url-path}（分派前，保留原始大小写与下划线）
     * 示例：/admin/index/index、/admin/login/index、/admin/member/level/index
     *
     * @param Request $request
     * @return string
     */
    protected function getDispatchedRoute(Request $request): string
    {
        $app = app('http')->getName();
        if (empty($app)) {
            return $request->baseUrl();
        }

        $controller = $this->normalizeController($request->controller());
        $action     = $request->action();

        if ($controller === '' || $action === '') {
            return '/' . $app . '/' . $this->urlPath($request, $app);
        }

        return '/' . implode('/', [$app, $controller, $action]);
    }

    /**
     * 由 URL 推导路由路径（去掉应用名首段与伪静态后缀）
     *
     * - pathinfo 在多应用模式下已被剥离应用名首段（member/level/index）；
     *   未剥离时（域名绑定应用 / CLI / 自定义入口）会带 'admin/'，去掉避免拼成 /admin/admin/...
     * - 去掉伪静态后缀（.html），与菜单 path 的写法保持一致
     * - 空的 pathinfo（如直接访问 /admin）按默认控制器/操作补全为 index/index
     *
     * @param Request $request
     * @param string  $app 应用名
     * @return string
     */
    private function urlPath(Request $request, string $app): string
    {
        $path = trim((string) $request->pathinfo(), '/');

        $root       = rtrim((string) $request->root(), '/');
        $hasAppRoot = $root === '' || substr($root, -strlen('/' . $app)) === '/' . $app;

        if (!$hasAppRoot && $path !== '' && stripos($path, $app . '/') === 0) {
            $path = substr($path, strlen($app) + 1);
        }

        $ext = (string) $request->ext();
        if ($ext !== '' && substr($path, -strlen('.' . $ext)) === '.' . $ext) {
            $path = substr($path, 0, -strlen('.' . $ext));
        }

        if ($path === '') {
            $path = 'index/index';
        }

        return $path;
    }

    /**
     * 标准化控制器名称
     *
     * 将 ThinkPHP 控制器的类名转换为小写路由片段。
     * 例：Index → index、UserAdmin → useradmin
     *
     * @param string $controller
     * @return string
     */
    private function normalizeController(string $controller): string
    {
        if (strpos($controller, '\\') !== false) {
            $parts = explode('\\', $controller);
            $controller = end($parts);
        }

        return strtolower($controller);
    }
}
