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
use wise\auth\contract\UserContract;
use wise\auth\service\RbacManager;
use wise\auth\exception\UnauthorizedException;

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
        // 解析参数
        $checkType = config('wise-auth.middleware_check_type', 'or');
        $requiredPermissions = null;

        if (!empty($params)) {
            // 参数可能是权限标识字符串
            $requiredPermissions = $params;
        }

        /** @var RbacManager $manager */
        $manager = app(RbacManager::class);
        
        // 黑白名单检查（优先于登录检查，白名单路由无需登录即可访问）
        if ($this->shouldBypassAuth($request, $manager)) {
            return $next($request);
        }

        // 获取当前用户
        $user = $this->resolveUser($request);

        // 登录检查
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

        // 超级管理员直接通过
        if ($manager->isSuperAdmin($userId, $userType)) {
            return $next($request);
        }

        // 如果没有指定权限参数，则根据路由自动匹配
        if (empty($requiredPermissions)) {
            $route = $this->getDispatchedRoute($request);
            $method = $request->method();
            $requiredPermissions = $manager->matchRouteToPermissions($route, $method);

            // 根据黑白名单策略决定没有匹配到权限时的行为
            if (empty($requiredPermissions)) {
                if (config('wise-auth.default_mode', 'whitelist') === 'whitelist') {
                    // 白名单模式：未匹配 = 需要鉴权，拒绝访问
                    return $this->handleUnauthorized($request, "Permission not defined for route: {$route}", $route, 'forbidden');
                } else {
                    // 黑名单模式：未匹配 = 默认允许
                    return $next($request);
                }
            }
        }

        // 执行权限检查
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
     * @param Request $request
     * @return UserContract|null
     */
    protected function resolveUser(Request $request): ?object
    {
        // 1. 自定义解析器
        $resolver = config('wise-auth.user_resolver');
        if ($resolver instanceof \Closure) {
            $user = call_user_func($resolver);
            $this->ensureUserContract($user, 'User resolver');
            return $user;
        }

        // 2. 从 Session 获取
        $userId = session('admin_id');
        if (!$userId) {
            // 如果使用 JWT，从 request 获取
            $userId = $request->auth_user_id ?? null;
        }

        if (!$userId) {
            return null;
        }

        // 3. 使用默认用户模型查询
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

        // 检查白名单：命中则跳过认证
        // 先匹配分派路由，再匹配原始 URL（兼容旧格式）
        foreach ($whitelist as $pattern) {
            if ($manager->routeMatch($pattern, $dispatchedRoute) || $manager->routeMatch($pattern, $baseUrl)) {
                return true;
            }
        }
        
        // 检查黑名单：命中表示必须认证（不跳过）
        $blacklist = config('wise-auth.blacklist_routes', []);
        foreach ($blacklist as $pattern) {
            if ($manager->routeMatch($pattern, $dispatchedRoute) || $manager->routeMatch($pattern, $baseUrl)) {
                return false;
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
                return view("Please configure redirect URL for '{$type}' scenario");

            case 'json':
                return $this->jsonUnauthorized($message, $type);

            case 'custom':
                $handler = $this->getCustomHandler($type);
                if ($handler instanceof \Closure) {
                    return call_user_func($handler, $request, $type);
                }
                if (is_string($handler) && class_exists($handler)) {
                    // 使用容器实例化，支持依赖注入
                    $instance = app()->make($handler);
                    if (is_callable($instance)) {
                        return $instance($request, $type);
                    }
                }
                // fallback to json
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
        // forbidden 及任何其他类型
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
        // 获取场景特定配置，未设置则回退到通用配置
        $actionConfigKey = ($type === 'login')
            ? 'wise-auth.not_logged_in_action'
            : 'wise-auth.forbidden_action';

        $action = config($actionConfigKey);

        // 未配置场景专属动作 → 回退到通用 unauthorized_action（向后兼容）
        if ($action === null) {
            $action = config('wise-auth.unauthorized_action', 'auto');
        }

        // 字符串模式：直接返回或自动判断
        if (is_string($action)) {
            if ($action === 'auto') {
                return $this->isAjaxRequest($request) ? 'json' : 'redirect';
            }
            return $action;
        }

        // 数组模式：按请求类型匹配
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
        // ThinkPHP 内置 AJAX 检测（基于 X-Requested-With）
        if ($request->isAjax()) {
            return true;
        }

        // 额外检测：Accept 头包含 json（fetch/axios 等现代请求）
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
     * 获取分派路由（app/controller/action 格式）
     *
     * ThinkPHP 多应用模式下，URL 如 /admin 实际分派到 admin/Index/index。
     * 此方法返回分派后的真实路由，用于白名单匹配和权限查找。
     *
     * 格式：/{app}/{controller}/{action}，全部小写
     * 示例：/admin/index/index、/admin/login/index
     *
     * @param Request $request
     * @return string
     */
    protected function getDispatchedRoute(Request $request): string
    {
        $app = app('http')->getName();
        if (empty($app)) {
            // 非多应用模式，回退到原始 URL
            return $request->baseUrl();
        }

        return '/' . implode('/', [
            $app,
            $this->normalizeController($request->controller()),
            $request->action()
        ]);
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
        // 如果是全限定类名（如 app\admin\controller\Index），取最后一段
        if (strpos($controller, '\\') !== false) {
            $parts = explode('\\', $controller);
            $controller = end($parts);
        }

        return strtolower($controller);
    }
}
