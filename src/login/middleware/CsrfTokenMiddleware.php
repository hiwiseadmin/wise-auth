<?php
declare(strict_types=1);

namespace wise\login\middleware;

use think\Request;
use think\Response;
use wise\support\context\ContextualLogger;
use wise\login\exception\LoginException;

/**
 * CSRF Token 验证中间件
 *
 * 工作方式：
 *  1. GET/HEAD/OPTIONS 请求自动放行
 *  2. POST/PUT/DELETE/PATCH 请求强制校验 CSRF Token
 *  3. Token 来源（按优先级）：
 *     - Header: X-CSRF-Token 或 X-XSRF-Token
 *     - Body: _csrf_token 字段
 *  4. Token 与 Session 中存储的值比对（等长恒等比较，防时序攻击）
 *
 * 用法：
 *  - 全局：在 route/app.php 中间件数组中加入
 *  - 路由组：
 *    Route::group('admin', ...)->middleware([
 *        \wise\login\middleware\CsrfTokenMiddleware::class,
 *    ]);
 *  - 排除指定路由（通过 except 配置）
 *
 * Token 获取：
 *  - 前端通过 GET /wise/captcha/create 获取 CSRF Token（响应中 _csrf_token 字段）
 *  - 或在页面中嵌入 <meta name="csrf-token" content="...">
 */
class CsrfTokenMiddleware
{
    /**
     * @param Request $request
     * @param \Closure $next
     * @return Response
     * @throws LoginException CSRF 校验失败时抛出
     */
    public function handle(Request $request, \Closure $next): Response
    {
        $cfg = $this->config();
        if (!($cfg['enabled'] ?? true)) {
            return $next($request);
        }

        $method = strtoupper($request->method());

        if (in_array($method, ['GET', 'HEAD', 'OPTIONS'], true)) {
            return $next($request);
        }

        $except = (array) ($cfg['except'] ?? []);
        $path = $request->pathinfo();
        foreach ($except as $pattern) {
            if ($this->matchPath($pattern, $path)) {
                return $next($request);
            }
        }

        $clientToken = $this->getClientToken($request);
        if ($clientToken === null || $clientToken === '') {
            ContextualLogger::warning('[CsrfTokenMiddleware] CSRF token missing', [
                'method' => $method,
                'path'   => $path,
                'ip'     => $request->ip(),
            ]);
            throw new LoginException('CSRF Token 缺失', [
                'path'       => $path,
                'error_type' => 'csrf_missing',
            ], 1080);
        }

        $sessionToken = $this->getSessionToken($request);
        if ($sessionToken === null || $sessionToken === '') {
            ContextualLogger::warning('[CsrfTokenMiddleware] CSRF session token missing', [
                'method' => $method,
                'path'   => $path,
                'ip'     => $request->ip(),
            ]);
            throw new LoginException('CSRF Token 已过期，请刷新页面', [
                'path'       => $path,
                'error_type' => 'csrf_expired',
            ], 1081);
        }

        if (!$this->tokensMatch($clientToken, $sessionToken)) {
            ContextualLogger::warning('[CsrfTokenMiddleware] CSRF token mismatch', [
                'method' => $method,
                'path'   => $path,
                'ip'     => $request->ip(),
            ]);
            throw new LoginException('CSRF Token 无效', [
                'path'       => $path,
                'error_type' => 'csrf_mismatch',
            ], 1082);
        }

        return $next($request);
    }

    /**
     * 生成新的 CSRF Token 并存入 Session
     *
     * 调用方：CaptchaController、登录页面渲染控制器等
     *
     * @param Request $request
     * @return string 新生成的 Token（64 字符 hex）
     */
    public static function generateToken(Request $request): string
    {
        $token = bin2hex(random_bytes(32));
        \think\facade\Session::set('wise_login_security.csrf_token', $token);
        return $token;
    }

    /**
     * 获取当前有效的 CSRF Token
     *
     * Session 中无 Token 时自动生成
     *
     * @param Request $request
     * @return string
     */
    public static function getToken(Request $request): string
    {
        $token = \think\facade\Session::get('wise_login_security.csrf_token');
        if (empty($token)) {
            $token = static::generateToken($request);
        }
        return (string) $token;
    }

    /**
     * 从请求中提取客户端提交的 CSRF Token
     */
    protected function getClientToken(Request $request): ?string
    {
        $cfg = $this->config();

        $headerName = $cfg['header_name'] ?? 'X-CSRF-Token';
        $token = $request->header($headerName);
        if (!empty($token)) {
            return (string) $token;
        }

        $token = $request->header('X-XSRF-Token');
        if (!empty($token)) {
            return (string) $token;
        }

        $fieldName = $cfg['field_name'] ?? '_csrf_token';
        $token = $request->param($fieldName);
        if (!empty($token)) {
            return (string) $token;
        }

        return null;
    }

    /**
     * 从 Session 读取服务端 Token
     */
    protected function getSessionToken(Request $request): ?string
    {
        $token = \think\facade\Session::get('wise_login_security.csrf_token');
        return $token !== null ? (string) $token : null;
    }

    /**
     * 等长恒等比较（防时序攻击，hash_equals）
     */
    protected function tokensMatch(string $clientToken, string $sessionToken): bool
    {
        return hash_equals($sessionToken, $clientToken);
    }

    /**
     * 简单路径匹配（支持 * 通配符）
     */
    protected function matchPath(string $pattern, string $path): bool
    {
        if ($pattern === $path) {
            return true;
        }
        if (str_ends_with($pattern, '*')) {
            $prefix = rtrim($pattern, '*');

            if (str_ends_with($prefix, '/')) {
                return str_starts_with($path, $prefix);
            }

            return $path === $prefix || str_starts_with($path, $prefix . '/');
        }
        return false;
    }

    /**
     * CSRF 配置（读取本包独立配置，不与全局 CSRF 共用）
     *
     * 本中间件是「登录安全子系统」自带的 CSRF 防护，配置源固定为
     * `wise-login-security.csrf`，**不受** host 的 `config/csrf.php` 影响。
     *
     * 两层 CSRF 的职责边界（互不替代、互不读取）：
     *   - 全局层：`config/csrf.php` + `app\common\middleware\VerifyCsrfToken`
     *     令牌为 Cookie 中的随机串，保护后台业务写操作；
     *     其 `except` 显式排除 `admin/login/*`，把登录端点让给本包。
     *   - 包内层：本中间件，令牌存 Session，挂在 `login/doLogin` 路由，
     *     守护登录端点；配套 `SameOriginCheckAction` 做来源校验。
     *
     * 禁止让一层去读另一层的配置：两层令牌的来源与存储都不同，
     * 混用会退化成「A 层签发的令牌交给 B 层校验」，必然失败。
     */
    protected function config(): array
    {
        return (array) config('wise-auth.login.csrf', []);
    }
}
