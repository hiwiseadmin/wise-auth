<?php
declare(strict_types=1);

namespace wise\login\controller;

use think\facade\Cache;
use think\facade\Request;
use wise\login\captcha\CaptchaManager;
use wise\login\exception\ServiceUnavailableException;
use wise\login\ip\CidrMatcher;
use wise\login\middleware\CsrfTokenMiddleware;
use wise\support\backoff\BackoffStrategy;
use wise\support\circuit\CircuitBreaker;
use wise\support\context\ContextualLogger;
use wise\support\traits\JsonResponse;

/**
 * 验证码 HTTP 控制器
 *
 * 由包内自动注册路由使用（route/captcha.php），用户也可手动绑定到自己路由。
 *
 * 路由约定：
 *   GET  {prefix}/create   → 生成验证码（返回 JSON）
 *   POST {prefix}/verify   → 校验验证码
 *   GET  {prefix}/image    → 直接输出 PNG 图片（<img src> 兼容）
 */
class CaptchaController
{
    use JsonResponse;

    /**
     * 验证码服务断路器（实例级，随控制器实例释放）
     *
     * 不能用函数级 static：常驻运行时下 static 会跨请求存活，既把 circuit.*
     * 配置固化在首次调用时的取值上（改配置必须重启 worker），又把含 Redis 连接的
     * Cache store 跨请求复用，断路器内部失败计数也会延续到后续请求。
     *
     * @var CircuitBreaker|null
     */
    protected ?CircuitBreaker $captchaBreaker = null;

    public function __construct(protected CaptchaManager $captcha)
    {
    }

    /**
     * 生成验证码（AJAX 友好）
     *
     * 返回 JSON：
     *   { code: 0, msg: "ok", data: { key, image, expire, _csrf_token } }
     */
    public function create()
    {
        $this->checkRateLimit();

        $data = $this->captcha->generate();

        $csrfToken = '';
        try {
            $csrfToken = CsrfTokenMiddleware::getToken(Request::instance());
        } catch (\Throwable $e) {
        }

        return $this->success('ok', [
            'key'         => $data['key'],
            'image'       => $data['image'],
            'expire'      => $data['expire'],
            '_csrf_token' => $csrfToken,
        ]);
    }

    /**
     * 校验验证码
     *
     * 请求体（JSON 或 form）：
     *   { key: "hex...", code: "AB3X" }
     *
     * 返回 JSON：
     *   { code: 0, msg: "ok", data: { valid: true } }
     */
    public function verify()
    {
        $key  = request()->param('captcha_key', request()->header('X-Captcha-Key', ''));
        $code = request()->param('captcha_code', request()->header('X-Captcha-Code', ''));

        if (!is_string($key) || $key === '' || !is_string($code) || $code === '') {
            return $this->error('key and code required', ['valid' => false], 1);
        }

        try {
            $breaker = $this->getCaptchaBreaker();
            if (!$breaker->isAvailable()) {
                throw new ServiceUnavailableException();
            }

            $valid = \retry(1, fn() => $this->captcha->verify((string) $key, (string) $code), BackoffStrategy::fixed(500));

            $breaker->reportSuccess();
        } catch (ServiceUnavailableException $e) {
            return $this->circuitResponse($e);
        } catch (\Throwable $e) {
            if (isset($breaker)) {
                $breaker->reportFailure();
            }
            throw $e;
        }

        if ($valid) {
            return $this->success('ok', ['valid' => true]);
        }
        return $this->error('captcha incorrect or expired', ['valid' => false], 1);
    }

    /**
     * 直接输出原始 PNG 图片（兼容 <img src="/captcha/image"> 用法）
     *
     * 同时通过 X-Captcha-Key 标头返回 key，客户端可读取后提交。
     */
    public function image()
    {
        $this->checkRateLimit();

        $data = $this->captcha->generate();

        $dataUri = $data['image'];
        if (preg_match('/^data:image\/png;base64,(.+)$/', $dataUri, $m)) {
            $binary = base64_decode($m[1]);
        } else {
            $binary = $dataUri;
        }

        $csrfToken = '';
        try {
            $csrfToken = CsrfTokenMiddleware::getToken(Request::instance());
        } catch (\Throwable $e) {
        }

        return response($binary, 200)
            ->header([
                'Content-Type'              => 'image/png',
                'X-Captcha-Key'             => $data['key'],
                'X-Captcha-Expire'          => (string) $data['expire'],
                'X-CSRF-Token'              => $csrfToken,
                'Cache-Control'             => 'no-store, no-cache, must-revalidate',
                'Pragma'                    => 'no-cache',
                'Access-Control-Expose-Headers' => 'X-Captcha-Key, X-Captcha-Expire, X-CSRF-Token',
            ]);
    }

    protected function checkRateLimit(): void
    {
        $request = Request::instance();
        $trustProxy = (bool) config('wise-auth.login.ip_list.trust_proxy_header', true);
        $trustedProxies = (array) config('wise-auth.login.ip_list.trusted_proxies', []);
        $ip = CidrMatcher::getClientIp($request->server(), $trustProxy, $trustedProxies) ?: '127.0.0.1';
        $sessionId = null;

        try {
            $sessionId = $request->session('wise_login_security.session_id');
        } catch (\Throwable $e) {
        }

        if (!$sessionId) {
            $sessionId = $request->header('X-Session-Id', null);
        }

        $this->captcha->checkRateLimit($ip, $sessionId);
    }

    /**
     * 验证码服务断路器（固定 key：captcha）
     */
    protected function getCaptchaBreaker(): CircuitBreaker
    {
        if ($this->captchaBreaker !== null) {
            return $this->captchaBreaker;
        }

        $cfg = config('wise-auth.login.circuit', []);

        $store = trim((string) ($cfg['store'] ?? 'redis'));
        if ($store === '') {
            $store = (string) config('cache.default', 'file');
        }

        try {
            $cache = Cache::store($store);
        } catch (\Throwable $e) {
            ContextualLogger::warning(
                '[login-security] 断路器缓存驱动不可用，降级到应用默认缓存: ' . $e->getMessage()
            );
            $cache = Cache::store((string) config('cache.default', 'file'));
        }

        return $this->captchaBreaker = new CircuitBreaker(
            'captcha',
            $cache,
            [
                'failure_threshold' => $cfg['failure_threshold'] ?? 3,
                'timeout'           => $cfg['timeout'] ?? 30,
                'key_prefix'        => $cfg['key_prefix'] ?? 'wise_login_security:cb',
            ]
        );
    }
}
