<?php
declare(strict_types=1);

namespace wise\login\middleware;

use think\Request;
use think\Response;
use wise\login\captcha\CaptchaManager;
use wise\login\event\EventLogger;
use wise\login\event\LoginEvent;
use wise\login\exception\CaptchaInvalidException;

/**
 * 验证码校验中间件
 *
 * 用法：
 *   Route::post('login')
 *       ->middleware([
 *           \wise\login\middleware\CaptchaMiddleware::class,
 *       ]);
 *
 * 客户端需提交字段：captcha_key, captcha_code
 *
 * 跳过规则（按需调整）：
 *  - 已通过 TOTP 的请求跳过（本中间件无 TOTP 状态，需配合 TwoFactorMiddleware）
 */
class CaptchaMiddleware
{
    public function __construct(
        protected CaptchaManager $captcha,
        protected EventLogger $eventLogger
    ) {
    }

    public function handle(Request $request, \Closure $next): Response
    {
        $key   = (string) $request->param('captcha_key', $request->header('X-Captcha-Key', ''));
        $input = (string) $request->param('captcha_code', $request->header('X-Captcha-Code', ''));

        if ($input === '') {
            $this->eventLogger->log(LoginEvent::TYPE_CAPTCHA_FAILED, [
                'reason' => 'missing_field',
                'ip'     => $request->ip(),
            ], $request);
            return self::jsonError('请输入验证码', ['has_key' => $key !== '', 'has_input' => $input !== '']);
        }

        if (!$this->captcha->verify($key, $input)) {
            $this->eventLogger->log(LoginEvent::TYPE_CAPTCHA_FAILED, [
                'reason' => 'invalid',
                'ip'     => $request->ip(),
            ], $request);
            return self::jsonError('验证码错误或已过期');
        }

        return $next($request);
    }

    /**
     * 创建统一的 JSON 错误响应
     *
     * @param string $message 错误描述
     * @param array  $data    附加数据（如 ip, ttl_seconds, need_captcha）
     * @param int    $code    业务错误码（HTTP 状态码语义：400/403/422/423）
     */
    public static function jsonError(string $message, array $data = [], int $code = 400): Response
    {
        return json([
            'code'      => $code,
            'msg'       => $message,
            'data'      => $data,
            'timestamp' => time(),
        ]);
    }
}
