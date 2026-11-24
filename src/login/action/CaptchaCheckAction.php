<?php
declare(strict_types=1);

namespace wise\login\action;

use Closure;
use think\Request;
use wise\login\contract\LoginGuardAction;
use wise\login\contract\LoginPayload;
use wise\login\event\EventLogger;
use wise\login\facade\Captcha;
use wise\login\lock\LoginLockManager;
use wise\support\traits\JsonResponse;

/**
 * 验证码检查 Action
 *
 * 根据失败次数动态决定是否要求输入验证码。
 * 失败次数达到阈值时，校验验证码有效性。
 *
 * 从 LoginGuardMiddleware::checkCaptcha() 提取
 */
class CaptchaCheckAction implements LoginGuardAction
{
    use JsonResponse;

    protected LoginLockManager $lockManager;
    protected EventLogger $eventLogger;
    protected int $threshold;
    protected bool $checkEnabled;

    public function __construct(LoginLockManager $lockManager, EventLogger $eventLogger, int $threshold = 2, bool $checkEnabled = true)
    {
        $this->lockManager  = $lockManager;
        $this->eventLogger  = $eventLogger;
        $this->threshold     = $threshold;
        $this->checkEnabled  = $checkEnabled;
    }

    /**
     * 根据失败次数动态决定是否要求验证码
     *
     * @param LoginPayload $payload
     * @param Closure      $next
     * @return mixed 需验证码时返回 JSON Response，否则放行
     */
    public function handle(LoginPayload $payload, Closure $next)
    {
        if (!$this->checkEnabled) {
            $payload->log(static::class, 'skipped', '未启用');
            return $next($payload);
        }

        $username = $payload->username;
        $ip       = $payload->ip;
        $request  = $payload->request;

        if ($this->threshold > 0) {
            $current = (int) $this->lockManager->getAttempts($username, $ip);

            if ($current < $this->threshold) {
                $payload->log(static::class, 'skipped', "失败次数{$current}<阈值{$this->threshold}");
                return $next($payload);
            }
        }

        $key   = (string) $request->param('captcha_key', $request->header('X-Captcha-Key', ''));
        $input = (string) $request->param('captcha_code', $request->header('X-Captcha-Code', ''));

        if ($input === '') {
            $this->eventLogger->log('captcha_failed', [
                'reason'   => 'missing_field',
                'username' => $username,
                'ip'       => $ip,
            ], $request);
            $payload->log(static::class, 'blocked', '缺少验证码字段');
            return $this->error('请输入验证码', ['need_captcha' => true]);
        }

        if (!Captcha::verify($key, $input)) {
            $this->eventLogger->log('captcha_failed', [
                'reason'   => 'invalid',
                'username' => $username,
                'ip'       => $ip,
            ], $request);
            $payload->log(static::class, 'blocked', '验证码错误');
            return $this->error('验证码错误或已过期', ['need_captcha' => true]);
        }

        $payload->log(static::class, 'passed');
        return $next($payload);
    }
}
