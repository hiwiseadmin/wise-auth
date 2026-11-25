<?php
declare(strict_types=1);

namespace wise\login\captcha;

use think\App;
use wise\login\exception\CaptchaRateLimitException;
use wise\support\context\ContextualLogger;
use wise\support\rate\RateLimiter;

/**
 * 验证码管理器（业务层通常使用此类）
 *
 * 提供便捷方法：
 *  - generate(): 生成验证码
 *  - verify($key, $input): 校验
 *  - checkRateLimit($ip, $sessionId): 频率限制检查（SEC-9）
 *
 *  - 基于 IP + 会话双维度限制
 *  - 全局兜底限制
 */
class CaptchaManager
{
    public function __construct(protected App $app)
    {
    }

    /**
     * 获取当前配置的验证码驱动实例
     *
     * @return CaptchaDriverInterface
     */
    public function driver(): CaptchaDriverInterface
    {
        return $this->app->make(CaptchaDriverInterface::class);
    }

    /**
     * 生成验证码（代理到具体驱动）
     *
     * @return array {image:string, key:string, mime:string, expire:int}
     */
    public function generate(): array
    {
        return $this->driver()->generate();
    }

    /**
     * 校验用户输入的验证码（代理到具体驱动）
     *
     * @param string $key   generate() 返回的 key
     * @param string $input 用户输入
     * @return bool
     */
    public function verify(string $key, string $input): bool
    {
        return $this->driver()->verify($key, $input);
    }

    /**
     * 检查 CAPTCHA 生成频率限制
     *
     * 限制维度（三层）：
     *  1. 单 IP 每分钟上限（max_per_ip_minute）
     *  2. 单会话每分钟上限（max_per_session_minute）
     *  3. 全局每分钟上限（max_global_per_minute，兜底）
     *
     * @param string      $ip        客户端 IP
     * @param string|null $sessionId 会话标识（无 IP 场景降级）
     * @throws CaptchaRateLimitException 超过任一限制时抛出
     */
    public function checkRateLimit(string $ip, ?string $sessionId = null): void
    {
        $cfg = $this->rateLimitConfig();
        if (!($cfg['enabled'] ?? true)) {
            return;
        }

        $minute = (int) floor(time() / 60);
        $prefix = rtrim($cfg['cache_prefix'] ?? 'wise_login_security:captcha_rate:', ':');
        $store = $this->resolveRateStore($cfg);

        $maxGlobal = (int) ($cfg['max_global_per_minute'] ?? 0);
        if ($maxGlobal > 0) {
            $limiter = RateLimiter::perMinute($maxGlobal)
                ->via($store)
                ->withPrefix($prefix)
                ->by('global|' . $minute);

            if ($limiter->tooManyAttempts()) {
                throw new CaptchaRateLimitException('系统繁忙，请稍后再试', [
                    'limit_type'  => 'global',
                    'retry_after' => $limiter->cooldown(),
                ]);
            }
            $limiter->hit();
        }

        $maxIp = (int) ($cfg['max_per_ip_minute'] ?? 30);
        $ipHash = md5($ip);
        $limiter = RateLimiter::perMinute($maxIp)
            ->via($store)
            ->withPrefix($prefix)
            ->by('ip|' . $ipHash . '|' . $minute);

        if ($limiter->tooManyAttempts()) {
            throw new CaptchaRateLimitException('验证码请求过于频繁，请稍后再试', [
                'limit_type'  => 'ip',
                'retry_after' => $limiter->cooldown(),
            ]);
        }
        $limiter->hit();

        $maxSession = (int) ($cfg['max_per_session_minute'] ?? 10);
        $sessionHash = $sessionId ? md5($sessionId) : $ipHash;
        $limiter = RateLimiter::perMinute($maxSession)
            ->via($store)
            ->withPrefix($prefix)
            ->by('session|' . $sessionHash . '|' . $minute);

        if ($limiter->tooManyAttempts()) {
            throw new CaptchaRateLimitException('验证码请求过于频繁，请稍后再试', [
                'limit_type'  => 'session',
                'retry_after' => $limiter->cooldown(),
            ]);
        }
        $limiter->hit();
    }

    /**
     * 解析限流存储驱动
     *
     * 配置项 captcha.rate_limit.store（留空 = 跟随应用默认缓存 cache.default）。
     * 当解析结果为 redis 但其不可用时降级到应用默认缓存并记日志，
     * 避免验证码这一安全控件因 Redis 故障而整体 500。
     *
     * @param array $cfg 限流配置
     * @return string 可用的缓存驱动名
     */
    protected function resolveRateStore(array $cfg): string
    {
        $store = trim((string) ($cfg['store'] ?? 'redis'));
        if ($store === '') {
            $store = (string) $this->app->config->get('cache.default', 'file');
        }

        if ($store === 'redis') {
            try {
                $this->app->cache->store('redis')->handler();
            } catch (\Throwable $e) {
                ContextualLogger::warning(
                    '[login-security] Redis 不可用，验证码限流降级到应用默认缓存: ' . $e->getMessage()
                );
                $store = (string) $this->app->config->get('cache.default', 'file');
            }
        }

        return $store;
    }

    /**
     * 获取频率限制配置
     *
     * @return array
     */
    protected function rateLimitConfig(): array
    {
        return (array) $this->app->config->get('wise-auth.login.captcha.rate_limit', []);
    }
}
